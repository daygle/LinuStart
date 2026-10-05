"""Confirm-or-revert sessions for changes that can lock you out.

A network, firewall or sshd change is applied immediately and reverted
automatically unless it is confirmed within the timeout. The pending
sessions - the file snapshots plus what to re-apply - are written to
``/var/lib/linustart/pending-reverts.json`` as they are created, so a panel
that restarts inside the window (a crash, a self-update, ``systemctl
restart``) still reverts on schedule when it comes back, and reverts at once
if the deadline passed while it was down. Without that, the restart would
silently keep exactly the change the window exists to undo.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, Mapping, Optional

from fastapi import HTTPException

from . import audit
from .paths import PENDING_REVERTS_FILE
from .util import now_iso, restore_files

# Re-applying is described by data, not a closure, so it survives a restart:
# {"kind": "network", "backend": ..., "name": ...}, {"kind": "ssh"},
# {"kind": "firewall", "backend": ...}.
ReapplySpec = Dict[str, Optional[str]]


async def _reapply_network(spec: Mapping[str, Optional[str]]) -> None:
    from .modules import network

    await network.apply_backend(str(spec["backend"]), spec.get("name"))


async def _reapply_ssh(_spec: Mapping[str, Optional[str]]) -> None:
    from .modules import sshd

    await sshd.reload_service()


async def _reapply_firewall(spec: Mapping[str, Optional[str]]) -> None:
    from .modules import firewall

    await firewall.reapply(str(spec["backend"]))


REAPPLIERS: Dict[str, Callable[[Mapping[str, Optional[str]]], Awaitable[None]]] = {
    "network": _reapply_network,
    "ssh": _reapply_ssh,
    "firewall": _reapply_firewall,
}


async def run_reapply(spec: Mapping[str, Optional[str]]) -> None:
    handler = REAPPLIERS.get(str(spec.get("kind")))
    if handler is None:
        raise RuntimeError(f"unknown re-apply kind: {spec.get('kind')!r}")
    await handler(spec)


@dataclass
class RevertSession:
    id: str
    kind: str
    label: str
    snapshots: Dict[str, str]
    reapply: ReapplySpec
    expires_at: float  # wall clock (time.time), so it means the same after a restart
    created_at: str = field(default_factory=now_iso)
    confirmed: bool = False
    done: bool = False
    task: Optional[asyncio.Task] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "created_at": self.created_at,
            "confirmed": self.confirmed,
            "done": self.done,
            "seconds_left": 0 if self.confirmed else max(0, int(self.expires_at - time.time())),
        }

    def to_record(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "snapshots": self.snapshots,
            "reapply": self.reapply,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


class SessionManager:
    # Finished sessions are dropped after this many, newest kept.
    MAX_FINISHED = 50

    def __init__(self, state_file: Optional[os.PathLike] = None) -> None:
        self.sessions: Dict[str, RevertSession] = {}
        self.state_file = state_file if state_file is not None else PENDING_REVERTS_FILE

    # ---- persistence -----------------------------------------------------
    def _persist(self) -> None:
        """Write every pending session; the file holds config file contents,
        so it is root-only and replaced atomically."""
        pending = [s.to_record() for s in self.sessions.values() if not s.done]
        path = os.fspath(self.state_file)
        directory = os.path.dirname(path) or "."
        try:
            if not pending:
                if os.path.exists(path):
                    os.unlink(path)
                return
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".pending-reverts.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(pending, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as exc:
            # The change itself already happened; losing persistence must not
            # turn into an error for it, but it has to be visible.
            audit.record("revert.persist", f"could not save pending reverts: {exc}", ok=False)

    def resume(self) -> int:
        """Re-arm sessions saved by a previous run; returns how many."""
        path = os.fspath(self.state_file)
        try:
            with open(path, encoding="utf-8") as handle:
                records = json.load(handle)
        except FileNotFoundError:
            return 0
        except (OSError, ValueError) as exc:
            audit.record("revert.resume", f"pending reverts unreadable: {exc}", ok=False)
            return 0
        count = 0
        for record in records if isinstance(records, list) else []:
            try:
                session = RevertSession(
                    id=str(record["id"]),
                    kind=str(record["kind"]),
                    label=str(record["label"]),
                    snapshots={str(k): str(v) for k, v in dict(record["snapshots"]).items()},
                    reapply={str(k): (None if v is None else str(v)) for k, v in dict(record["reapply"]).items()},
                    expires_at=float(record["expires_at"]),
                    created_at=str(record.get("created_at") or now_iso()),
                )
            except (KeyError, TypeError, ValueError):
                continue
            if session.id in self.sessions:
                continue
            self.sessions[session.id] = session
            session.task = asyncio.get_running_loop().create_task(self._expire(session))
            count += 1
            audit.record(
                f"{session.kind}.resume",
                f"pending revert of {session.label} re-armed after restart "
                f"({max(0, int(session.expires_at - time.time()))}s left)",
            )
        return count

    # ---- lifecycle -------------------------------------------------------
    def create(
        self,
        kind: str,
        label: str,
        snapshots: Dict[str, str],
        timeout: int,
        reapply: ReapplySpec,
    ) -> RevertSession:
        if str(reapply.get("kind")) not in REAPPLIERS:
            raise ValueError(f"unknown re-apply kind: {reapply.get('kind')!r}")
        self._prune()
        session = RevertSession(
            id=uuid.uuid4().hex[:12],
            kind=kind,
            label=label,
            snapshots=snapshots,
            reapply=dict(reapply),
            expires_at=time.time() + timeout,
        )
        self.sessions[session.id] = session
        self._persist()
        session.task = asyncio.get_running_loop().create_task(self._expire(session))
        return session

    def pending(self):
        return [s for s in self.sessions.values() if not s.done]

    async def _expire(self, session: RevertSession) -> None:
        await asyncio.sleep(max(0.0, session.expires_at - time.time()))
        if session.confirmed or session.done:
            return
        session.done = True
        try:
            restore_files(session.snapshots)
            await run_reapply(session.reapply)
            audit.record(f"{session.kind}.revert", f"changes to {session.label} reverted automatically")
        except Exception as exc:  # noqa: BLE001 - log and keep running
            audit.record(f"{session.kind}.revert", f"revert of {session.label} failed: {exc}", ok=False)
        finally:
            self._persist()

    async def confirm(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        if not session.done:
            session.confirmed = True
            session.done = True
            self._persist()
            audit.record(f"{session.kind}.confirm", f"changes to {session.label} confirmed")
        return session

    async def revert(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        if not session.done:
            session.done = True
            try:
                restore_files(session.snapshots)
                await run_reapply(session.reapply)
            finally:
                self._persist()
            audit.record(f"{session.kind}.revert", f"changes to {session.label} reverted manually")
        return session

    def _prune(self) -> None:
        finished = [sid for sid, s in self.sessions.items() if s.done]
        for sid in finished[: max(0, len(finished) - self.MAX_FINISHED)]:
            del self.sessions[sid]

    def _get(self, session_id: str) -> RevertSession:
        session = self.sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no such revert session")
        return session
