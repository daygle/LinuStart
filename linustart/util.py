"""Shared helpers: subprocess execution and safe file writes."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .paths import BACKUP_DIR, ROOT


@dataclass
class CmdResult:
    argv: Sequence[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def run(
    argv: Sequence[str],
    *,
    timeout: float = 300.0,
    env: Optional[Mapping[str, str]] = None,
    check: bool = False,
    input_text: Optional[str] = None,
) -> CmdResult:
    """Run a command and capture its output."""
    merged = {**os.environ, **dict(env or {})}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            env=merged,
        )
    except OSError as exc:
        raise RuntimeError(f"could not run {argv[0]}: {exc}")
    payload = input_text.encode("utf-8") if input_text is not None else None
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=payload), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"command timed out after {timeout}s: {' '.join(argv)}")
    result = CmdResult(
        argv=list(argv),
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace"),
    )
    if check and not result.ok:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stderr.strip()}"
        )
    return result


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def is_within(base: Path, candidate: Path) -> bool:
    """True when *candidate* really lives at or under *base*.

    Both sides go through os.path.realpath, so a symlink pointing out of the
    tree is rejected instead of followed.
    """
    root = os.path.realpath(base)
    real = os.path.realpath(candidate)
    return real == root or real.startswith(os.path.join(root, ""))


def backup(path: Path) -> None:
    """Copy an existing file into the backup directory before it is rewritten.

    The realpath-then-prefix check is spelled out here rather than delegated
    to is_within so the guard sits in the same function as the copy below.
    """
    real = os.path.realpath(path)
    if not real.startswith(os.path.join(os.path.realpath(ROOT), "")):
        raise ValueError(f"refusing to back up a path outside {ROOT}: {path}")
    if not os.path.exists(real):
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    name = f"{stamp}-{real.lstrip(os.sep).replace(os.sep, '__')}"
    shutil.copy2(real, BACKUP_DIR / name)


DEFAULT_FILE_MODE = 0o644


def write_text(path: Path, content: str, *, mode: Optional[int] = None) -> None:
    """Atomically write *content* to *path*, backing up the previous version.

    The replacement keeps the mode and ownership of the file it replaces.
    mkstemp creates its file 0600, so without this every rewritten file -
    /etc/hosts, sshd_config, netplan YAML - would silently become root-only.
    New files get *mode* (default 0644); an explicit *mode* always wins, and
    is applied before the rename so a secret is never briefly world-readable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    old = read_text(path)
    if old == content and path.exists():
        if mode is not None:
            os.chmod(path, mode)
        return
    try:
        current = path.stat()
    except FileNotFoundError:
        current = None
    if old:
        backup(path)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        if mode is not None:
            os.chmod(tmp_name, mode)
        elif current is not None:
            os.chmod(tmp_name, current.st_mode & 0o7777)
        else:
            os.chmod(tmp_name, DEFAULT_FILE_MODE)
        if current is not None:
            try:
                os.chown(tmp_name, current.st_uid, current.st_gid)
            except (OSError, AttributeError):
                pass  # unprivileged dev sandboxes cannot chown; mode still kept
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def snapshot_files(paths: Sequence[Path]) -> dict:
    """Capture the current content of several files for a later revert."""
    return {str(path): read_text(path) for path in paths}


def restore_files(snapshots: Mapping[str, str]) -> None:
    """Restore files captured with :func:`snapshot_files`."""
    for name, content in snapshots.items():
        path = Path(name)
        real = os.path.realpath(path)
        if not real.startswith(os.path.join(os.path.realpath(ROOT), "")):
            raise ValueError(f"refusing to restore a path outside {ROOT}: {path}")
        if content == "":
            if path.exists():
                backup(path)
                path.unlink()
        else:
            write_text(path, content)
