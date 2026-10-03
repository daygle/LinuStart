"""Background job runner for long-lived operations (apt, upgrades, ...)."""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence

from .util import now_iso

MAX_LOG_LINES = 5000

STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"


@dataclass
class Job:
    id: str
    kind: str
    description: str
    argv: List[str]
    status: str = STATUS_RUNNING
    returncode: Optional[int] = None
    lines: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)
    finished_at: Optional[str] = None
    cancel_requested: bool = False
    _proc: Optional[asyncio.subprocess.Process] = field(default=None, repr=False)

    def to_dict(self, *, include_argv: bool = False) -> Dict[str, object]:
        data: Dict[str, object] = {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
            "status": self.status,
            "returncode": self.returncode,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "lines": len(self.lines),
            "cancel_requested": self.cancel_requested,
        }
        if include_argv:
            data["argv"] = self.argv
        return data

    def log_slice(self, after: int = 0) -> List[str]:
        return self.lines[after:]


class JobManager:
    """Runs commands in the background and keeps their output."""

    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self._order: List[str] = []

    async def start(
        self,
        kind: str,
        description: str,
        argv: Sequence[str],
        env: Optional[Mapping[str, str]] = None,
        stdin_text: Optional[str] = None,
    ) -> Job:
        job = Job(
            id=uuid.uuid4().hex[:12],
            kind=kind,
            description=description,
            argv=list(argv),
        )
        self.jobs[job.id] = job
        self._order.append(job.id)
        asyncio.get_running_loop().create_task(self._runner(job, dict(env or {}), stdin_text))
        return job

    async def _runner(self, job: Job, env: Mapping[str, str], stdin_text: Optional[str] = None) -> None:
        merged = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", **env}
        try:
            proc = await asyncio.create_subprocess_exec(
                *job.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
                env=merged,
            )
        except OSError as exc:
            job.lines.append(f"failed to start: {exc}")
            job.status = STATUS_FAILED
            job.returncode = -1
            job.finished_at = now_iso()
            return
        job._proc = proc
        assert proc.stdout is not None
        if stdin_text is not None and proc.stdin is not None:
            proc.stdin.write(stdin_text.encode("utf-8"))
            try:
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            proc.stdin.close()
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            job.lines.append(line.decode("utf-8", errors="replace").rstrip("\n"))
            if len(job.lines) > MAX_LOG_LINES:
                del job.lines[: len(job.lines) - MAX_LOG_LINES]
        job.returncode = await proc.wait()
        job.finished_at = now_iso()
        if job.cancel_requested:
            job.status = STATUS_CANCELLED
        elif job.returncode == 0:
            job.status = STATUS_SUCCEEDED
        else:
            job.status = STATUS_FAILED

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def list(self) -> List[Job]:
        return [self.jobs[job_id] for job_id in reversed(self._order) if job_id in self.jobs]

    async def cancel(self, job_id: str) -> Optional[Job]:
        job = self.jobs.get(job_id)
        if job is None or job.status != STATUS_RUNNING:
            return job
        job.cancel_requested = True
        proc = job._proc
        if proc is not None and proc.returncode is None:
            proc.terminate()
        return job

    def any_running(self) -> bool:
        return any(job.status == STATUS_RUNNING for job in self.jobs.values())
