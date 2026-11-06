"""Background job runner for long-lived operations (apt, upgrades, ...)."""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Set

from .util import now_iso

MAX_LOG_LINES = 5000
# Finished jobs are kept for the Jobs view; older ones are dropped so a panel
# that runs for months does not hold every apt log it ever produced.
MAX_FINISHED_JOBS = 100
# asyncio's default line limit is 64 KiB; a longer line (a progress bar that
# never prints a newline) would raise out of readline and leave the job
# "running" forever.
STREAM_LIMIT = 1024 * 1024

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
    # Lines already dropped from the front of ``lines``; ``log_slice`` offsets
    # count every line ever produced, so trimming must not shift them.
    dropped: int = 0
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
        """Lines the caller has not seen yet.

        ``after`` counts lines produced since the job started, so the oldest
        lines being dropped (MAX_LOG_LINES) must not shift it: otherwise a
        client polling past the cap would stop receiving output for good.
        """
        return self.lines[max(0, after - self.dropped):]


class JobManager:
    """Runs commands in the background and keeps their output."""

    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self._order: List[str] = []
        # asyncio keeps only a weak reference to a task: without a strong one
        # here a runner can be garbage-collected mid-job, leaving it "running"
        # for ever with its subprocess unsupervised.
        self._tasks: Set["asyncio.Task[None]"] = set()

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
        self._prune()
        self.jobs[job.id] = job
        self._order.append(job.id)
        task = asyncio.get_running_loop().create_task(self._runner(job, dict(env or {}), stdin_text))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
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
                limit=STREAM_LIMIT,
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
            try:
                line = await proc.stdout.readline()
            except ValueError:
                # Over the stream limit: take what is buffered as one line.
                line = await proc.stdout.read(STREAM_LIMIT)
            if not line:
                break
            job.lines.append(line.decode("utf-8", errors="replace").rstrip("\n"))
            if len(job.lines) > MAX_LOG_LINES:
                trimmed = len(job.lines) - MAX_LOG_LINES
                del job.lines[:trimmed]
                job.dropped += trimmed  # keeps polling offsets valid
        job.returncode = await proc.wait()
        job._proc = None
        job.finished_at = now_iso()
        if job.cancel_requested:
            job.status = STATUS_CANCELLED
        elif job.returncode == 0:
            job.status = STATUS_SUCCEEDED
        else:
            job.status = STATUS_FAILED

    def _prune(self) -> None:
        finished = [jid for jid in self._order if self.jobs[jid].status != STATUS_RUNNING]
        for jid in finished[: max(0, len(finished) - MAX_FINISHED_JOBS)]:
            del self.jobs[jid]
        if len(self._order) != len(self.jobs):
            self._order = [jid for jid in self._order if jid in self.jobs]

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
