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

    Both sides are resolved before the comparison, so a symlink that points
    out of the tree is rejected instead of followed. Callers use this as the
    last gate before touching a path that can trace back to a request.
    """
    try:
        target = candidate.resolve()
        root = base.resolve()
    except OSError:
        return False
    return target == root or root in target.parents


def backup(path: Path) -> None:
    """Copy an existing file into the backup directory before it is rewritten."""
    if not is_within(ROOT, path):
        raise ValueError(f"refusing to back up a path outside {ROOT}: {path}")
    if not path.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    name = f"{stamp}-{str(path).lstrip(os.sep).replace(os.sep, '__')}"
    shutil.copy2(path, BACKUP_DIR / name)


def write_text(path: Path, content: str) -> None:
    """Atomically write *content* to *path*, backing up the previous version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    old = read_text(path)
    if old == content:
        return
    if old:
        backup(path)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
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
        if not is_within(ROOT, path):
            raise ValueError(f"refusing to restore a path outside {ROOT}: {path}")
        if content == "":
            if path.exists():
                backup(path)
                path.unlink()
        else:
            write_text(path, content)
