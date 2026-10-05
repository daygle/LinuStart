"""Append-only audit log of everything the panel changes.

The log rotates at MAX_BYTES into ``audit.log.1`` ... ``audit.log.<KEEP>``
(oldest dropped), so it cannot fill the disk over years of use, and reading
the newest entries never loads more than the tail of the files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from .paths import AUDIT_LOG
from .util import now_iso

MAX_BYTES = 5 * 1024 * 1024
KEEP = 5
_BLOCK = 64 * 1024


def _rotated(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.{index}")


def rotate(path: Path, keep: Optional[int] = None) -> None:
    """Shift audit.log -> .1 -> .2 ...; the file past *keep* is removed."""
    keep = KEEP if keep is None else keep
    oldest = _rotated(path, keep)
    if oldest.exists():
        oldest.unlink()
    for index in range(keep - 1, 0, -1):
        source = _rotated(path, index)
        if source.exists():
            os.replace(source, _rotated(path, index + 1))
    if path.exists():
        os.replace(path, _rotated(path, 1))


def record(action: str, detail: str, *, ok: bool = True) -> None:
    entry = {"ts": now_iso(), "action": action, "detail": detail, "ok": ok}
    path = AUDIT_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.stat().st_size >= MAX_BYTES:
            rotate(path)
    except FileNotFoundError:
        pass
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def tail_lines(path: Path, count: int) -> List[str]:
    """The last *count* lines of a file, reading backwards in blocks."""
    if count <= 0:
        return []
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        return []
    with handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        data = b""
        while position > 0 and data.count(b"\n") <= count:
            step = min(_BLOCK, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-count:]


def read(limit: int = 200) -> List[Dict[str, object]]:
    """Newest entries first; continues into rotated files when needed."""
    lines: List[str] = []
    for index in range(0, KEEP + 1):
        path = AUDIT_LOG if index == 0 else _rotated(AUDIT_LOG, index)
        needed = limit - len(lines)
        if needed <= 0:
            break
        lines = tail_lines(path, needed) + lines
    entries: List[Dict[str, object]] = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries.reverse()
    return entries
