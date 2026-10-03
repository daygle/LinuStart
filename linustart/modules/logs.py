"""Log viewing: journalctl queries and safe tails of /var/log files.

Pure helpers validate names and slice text so they can be tested without root.
File access is restricted to validated plain names directly under ``/var/log``
- no path separators, so nothing outside that directory can be reached.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from ..paths import VAR_LOG_DIR
from ..util import is_within, run

LOG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
MAX_TAIL_BYTES = 256 * 1024
MIN_LINES, MAX_LINES = 10, 2000


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def valid_log_name(name: str) -> str:
    name = (name or "").strip()
    if not LOG_NAME_RE.match(name) or ".." in name:
        raise ValueError(f"not a valid log file name: {name!r}")
    return name


def clamp_lines(lines: object) -> int:
    try:
        value = int(lines)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 200
    return max(MIN_LINES, min(MAX_LINES, value))


def journal_command(
    lines: object = 200,
    unit: str = "",
    priority: str = "",
) -> List[str]:
    """argv for a bounded journal query with optional unit/priority filters."""
    argv = ["journalctl", "-n", str(clamp_lines(lines)), "--no-pager", "-o", "short-iso"]
    unit = (unit or "").strip()
    if unit:
        if not LOG_NAME_RE.match(unit) or "/" in unit:
            raise ValueError(f"not a valid unit name: {unit!r}")
        argv += ["-u", unit]
    priority = (priority or "").strip().lower()
    if priority:
        if priority not in PRIORITIES and not priority.isdigit():
            raise ValueError(f"priority must be one of: {', '.join(PRIORITIES)}")
        argv += ["-p", priority]
    return argv


def tail_text(text: str, lines: int = 200) -> List[str]:
    try:
        count = int(lines)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        count = 200
    count = max(1, min(MAX_LINES, count))
    return text.splitlines()[-count:]


def tail_file(path: Path, lines: int = 200) -> List[str]:
    """Read only the last slice of a (possibly huge) log file."""
    if not is_within(VAR_LOG_DIR, path):
        raise ValueError("refusing to read outside /var/log")
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - MAX_TAIL_BYTES))
            data = handle.read()
    except FileNotFoundError:
        raise ValueError(f"no such log file: {path.name}")
    text = data.decode("utf-8", errors="replace")
    return tail_text(text, lines)


def log_file_entry(path: Path) -> Optional[Dict[str, object]]:
    try:
        stat = path.stat()
    except OSError:
        return None
    return {"name": path.name, "size": stat.st_size, "modified": int(stat.st_mtime)}


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def journal(lines: object = 200, unit: str = "", priority: str = "") -> Dict[str, object]:
    result = await run(journal_command(lines, unit, priority))
    return {"lines": result.stdout.splitlines(), "command": journal_command(lines, unit, priority)}


def list_log_files() -> Dict[str, object]:
    files: List[Dict[str, object]] = []
    try:
        entries = sorted(VAR_LOG_DIR.iterdir())
    except FileNotFoundError:
        return {"files": []}
    for entry in entries:
        if not entry.is_file():
            continue
        info = log_file_entry(entry)
        if info:
            files.append(info)
    return {"files": files}


def read_log_file(name: str, lines: object = 200) -> Dict[str, object]:
    safe = valid_log_name(name)
    path = VAR_LOG_DIR / safe
    if not is_within(VAR_LOG_DIR, path):
        raise ValueError("refusing to read outside /var/log")
    return {"name": safe, "lines": tail_file(path, lines)}
