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
from ..util import run

LOG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# Unit names also carry '@' (getty@tty1.service) and '\x2d'-style escapes.
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@\\-]*$")
PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
MAX_TAIL_BYTES = 256 * 1024
MIN_LINES, MAX_LINES = 10, 2000
# journald cursors: "s=...;i=...;b=...;m=...;t=...;x=..." (hex and '=;')
CURSOR_RE = re.compile(r"^[A-Za-z0-9=;_-]{1,512}$")
CURSOR_LINE = "-- cursor: "


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
    after_cursor: str = "",
) -> List[str]:
    """argv for a bounded journal query with optional unit/priority filters.

    With *after_cursor* only entries newer than that cursor are returned -
    how the log view follows the journal without re-reading it.
    """
    argv = ["journalctl", "-n", str(clamp_lines(lines)), "--no-pager", "-o", "short-iso"]
    if after_cursor:
        if not CURSOR_RE.match(after_cursor):
            raise ValueError("not a valid journal cursor")
        argv.append(f"--after-cursor={after_cursor}")
    unit = (unit or "").strip()
    if unit:
        if not UNIT_NAME_RE.match(unit):
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
    """Read only the last slice of a (possibly huge) log file.

    The realpath-then-prefix check is written out here instead of delegating to
    util.is_within: the guard has to sit in this function, immediately before
    the file is opened, for it to be provably about this open.
    """
    real = os.path.realpath(path)
    if not real.startswith(os.path.join(os.path.realpath(VAR_LOG_DIR), "")):
        raise ValueError("refusing to read outside /var/log")
    try:
        size = os.stat(real).st_size
        with open(real, "rb") as handle:
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

def split_cursor(output: str) -> "tuple[List[str], str]":
    """Separate journalctl output from its trailing ``-- cursor:`` line."""
    lines = output.splitlines()
    cursor = ""
    if lines and lines[-1].startswith(CURSOR_LINE):
        cursor = lines.pop()[len(CURSOR_LINE):].strip()
    return lines, cursor


async def journal(
    lines: object = 200, unit: str = "", priority: str = "", after_cursor: str = ""
) -> Dict[str, object]:
    argv = journal_command(lines, unit, priority, after_cursor)
    result = await run(argv + ["--show-cursor"])
    entries, cursor = split_cursor(result.stdout)
    if after_cursor and not cursor:
        cursor = after_cursor  # nothing new: keep following from the same place
    if entries == ["-- No entries --"]:
        entries = []
    return {"lines": entries, "command": argv, "cursor": cursor}


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


def read_new_lines(path: Path, offset: int) -> "tuple[List[str], int]":
    """Complete lines appended since byte *offset*, and the next offset.

    A file smaller than *offset* was rotated or truncated, so it is read from
    the start. A trailing partial line is left for the next call. At most
    MAX_TAIL_BYTES are read per call.
    """
    real = os.path.realpath(path)
    if not real.startswith(os.path.join(os.path.realpath(VAR_LOG_DIR), "")):
        raise ValueError("refusing to read outside /var/log")
    try:
        size = os.stat(real).st_size
        if offset > size:
            offset = 0
        with open(real, "rb") as handle:
            handle.seek(offset)
            data = handle.read(MAX_TAIL_BYTES)
    except FileNotFoundError:
        raise ValueError(f"no such log file: {path.name}")
    end = data.rfind(b"\n")
    if end == -1:
        return [], offset
    chunk = data[: end + 1]
    return chunk.decode("utf-8", errors="replace").splitlines(), offset + len(chunk)


def read_log_file(name: str, lines: object = 200, offset: Optional[int] = None) -> Dict[str, object]:
    safe = valid_log_name(name)
    path = VAR_LOG_DIR / safe
    if not os.path.realpath(path).startswith(
        os.path.join(os.path.realpath(VAR_LOG_DIR), "")
    ):
        raise ValueError("refusing to read outside /var/log")
    if offset is not None:
        new_lines, next_offset = read_new_lines(path, offset)
        return {"name": safe, "lines": new_lines, "offset": next_offset}
    tail = tail_file(path, lines)
    try:
        size = os.stat(os.path.realpath(path)).st_size
    except OSError:
        size = 0
    return {"name": safe, "lines": tail, "offset": size}
