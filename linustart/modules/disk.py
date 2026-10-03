"""Disk usage: filesystem overview plus a directory-size explorer.

``df`` output is parsed directly; directory scans run ``du -x`` as a
background job (they can take minutes on large disks) and the job's output is
parsed back into entries with :func:`parse_du`. Pure helpers are tested
without root.
"""

from __future__ import annotations

import posixpath
from typing import Dict, List, Optional

from ..util import run


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def valid_path(path: str) -> str:
    """Validate and normalize a directory to scan.

    Must be an absolute path without ``..`` components; nothing can escape to
    a relative location by accident.
    """
    path = (path or "").strip()
    if not path or "\x00" in path:
        raise ValueError("a path is required")
    if not path.startswith("/"):
        raise ValueError("the path must be absolute")
    if ".." in path.split("/"):
        raise ValueError("the path must not contain '..'")
    return posixpath.normpath(path)


def parse_df(text: str) -> List[Dict[str, object]]:
    """Parse ``df -B1 --output=source,target,fstype,size,used,avail,pcent``."""
    filesystems: List[Dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            size, used, avail = int(parts[3]), int(parts[4]), int(parts[5])
            percent = int(parts[6].rstrip("%"))
        except ValueError:
            continue  # header or unexpected row
        filesystems.append(
            {
                "source": parts[0],
                "target": parts[1],
                "fstype": parts[2],
                "size": size,
                "used": used,
                "avail": avail,
                "percent": percent,
            }
        )
    return filesystems


def parse_du(text: str, root: Optional[str] = None) -> List[Dict[str, object]]:
    """Parse ``du -x -b -d 1 PATH`` output into size-sorted entries.

    The ``root`` entry (the total for the scanned directory itself) is
    excluded; unparseable lines (progress/errors) are skipped.
    """
    entries: List[Dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        path = parts[1].strip()
        if root is not None and path == root:
            continue
        entries.append({"path": path, "size": size})
    entries.sort(key=lambda e: (-int(e["size"]), str(e["path"])))
    return entries


def du_command(path: str) -> List[str]:
    """argv for a one-level, cross-filesystem-boundary directory scan."""
    return ["du", "-x", "-b", "-d", "1", valid_path(path)]


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def filesystems() -> Dict[str, object]:
    result = await run(
        ["df", "-B1", "--output=source,target,fstype,size,used,avail,pcent"]
    )
    return {"filesystems": parse_df(result.stdout)}
