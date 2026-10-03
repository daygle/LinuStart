"""Sudo rules: per-user drop-in files in ``/etc/sudoers.d``.

The panel only ever writes its own drop-ins (``linustart-<user>``) with one of
two shapes - full sudo or passwordless sudo - and validates each file with
``visudo -cf`` before installing it. Foreign sudoers files are listed but
never edited. Pure helpers are testable without root.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from ..paths import SUDOERS_D
from ..util import backup, is_within, read_text, run
from .users import valid_username

PREFIX = "linustart-"
DROPIN_RE = re.compile(r"^(?P<user>[a-z_][a-z0-9_-]{0,31})\s+ALL=\(ALL\)\s+(?P<nopasswd>NOPASSWD:\s*)?ALL\s*$")
MODE = 0o440


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def dropin_path(username: str) -> Path:
    """The one place a user name becomes a path.

    Every writer and remover goes through here, so the containment check sits
    on the single path that every sudoers file is reached by.
    """
    if not valid_username(username):
        raise ValueError(f"not a valid user name: {username!r}")
    path = SUDOERS_D / f"{PREFIX}{username}"
    if not is_within(SUDOERS_D, path):
        raise ValueError(f"refusing to touch a path outside {SUDOERS_D}: {username!r}")
    return path


def build_sudoers_dropin(username: str, nopasswd: bool = False) -> str:
    if not valid_username(username):
        raise ValueError(f"not a valid user name: {username!r}")
    rule = "NOPASSWD: ALL" if nopasswd else "ALL"
    return f"{username} ALL=(ALL) {rule}\n"


def parse_sudoers_dropin(text: str) -> Optional[Dict[str, object]]:
    """Recognize a panel-generated drop-in; None for anything else."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = DROPIN_RE.match(stripped)
        if not match:
            return None
        return {"user": match.group("user"), "nopasswd": bool(match.group("nopasswd"))}
    return None


def is_managed(path: Path) -> bool:
    return path.name.startswith(PREFIX)


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def validate_sudoers(content: str) -> Optional[str]:
    """Check *content* with ``visudo -cf``; return an error or None."""
    if not shutil.which("visudo"):
        return None  # non-Debian dev sandbox: nothing to validate with
    fd, tmp_name = tempfile.mkstemp(prefix="linustart-sudoers-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        result = await run(["visudo", "-cf", tmp_name])
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
    if not result.ok:
        return (result.stderr or result.stdout).strip()
    return None


def list_dropins() -> Dict[str, object]:
    entries: List[Dict[str, object]] = []
    try:
        paths = sorted(SUDOERS_D.iterdir())
    except FileNotFoundError:
        return {"dropins": []}
    for path in paths:
        if not path.is_file():
            continue
        parsed = parse_sudoers_dropin(read_text(path)) if is_managed(path) else None
        entries.append(
            {
                "file": path.name,
                "managed": is_managed(path),
                "user": parsed["user"] if parsed else "",
                "nopasswd": parsed["nopasswd"] if parsed else False,
            }
        )
    return {"dropins": entries}


async def set_rule(username: str, nopasswd: bool = False) -> Dict[str, object]:
    path = dropin_path(username)
    content = build_sudoers_dropin(username, nopasswd)
    error = await validate_sudoers(content)
    if error:
        raise ValueError(f"sudo rejected the rule: {error}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(content)
        tmp_name = handle.name
    os.chmod(tmp_name, MODE)
    if path.exists():
        backup(path)
    os.replace(tmp_name, path)
    return {"file": path.name, "user": username, "nopasswd": nopasswd}


def remove_rule(username: str) -> Dict[str, object]:
    path = dropin_path(username)
    if not path.exists():
        raise ValueError(f"no sudo rule installed for {username}")
    backup(path)
    path.unlink()
    return {"file": path.name, "removed": True}
