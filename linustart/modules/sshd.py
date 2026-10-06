"""SSH server hardening: read and manage ``/etc/ssh/sshd_config``.

Debian 12+ and Ubuntu 22.04+ start sshd_config with ``Include
/etc/ssh/sshd_config.d/*.conf`` and sshd keeps the *first* value it reads, so
a drop-in (Ubuntu cloud images ship ``50-cloudimg-settings.conf``) silently
beats anything set further down the main file. The panel therefore reads the
effective value across the main file and its includes, and writes its own
settings to ``sshd_config.d/00-linustart.conf`` - first in the include order
- whenever the main file includes that directory.

Ubuntu 22.10+ also starts sshd through ``ssh.socket``, whose port is
generated from sshd_config at daemon-reload: a Port change needs the socket
regenerated and restarted, not just a reload of the service.

Pure helpers operate on the file text so they can be tested without root.
Applying changes validates the result with ``sshd -t`` before the service is
reloaded, and every apply is paired with a confirm-or-revert session in
``routes.py`` so a bad change cannot lock anyone out of SSH.

Editing is diff-friendly: existing keyword lines are replaced in place and
comments/formatting are preserved (the same policy as the network module).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from ..paths import ROOT, SSHD_CONFIG
from ..util import is_within, read_text, run, write_text

INCLUDE_RE = re.compile(r"^\s*include\s+(?P<patterns>.+?)\s*$", re.IGNORECASE)
DROPIN_NAME = "00-linustart.conf"
DROPIN_HEADER = (
    "# Managed by LinuStart (SSH Hardening page). Read before every other drop-in,\n"
    "# so these values win: sshd keeps the first value it finds.\n"
)

MATCH_RE = re.compile(r"^\s*match\b", re.IGNORECASE)
KEYWORD_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z][A-Za-z0-9]*)(?P<sep>\s+)(?P<value>\S.*)$")

CHOICES: Dict[str, Tuple[str, ...]] = {
    "PermitRootLogin": ("yes", "no", "prohibit-password", "without-password", "forced-commands-only"),
    "PasswordAuthentication": ("yes", "no"),
    "PubkeyAuthentication": ("yes", "no"),
    "X11Forwarding": ("yes", "no"),
}
INT_RANGES: Dict[str, Tuple[int, int]] = {
    "Port": (1, 65535),
    "MaxAuthTries": (1, 10),
    "ClientAliveInterval": (0, 86400),
    "ClientAliveCountMax": (0, 10),
}

MANAGED_KEYS: List[str] = [
    "Port",
    "PermitRootLogin",
    "PasswordAuthentication",
    "PubkeyAuthentication",
    "X11Forwarding",
    "MaxAuthTries",
    "ClientAliveInterval",
    "ClientAliveCountMax",
]

DEFAULTS: Dict[str, str] = {
    "Port": "22",
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
    "PubkeyAuthentication": "yes",
    "X11Forwarding": "no",
    "MaxAuthTries": "6",
    "ClientAliveInterval": "0",
    "ClientAliveCountMax": "3",
}


# --------------------------------------------------------------------------
# Pure helpers (testable without root)
# --------------------------------------------------------------------------

def parse_sshd_config(text: str) -> Dict[str, str]:
    """Effective global values (sshd uses the first obtained value).

    Lines inside ``Match`` blocks are deliberately ignored: they only apply to
    a subset of connections and must not shadow the global picture.
    """
    values: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if MATCH_RE.match(line):
            break
        match = KEYWORD_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        lowered = key.lower()
        if lowered not in (k.lower() for k in MANAGED_KEYS):
            continue
        canonical = next(k for k in MANAGED_KEYS if k.lower() == lowered)
        if canonical not in values:
            values[canonical] = match.group("value").strip().strip('"')
    return values


def _canonical(key: str) -> Optional[str]:
    lowered = key.lower()
    return next((k for k in MANAGED_KEYS if k.lower() == lowered), None)


def include_targets(text: str) -> List[str]:
    """Include patterns of the global section (before the first Match)."""
    targets: List[str] = []
    for line in text.splitlines():
        if MATCH_RE.match(line):
            break
        match = INCLUDE_RE.match(line)
        if match:
            targets += match.group("patterns").split()
    return targets


def effective_values(documents: List[Tuple[str, str]]) -> Dict[str, Tuple[str, str]]:
    """``{key: (value, source)}`` - sshd keeps the first value it reads.

    *documents* is the main file followed, at the position of each Include,
    by the files it pulls in, as ``(source, text)`` in the order sshd reads
    them (see :func:`config_documents`). A Match block ends the global part
    of its file.
    """
    values: Dict[str, Tuple[str, str]] = {}
    for source, text in documents:
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if MATCH_RE.match(line):
                break
            match = KEYWORD_RE.match(line)
            if not match:
                continue
            key = _canonical(match.group("key"))
            if key and key not in values:
                values[key] = (match.group("value").strip().strip('"'), source)
    return values


def _resolve_include(pattern: str) -> List[Path]:
    """Files an Include pattern names (relative ones are under /etc/ssh)."""
    pure = PurePosixPath(pattern)
    if ".." in pure.parts:
        return []
    relative = str(pure.relative_to("/")) if pure.is_absolute() else str(PurePosixPath("etc", "ssh", pure))
    return [path for path in sorted(ROOT.glob(relative)) if path.is_file() and is_within(ROOT, path)]


def config_documents() -> List[Tuple[str, str]]:
    """The main file split at its Include lines, includes inline, in sshd's order."""
    main = read_text(SSHD_CONFIG)
    documents: List[Tuple[str, str]] = []
    chunk: List[str] = []
    for line in main.splitlines():
        match = INCLUDE_RE.match(line)
        if match and not MATCH_RE.match(line):
            documents.append((str(SSHD_CONFIG), "\n".join(chunk)))
            chunk = []
            for pattern in match.group("patterns").split():
                documents += [(str(path), read_text(path)) for path in _resolve_include(pattern)]
            continue
        if MATCH_RE.match(line):
            chunk.append(line)
            break
        chunk.append(line)
    documents.append((str(SSHD_CONFIG), "\n".join(chunk)))
    return documents


def dropin_path() -> Optional[Path]:
    """The panel's drop-in when the main file includes its directory, else None."""
    dropin_dir = SSHD_CONFIG.parent / "sshd_config.d"
    candidate = dropin_dir / DROPIN_NAME
    if not is_within(ROOT, candidate):
        return None
    logical = PurePosixPath("/", *candidate.relative_to(ROOT).parts)
    for pattern in include_targets(read_text(SSHD_CONFIG)):
        pure = PurePosixPath(pattern)
        absolute = pure if pure.is_absolute() else PurePosixPath("/etc/ssh") / pure
        if logical.match(str(absolute)):
            return candidate
    return None


def render_dropin(existing: str, updates: Dict[str, str]) -> str:
    """The panel's drop-in with *updates* merged into what it already holds."""
    values = {key: value for key, (value, _src) in effective_values([("", existing)]).items()}
    values.update(updates)
    body = "".join(f"{key} {values[key]}\n" for key in MANAGED_KEYS if key in values)
    return DROPIN_HEADER + body


def set_sshd_option(text: str, key: str, value: str) -> str:
    """Set *key* to *value*, replacing global occurrences in place.

    If the keyword is not present it is appended to the end of the global
    section (before the first ``Match`` block). Comments are preserved.
    """
    if key not in MANAGED_KEYS:
        raise ValueError(f"not a managed sshd keyword: {key}")
    lines = text.splitlines()
    match_at = next((i for i, line in enumerate(lines) if MATCH_RE.match(line)), len(lines))
    new_line = f"{key} {value}"
    replaced = False
    for index in range(match_at):
        match = KEYWORD_RE.match(lines[index])
        if match and match.group("key").lower() == key.lower():
            lines[index] = f"{match.group('indent')}{new_line}"
            replaced = True
    if not replaced:
        insert_at = match_at
        while insert_at > 0 and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, new_line)
    return "\n".join(lines) + "\n"


def validate_settings(updates: Dict[str, object]) -> Dict[str, str]:
    """Normalize and validate a batch of keyword updates.

    Returns ``{keyword: value}`` with values ready to write. Raises
    ``ValueError`` describing the first problem found.
    """
    normalized: Dict[str, str] = {}
    for key, raw in updates.items():
        if key not in MANAGED_KEYS:
            raise ValueError(f"not a managed sshd keyword: {key}")
        if key in CHOICES:
            value = ("yes" if raw else "no") if isinstance(raw, bool) else str(raw).strip().lower()
            if value not in CHOICES[key]:
                raise ValueError(f"{key} must be one of: {', '.join(CHOICES[key])}")
            normalized[key] = value
        else:
            low, high = INT_RANGES[key]
            try:
                number = int(str(raw).strip())
            except ValueError:
                raise ValueError(f"{key} must be a number between {low} and {high}")
            if not (low <= number <= high):
                raise ValueError(f"{key} must be between {low} and {high}")
            normalized[key] = str(number)
    return normalized


def typed_values(values: Dict[str, str]) -> Dict[str, object]:
    """Convert raw string values to bool/int where the keyword demands it."""
    result: Dict[str, object] = {}
    for key in MANAGED_KEYS:
        raw = values.get(key, DEFAULTS[key])
        if key == "PermitRootLogin":
            result[key] = raw  # multi-choice, stays a string
        elif key in CHOICES:
            result[key] = raw.lower() == "yes"
        else:
            result[key] = int(raw)
    return result


def sshd_config_error(stderr: str) -> Optional[str]:
    """Extract a real config syntax error from ``sshd -t`` output.

    ``sshd -t`` also reports environment noise (missing host keys, missing
    privilege separation directory) that is unrelated to the configuration we
    wrote; only lines that point at the config syntax are treated as fatal.
    """
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ": line " in stripped or "Bad configuration options" in stripped:
            return stripped
    return None


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

def config_files() -> List[Path]:
    """What an SSH change may write: the main file and the panel's drop-in."""
    dropin = dropin_path()
    return [SSHD_CONFIG] + ([dropin] if dropin else [])


def effective() -> Dict[str, Tuple[str, str]]:
    return effective_values(config_documents())


async def validate() -> Optional[str]:
    """Run ``sshd -t`` against the managed file; return an error or None."""
    if not shutil.which("sshd"):
        return None
    result = await run(["sshd", "-t", "-f", str(SSHD_CONFIG)])
    return sshd_config_error(result.stderr)


async def apply_settings(updates: Dict[str, object]) -> Dict[str, str]:
    """Write settings to sshd_config and validate the result.

    Raises ``ValueError`` if the resulting configuration does not parse; the
    caller (routes) restores the previous file in that case.
    """
    values = validate_settings(updates)
    dropin = dropin_path()
    if dropin is not None:
        write_text(dropin, render_dropin(read_text(dropin), values))
    # Without a drop-in, or where a line in the main file still comes first
    # (above the Include), the main file is edited in place.
    current = effective()
    main_updates = {
        key: value for key, value in values.items()
        if dropin is None or current.get(key, ("", ""))[1] != str(dropin)
    }
    if main_updates:
        content = read_text(SSHD_CONFIG)
        for key, value in main_updates.items():
            content = set_sshd_option(content, key, value)
        write_text(SSHD_CONFIG, content)
    error = await validate()
    if error:
        raise ValueError(f"sshd rejected the new configuration: {error}")
    return values


async def socket_activated() -> bool:
    """Is sshd started through ssh.socket (Ubuntu 22.10+)?"""
    try:
        return (await run(["systemctl", "is-active", "--quiet", "ssh.socket"])).ok
    except RuntimeError:
        return False


async def reload_service() -> None:
    """Reload sshd so the new configuration takes effect.

    With socket activation the listening port belongs to ssh.socket, which
    is generated from sshd_config at daemon-reload; it is regenerated and
    restarted (open sessions are separate processes and stay up).
    """
    if await socket_activated():
        for argv in (["systemctl", "daemon-reload"], ["systemctl", "restart", "ssh.socket"]):
            result = await run(argv)
            if not result.ok:
                raise RuntimeError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout).strip()}")
        await run(["systemctl", "reload-or-restart", "ssh"])  # a running sshd re-reads the rest
        return
    result = await run(["systemctl", "reload", "ssh"])
    if not result.ok:
        result = await run(["systemctl", "reload", "sshd"])
    if not result.ok:
        raise RuntimeError(f"reloading sshd failed: {(result.stderr or result.stdout).strip()}")


async def status() -> Dict[str, object]:
    found = effective()
    values = {key: value for key, (value, _src) in found.items()}
    dropin = dropin_path()
    error = await validate()
    active = None
    if shutil.which("systemctl"):
        probe = await run(["systemctl", "is-active", "ssh"])
        if not probe.ok:
            probe = await run(["systemctl", "is-active", "sshd"])
        active = probe.stdout.strip() == "active"
    return {
        "managed_keys": MANAGED_KEYS,
        "values": {key: values.get(key, DEFAULTS[key]) for key in MANAGED_KEYS},
        "typed": typed_values(values),
        "validation_error": error,
        "service_active": active,
        # where each effective value comes from, and files other than the
        # panel's that set managed keys (they win over the main file)
        "sources": {key: src for key, (_value, src) in found.items()},
        "overriding_files": sorted({
            src for _value, src in found.values()
            if src not in (str(SSHD_CONFIG), str(dropin) if dropin else "")
        }),
        "writes_to": str(dropin or SSHD_CONFIG),
        "socket_activated": await socket_activated(),
    }
