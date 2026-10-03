"""SSH server hardening: read and manage ``/etc/ssh/sshd_config``.

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
from typing import Dict, List, Optional, Tuple

from ..paths import SSHD_CONFIG
from ..util import read_text, run, write_text

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
    content = read_text(SSHD_CONFIG)
    for key, value in values.items():
        content = set_sshd_option(content, key, value)
    write_text(SSHD_CONFIG, content)
    error = await validate()
    if error:
        raise ValueError(f"sshd rejected the new configuration: {error}")
    return values


async def reload_service() -> None:
    """Reload sshd so the new configuration takes effect."""
    result = await run(["systemctl", "reload", "ssh"])
    if not result.ok:
        result = await run(["systemctl", "reload", "sshd"])
    if not result.ok:
        raise RuntimeError(f"reloading sshd failed: {(result.stderr or result.stdout).strip()}")


async def status() -> Dict[str, object]:
    values = parse_sshd_config(read_text(SSHD_CONFIG))
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
    }
