"""Systemd service manager: list, inspect and control units.

Pure helpers parse ``systemctl`` output so they can be tested without a
systemd system. Actions are validated against a fixed allowlist and executed
through the panel's background job runner (start/stop/restart/enable/disable),
while inspection uses quick synchronous reads.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Dict, List

from ..paths import SYSTEMD_SYSTEM_DIR
from ..util import backup, read_text, restore_files, run, snapshot_files, write_text

# Must start with a letter or digit: a leading '-' would turn the unit name
# into options for systemctl/journalctl.
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@\\-]*$")
SUFFIXES = (".service", ".timer", ".socket", ".mount", ".target")
ACTIONS = ("start", "stop", "restart", "reload", "enable", "disable")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def normalize_unit(name: str) -> str:
    """Validate a unit name and default it to ``.service``."""
    name = name.strip()
    if not name or not UNIT_RE.match(name) or "/" in name or name.startswith("."):
        raise ValueError(f"not a valid unit name: {name!r}")
    if not name.endswith(SUFFIXES):
        name += ".service"
    return name


def valid_action(action: str) -> bool:
    return action.strip().lower() in ACTIONS


def action_argv(name: str, action: str) -> List[str]:
    action = action.strip().lower()
    if action not in ACTIONS:
        raise ValueError(f"action must be one of: {', '.join(ACTIONS)}")
    return ["systemctl", action, normalize_unit(name)]


def parse_unit_list(text: str) -> List[Dict[str, str]]:
    """Parse ``systemctl list-units --plain --no-legend`` output.

    Columns: UNIT LOAD ACTIVE SUB DESCRIPTION (description keeps its spaces).
    """
    units: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        if not unit.endswith(SUFFIXES):
            continue
        units.append(
            {
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": parts[4] if len(parts) > 4 else "",
            }
        )
    return units


def parse_unit_files(text: str) -> Dict[str, str]:
    """Parse ``systemctl list-unit-files --plain --no-legend`` output.

    Returns ``{unit: state}`` where state is enabled/disabled/static/...
    """
    states: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        unit, state = parts[0], parts[1]
        if unit.endswith(SUFFIXES):
            states[unit] = state
    return states


def parse_show(text: str) -> Dict[str, str]:
    """Parse ``systemctl show`` key=value output."""
    props: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key] = value
    return props


def filter_units(units: List[Dict[str, str]], needle: str) -> List[Dict[str, str]]:
    needle = needle.strip().lower()
    if not needle:
        return units
    return [
        unit
        for unit in units
        if needle in unit["unit"].lower() or needle in unit["description"].lower()
    ]


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def list_services(needle: str = "") -> Dict[str, object]:
    listed, files = await asyncio.gather(
        run(["systemctl", "list-units", "--all", "--type=service", "--plain", "--no-pager", "--no-legend"]),
        run(["systemctl", "list-unit-files", "--type=service", "--plain", "--no-pager", "--no-legend"]),
    )
    states = parse_unit_files(files.stdout)
    units = parse_unit_list(listed.stdout)
    for unit in units:
        unit["enabled"] = states.get(unit["unit"], "unknown")
    units = filter_units(units, needle)
    units.sort(key=lambda u: u["unit"])
    return {"units": units, "count": len(units)}


async def unit_detail(name: str) -> Dict[str, object]:
    unit = normalize_unit(name)
    props = await run(
        [
            "systemctl", "show", unit, "--no-pager",
            "-p", "Id",
            "-p", "Description",
            "-p", "ActiveState",
            "-p", "SubState",
            "-p", "UnitFileState",
            "-p", "FragmentPath",
            "-p", "MainPID",
            "-p", "ExecMainStartTimestamp",
        ]
    )
    if not props.ok:
        raise RuntimeError(f"inspecting {unit} failed: {(props.stderr or props.stdout).strip()}")
    data = parse_show(props.stdout)
    journal = await run(["journalctl", "-u", unit, "-n", "80", "--no-pager", "-o", "short-iso"])
    return {
        "unit": unit,
        "description": data.get("Description", ""),
        "active": data.get("ActiveState", ""),
        "sub": data.get("SubState", ""),
        "enabled": data.get("UnitFileState", ""),
        "fragment": data.get("FragmentPath", ""),
        "main_pid": data.get("MainPID", ""),
        "since": data.get("ExecMainStartTimestamp", ""),
        "journal": journal.stdout.splitlines(),
    }


# --------------------------------------------------------------------------
# Drop-in overrides (what `systemctl edit` writes)
# --------------------------------------------------------------------------

MAX_OVERRIDE_BYTES = 64 * 1024
SECTION_RE = re.compile(r"^\[[A-Za-z][A-Za-z0-9-]*\]$")
ASSIGN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*\s*=")


def override_path(unit: str) -> Path:
    unit = normalize_unit(unit)
    path = SYSTEMD_SYSTEM_DIR / f"{unit}.d" / "override.conf"
    _inside_systemd_dir(path)  # validate before the path leaves this helper
    return path


def validate_override(content: str) -> str:
    """Check drop-in syntax: sections, ``Key=value`` lines, comments, and
    backslash continuations. Raises ValueError naming the first bad line."""
    if len(content.encode("utf-8")) > MAX_OVERRIDE_BYTES:
        raise ValueError("the override is too large")
    if "\x00" in content:
        raise ValueError("the override contains a NUL byte")
    seen_section = False
    continued = False
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if continued:
            continued = line.endswith("\\")
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if SECTION_RE.match(line):
            seen_section = True
            continue
        if not ASSIGN_RE.match(line):
            raise ValueError(f"line {number}: expected [Section] or Key=value: {raw.strip()[:80]!r}")
        if not seen_section:
            raise ValueError(f"line {number}: settings must follow a [Section] header such as [Service]")
        continued = line.endswith("\\")
    text = content.replace("\r\n", "\n")
    return text if not text or text.endswith("\n") else text + "\n"


def _inside_systemd_dir(path: Path) -> None:
    real = os.path.realpath(path)
    if not real.startswith(os.path.join(os.path.realpath(SYSTEMD_SYSTEM_DIR), "")):
        raise ValueError("refusing to touch a path outside /etc/systemd/system")


async def get_override(unit: str) -> Dict[str, object]:
    path = override_path(unit)
    shown = await run(["systemctl", "cat", "--no-pager", normalize_unit(unit)])
    return {
        "unit": normalize_unit(unit),
        "path": str(path),
        "content": read_text(path),
        "exists": path.exists(),
        "definition": shown.stdout if shown.ok else (shown.stderr or shown.stdout).strip(),
    }


async def _daemon_reload() -> None:
    result = await run(["systemctl", "daemon-reload"])
    if not result.ok:
        raise RuntimeError(f"systemctl daemon-reload failed: {(result.stderr or result.stdout).strip()}")


async def set_override(unit: str, content: str) -> Dict[str, object]:
    """Install (or, with empty content, remove) the unit's override.conf.

    The previous file is restored if systemd refuses to reload. The service
    itself is not restarted - that stays the operator's call.
    """
    path = override_path(unit)
    text = validate_override(content or "")
    snapshots = snapshot_files([path])
    try:
        if text.strip():
            write_text(path, text, mode=0o644)
        elif path.exists():
            backup(path)
            path.unlink()
            try:
                path.parent.rmdir()  # only when nothing else lives there
            except OSError:
                pass
        await _daemon_reload()
    except Exception:
        restore_files(snapshots)
        try:
            await _daemon_reload()
        except RuntimeError:
            pass
        raise
    return await get_override(unit)
