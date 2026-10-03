"""Systemd service manager: list, inspect and control units.

Pure helpers parse ``systemctl`` output so they can be tested without a
systemd system. Actions are validated against a fixed allowlist and executed
through the panel's background job runner (start/stop/restart/enable/disable),
while inspection uses quick synchronous reads.
"""

from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Tuple

from ..util import run

UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\-]+$")
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
        if not unit.endswith((".service", ".timer", ".socket", ".mount", ".target")):
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
    listed = await run(
        ["systemctl", "list-units", "--all", "--type=service", "--plain", "--no-pager", "--no-legend"]
    )
    files = await run(
        ["systemctl", "list-unit-files", "--type=service", "--plain", "--no-pager", "--no-legend"]
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
