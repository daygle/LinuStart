"""Timezone and NTP management via timedatectl."""

from __future__ import annotations

import re
from typing import Dict, List

from ..paths import ZONEINFO_DIR
from ..util import run

_SKIP_DIRS = {"posix", "right"}
_SKIP_SUFFIXES = (".tab", ".zi", ".list", ".jpg", ".png", ".awk", ".sh")
_SKIP_FILES = {"Factory", "leapseconds", "leap-seconds.list", "tzdata.zi", "iso3166.tab"}
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def list_timezones() -> List[str]:
    """All valid tzdata names under /usr/share/zoneinfo."""
    zones: List[str] = []
    base = ZONEINFO_DIR
    if not base.is_dir():
        return zones
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        parts = rel.split("/")
        if parts[0] in _SKIP_DIRS:
            continue
        if path.name in _SKIP_FILES or path.name.endswith(_SKIP_SUFFIXES):
            continue
        if not re.match(r"^[A-Za-z0-9_+/-]+$", rel):
            continue
        zones.append(rel)
    return sorted(set(zones))


def valid_timezone(name: str, zones: List[str]) -> bool:
    return name in zones


def valid_time(value: str) -> bool:
    return bool(TIME_RE.match(value))


def _parse_show(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()
    return data


async def status() -> Dict[str, object]:
    result = await run(["timedatectl", "show", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized", "-p", "LocalRTC"])
    data = _parse_show(result.stdout) if result.ok else {}
    time_result = await run(["timedatectl", "show", "-p", "TimeUSec", "--value"])
    return {
        "timezone": data.get("Timezone", ""),
        "ntp": data.get("NTP", "no") == "yes",
        "ntp_synchronized": data.get("NTPSynchronized", "no") == "yes",
        "local_time": time_result.stdout.strip() if time_result.ok else "",
    }


async def set_timezone(tz: str) -> str:
    zones = list_timezones()
    if not valid_timezone(tz, zones):
        raise ValueError(f"unknown timezone: {tz!r}")
    await run(["timedatectl", "set-timezone", tz], check=True)
    return tz


async def set_ntp(enabled: bool) -> None:
    await run(["timedatectl", "set-ntp", "yes" if enabled else "no"], check=True)
