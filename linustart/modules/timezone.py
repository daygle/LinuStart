"""Timezone and NTP management via timedatectl."""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Dict, List, Tuple

from ..paths import ZONEINFO_DIR
from ..util import run

_SKIP_DIRS = {"posix", "right"}
_SKIP_SUFFIXES = (".tab", ".zi", ".list", ".jpg", ".png", ".awk", ".sh")
_SKIP_FILES = {"Factory", "leapseconds", "leap-seconds.list", "tzdata.zi", "iso3166.tab"}
# Rewritten by every tzdata upgrade; see _tzdata_stamp.
_INDEX_FILES = ("tzdata.zi", "zone1970.tab", "zone.tab", "+VERSION")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def list_timezones() -> List[str]:
    """All valid tzdata names under /usr/share/zoneinfo.

    Walking the tree touches ~1800 files, and it ran on every page load and
    every timezone change; the result only changes when tzdata is upgraded,
    so it is cached against :func:`_tzdata_stamp`.
    """
    base = ZONEINFO_DIR
    if not base.is_dir():
        return []
    return list(_scan_timezones(str(base), _tzdata_stamp(base)))


def _tzdata_stamp(base: Path) -> Tuple[float, ...]:
    """Modification times that change whenever tzdata is upgraded.

    The top directory's own mtime is not enough: a new zone lands in a
    subdirectory (America/Ciudad_Juarez), which leaves the top untouched. The
    index files tzdata rewrites on every upgrade - plus the subdirectories
    themselves - catch it, for the price of a few dozen stat() calls instead
    of walking every zone file.
    """
    stamps: List[float] = []
    for path in [base, *(base / name for name in _INDEX_FILES)]:
        try:
            stamps.append(path.stat().st_mtime)
        except OSError:
            stamps.append(0.0)
    try:
        stamps.extend(
            entry.stat().st_mtime
            for entry in sorted(base.iterdir())
            if entry.is_dir() and entry.name not in _SKIP_DIRS
        )
    except OSError:
        pass
    return tuple(stamps)


@functools.lru_cache(maxsize=4)
def _scan_timezones(base_dir: str, _mtime: float) -> Tuple[str, ...]:
    base = Path(base_dir)
    zones: List[str] = []
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
    return tuple(sorted(set(zones)))


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
    try:
        await run(["timedatectl", "set-ntp", "yes" if enabled else "no"], check=True)
    except RuntimeError as exc:
        # A fresh minimal install may have no time-sync daemon at all.
        if "not supported" in str(exc).lower():
            raise RuntimeError(
                "no time-sync service is installed: install systemd-timesyncd under "
                "Software → System Components, then switch NTP on"
            ) from None
        raise
