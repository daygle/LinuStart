"""APT package management: search, install, remove, upgrade."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..paths import APT_CACHE_DIR
from ..util import run

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]*(:[a-z0-9][a-z0-9-]*)?$")
SEARCH_LINE_RE = re.compile(r"^(?P<name>\S+)\s+-\s+(?P<desc>.*)$")
INST_RE = re.compile(r"^Inst\s+(?P<name>\S+)\s+\[(?P<old>[^\]]*)\]\s+\((?P<new>\S+)")
REM_RE = re.compile(r"^Remv\s+(?P<name>\S+)")

APT_ENV = {
    "DEBIAN_FRONTEND": "noninteractive",
    "NEEDRESTART_MODE": "a",
}
DPKG_OPTS = [
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
]


def validate_names(names: Sequence[str]) -> List[str]:
    cleaned = [name.strip() for name in names if name and name.strip()]
    if not cleaned:
        raise ValueError("no package names given")
    for name in cleaned:
        if not NAME_RE.match(name):
            raise ValueError(f"invalid package name: {name!r}")
    return cleaned


def parse_search_output(text: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for line in text.splitlines():
        match = SEARCH_LINE_RE.match(line.strip())
        if match:
            results.append({"name": match.group("name"), "description": match.group("desc")})
    return results


def parse_dpkg_query(text: str) -> List[Dict[str, str]]:
    packages: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or parts[2] != "install ok installed":
            continue
        packages.append({"name": parts[0], "version": parts[1]})
    return packages


def parse_upgrade_simulation(text: str) -> List[Dict[str, str]]:
    """Parse `apt-get --just-print upgrade` output."""
    upgrades: List[Dict[str, str]] = []
    for line in text.splitlines():
        match = INST_RE.match(line.strip())
        if match:
            upgrades.append(
                {"name": match.group("name"), "old": match.group("old"), "new": match.group("new")}
            )
    return upgrades


async def search(query: str) -> List[Dict[str, str]]:
    query = query.strip()
    if not query:
        return []
    result = await run(["apt-cache", "search", "--names-only", "--", query], timeout=60)
    return parse_search_output(result.stdout)[:100]


async def installed() -> List[Dict[str, str]]:
    result = await run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"],
        timeout=120,
    )
    return parse_dpkg_query(result.stdout)


async def upgradable() -> List[Dict[str, str]]:
    result = await run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=180)
    return parse_upgrade_simulation(result.stdout)


def parse_autoremove_simulation(text: str) -> List[str]:
    """Parse `apt-get -s autoremove` output (the `Remv` lines)."""
    names: List[str] = []
    for line in text.splitlines():
        match = REM_RE.match(line.strip())
        if match:
            names.append(match.group("name"))
    return names


def cache_stats(path: Optional[Path] = None) -> Dict[str, int]:
    """Size and file count of the apt package cache (/var/cache/apt/archives)."""
    directory = path if path is not None else APT_CACHE_DIR
    total = 0
    files = 0
    if directory.is_dir():
        for entry in directory.glob("*.deb"):
            try:
                total += entry.stat().st_size
                files += 1
            except OSError:
                continue
    return {"size_bytes": total, "files": files}


def install_command(names: Sequence[str]) -> List[str]:
    return ["apt-get", "-y", *DPKG_OPTS, "install", *validate_names(names)]


def remove_command(names: Sequence[str]) -> List[str]:
    return ["apt-get", "-y", *DPKG_OPTS, "remove", *validate_names(names)]


def update_command() -> List[str]:
    return ["apt-get", "update"]


def upgrade_command(full: bool = False) -> List[str]:
    return ["apt-get", "-y", *DPKG_OPTS, "full-upgrade" if full else "upgrade"]


def autoremove_command() -> List[str]:
    return ["apt-get", "-y", *DPKG_OPTS, "autoremove"]


def autoclean_command() -> List[str]:
    return ["apt-get", "autoclean"]


def clean_command() -> List[str]:
    return ["apt-get", "clean"]


async def autoremove_candidates() -> List[str]:
    """Which packages would `apt-get autoremove` uninstall? (dry run)"""
    result = await run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "autoremove"], timeout=180)
    return parse_autoremove_simulation(result.stdout)


def dry_run_command() -> List[str]:
    return ["unattended-upgrade", "--dry-run", "--debug"]
