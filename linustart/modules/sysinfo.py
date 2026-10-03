"""Basic system information for the overview page."""

from __future__ import annotations

import os
import platform
import shutil
from typing import Dict, Optional

from ..paths import OS_RELEASE_FILE
from ..util import read_text


def os_release() -> Dict[str, str]:
    info: Dict[str, str] = {}
    for line in read_text(OS_RELEASE_FILE).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        info[key.strip()] = value.strip().strip('"')
    return info


def distro_info(release: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Identify the distribution family (Debian vs Ubuntu, incl. derivatives)."""
    if release is None:
        release = os_release()
    ident = release.get("ID", "").lower()
    id_like = release.get("ID_LIKE", "").lower().split()
    if ident == "ubuntu" or "ubuntu" in id_like:
        family = "ubuntu"
    elif ident == "debian" or "debian" in id_like:
        family = "debian"
    else:
        family = "unknown"
    return {
        "id": ident,
        "id_like": " ".join(id_like),
        "family": family,
        "pretty": release.get("PRETTY_NAME", ident),
    }


def _uptime_seconds() -> float:
    try:
        with open("/proc/uptime", encoding="utf-8") as handle:
            return float(handle.read().split()[0])
    except (OSError, IndexError, ValueError):
        return 0.0


def _memory() -> Dict[str, int]:
    total = available = 0
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                if key == "MemTotal":
                    total = int(rest.split()[0]) * 1024
                elif key == "MemAvailable":
                    available = int(rest.split()[0]) * 1024
    except (OSError, ValueError):
        pass
    return {"total": total, "available": available, "used": max(total - available, 0)}


def _load_average() -> list:
    try:
        with open("/proc/loadavg", encoding="utf-8") as handle:
            parts = handle.read().split()
            return [float(parts[0]), float(parts[1]), float(parts[2])]
    except (OSError, IndexError, ValueError):
        return []


def _disk(path: str = "/") -> Dict[str, int]:
    try:
        usage = shutil.disk_usage(path)
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return {"total": 0, "used": 0, "free": 0}


def overview() -> Dict[str, object]:
    release = os_release()
    return {
        "hostname": platform.node(),
        "os_name": release.get("PRETTY_NAME") or release.get("NAME") or platform.system(),
        "distro": distro_info(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "uptime_seconds": _uptime_seconds(),
        "cpus": os.cpu_count() or 1,
        "memory": _memory(),
        "disk": _disk(),
        "load_average": _load_average(),
    }
