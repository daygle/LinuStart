"""Process listing and termination.

Parses ``ps`` output with a pure helper (testable without root) and validates
kill requests against a strict allowlist of signals. Killing PID 1 or the
panel's own process is refused.
"""

from __future__ import annotations

import os
from typing import Dict, List

from ..util import run

PS_FORMAT = "pid=,ppid=,user=,%cpu=,%mem=,rss=,etimes=,args="
SIGNALS = ("TERM", "KILL", "HUP", "INT")
SORTS = ("cpu", "mem")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def ps_command(sort: str = "cpu") -> List[str]:
    sort = (sort or "cpu").strip().lower()
    if sort not in SORTS:
        raise ValueError(f"sort must be one of: {', '.join(SORTS)}")
    key = "%cpu" if sort == "cpu" else "%mem"
    return ["ps", "-eo", PS_FORMAT, f"--sort=-{key}"]


def parse_ps(text: str) -> List[Dict[str, object]]:
    """Parse ``ps -eo pid=,ppid=,user=,%cpu=,%mem=,rss=,etimes=,args=``."""
    processes: List[Dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        try:
            processes.append(
                {
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "user": parts[2],
                    "cpu": float(parts[3]),
                    "mem": float(parts[4]),
                    "rss_kb": int(parts[5]),
                    "elapsed": int(parts[6]),
                    "args": parts[7] if len(parts) > 7 else "",
                }
            )
        except ValueError:
            continue
    return processes


def kill_argv(pid: object, signal: str = "TERM") -> List[str]:
    """argv for terminating a process; refuses PID 1 and non-numeric PIDs."""
    try:
        number = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("pid must be a number")
    if number <= 1:
        raise ValueError("refusing to signal PID 1 or lower")
    signal = (signal or "TERM").strip().upper()
    if signal.startswith("SIG"):
        signal = signal[3:]
    if signal not in SIGNALS:
        raise ValueError(f"signal must be one of: {', '.join(SIGNALS)}")
    return ["kill", f"-{signal}", str(number)]


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def list_processes(sort: str = "cpu") -> Dict[str, object]:
    result = await run(ps_command(sort))
    processes = parse_ps(result.stdout)
    return {"processes": processes, "count": len(processes)}


async def kill(pid: object, signal: str = "TERM") -> Dict[str, object]:
    argv = kill_argv(pid, signal)
    number = int(argv[-1])
    if number == os.getpid():
        raise ValueError("refusing to signal the panel's own process")
    result = await run(argv)
    if not result.ok:
        raise RuntimeError(f"signal failed: {(result.stderr or result.stdout).strip()}")
    return {"ok": True, "pid": number, "signal": argv[1].lstrip("-")}
