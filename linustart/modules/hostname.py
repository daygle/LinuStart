"""Hostname management: hostnamectl plus /etc/hosts bookkeeping."""

from __future__ import annotations

import re
import socket
from typing import List

from ..paths import HOSTNAME_FILE, HOSTS_FILE
from ..util import read_text, run, write_text

LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
HOSTS_HOST_RE = re.compile(r"^127\.0\.1\.1\s+")


def valid_hostname(name: str) -> bool:
    """RFC 1123 hostname (a dotted sequence of labels)."""
    name = name.strip().rstrip(".")
    if not name or len(name) > 253:
        return False
    return all(LABEL_RE.match(part) for part in name.split("."))


def update_hosts_content(content: str, hostname: str) -> str:
    """Make the 127.0.1.1 line point at *hostname*, preserving aliases."""
    lines = content.splitlines()
    out: List[str] = []
    replaced = False
    for line in lines:
        if HOSTS_HOST_RE.match(line.strip()):
            parts = line.split()
            aliases = parts[2:]
            out.append("127.0.1.1\t" + "\t".join([hostname] + aliases))
            replaced = True
        else:
            out.append(line)
    if not replaced:
        if out and out[-1] != "":
            out.append("")
        out.append(f"127.0.1.1\t{hostname}")
    return "\n".join(out) + "\n"


async def current() -> str:
    text = read_text(HOSTNAME_FILE).strip()
    return text or socket.gethostname()


async def set_hostname(name: str) -> str:
    name = name.strip().rstrip(".")
    if not valid_hostname(name):
        raise ValueError(f"invalid hostname: {name!r}")
    await run(["hostnamectl", "set-hostname", name], check=True)
    write_text(HOSTNAME_FILE, name + "\n")
    write_text(HOSTS_FILE, update_hosts_content(read_text(HOSTS_FILE), name))
    return name
