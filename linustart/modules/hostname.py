"""Hostname management: hostnamectl plus /etc/hosts bookkeeping.

On cloud images cloud-init sets the hostname at boot (unless
``preserve_hostname: true``) and may regenerate /etc/hosts from a template
(``manage_etc_hosts``), so a hostname saved here would be undone at the next
restart. Saving on such a machine also writes a cloud-init drop-in that
leaves both to the panel.
"""

from __future__ import annotations

import re
import socket
from typing import Dict, List, Mapping

from ..paths import HOSTNAME_FILE, HOSTS_FILE, rooted
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


CLOUD_HOSTNAME_FILE = rooted("etc", "cloud", "cloud.cfg.d", "99-linustart-hostname.cfg")
CLOUD_HOSTNAME_TEXT = (
    "# Written by LinuStart: the hostname is set on the System page, so cloud-init\n"
    "# must not reset it (or rewrite /etc/hosts) at boot. Delete this file to undo.\n"
    "preserve_hostname: true\n"
    "manage_etc_hosts: false\n"
)


def cloud_resets_hostname(settings: Mapping[str, object]) -> List[str]:
    """What cloud-init would undo at boot, given its merged settings."""
    undone = []
    if settings.get("preserve_hostname") is not True:
        undone.append("hostname")
    if settings.get("manage_etc_hosts") not in (None, False, "false", "False"):
        undone.append("/etc/hosts")
    return undone


def cloud_init_status() -> Dict[str, object]:
    from . import nethealth

    if not nethealth.cloud_init_active():
        return {"managed": False, "undone": []}
    undone = cloud_resets_hostname(nethealth.cloud_settings(nethealth._cloud_cfg_texts()))
    return {"managed": bool(undone), "undone": undone}


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
    if cloud_init_status()["managed"]:
        write_text(CLOUD_HOSTNAME_FILE, CLOUD_HOSTNAME_TEXT)
    return name
