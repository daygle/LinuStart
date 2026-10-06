"""System components the panel relies on: what is installed, what is in use,
what can be installed, and what is installed but unused and safe to remove.

A fresh minimal install may lack a firewall, a time-sync daemon or cron; a
long-lived machine often carries the leftovers of earlier choices (a second
firewall, a mail transfer agent nothing uses, a stopped NTP daemon). This
module looks at both the same way:

* **install** - ``apt-get --no-remove install``, so an install that would
  remove anything else (a conflicting package) aborts instead;
* **remove**  - only for a component that is installed and *not in use*, and
  only after ``apt-get -s remove`` shows nothing else would go with it.

What "in use" means is decided per area by asking the module that owns it
(the firewall backend, the mail transport, the resolver, a running daemon).
Things that are a choice rather than a leftover - cron, unattended-upgrades,
the SSH server - are offered for install but never for removal.
"""

from __future__ import annotations

import re
import shutil
from typing import Dict, List, Mapping, Optional, Sequence

from ..util import run
from . import packages

REMV_RE = re.compile(r"^Remv\s+(?P<name>\S+)")

# id -> definition. "packages" are what install/remove act on (the first is
# the one installed); "detect" are the package names that mean "installed".
COMPONENTS: Dict[str, Dict[str, object]] = {
    "ufw": {"group": "Firewall", "label": "ufw", "packages": ["ufw"], "service": "ufw",
            "about": "Simple firewall front end (recommended)."},
    "nftables": {"group": "Firewall", "label": "nftables", "packages": ["nftables"], "service": "nftables",
                 "about": "The kernel firewall's own tool; the panel keeps its rules in a marked block."},
    "firewalld": {"group": "Firewall", "label": "firewalld", "packages": ["firewalld"], "service": "firewalld",
                  "about": "Zone-based firewall daemon."},
    "postfix": {"group": "Mail", "label": "Postfix", "packages": ["postfix"], "service": "postfix",
                "about": "Mail relay with a local queue."},
    "msmtp-mta": {"group": "Mail", "label": "msmtp", "packages": ["msmtp-mta"],
                  "about": "Lightweight sendmail that hands mail to a relay (no daemon)."},
    "exim4": {"group": "Mail", "label": "Exim", "packages": ["exim4-base", "exim4-daemon-light",
                                                             "exim4-daemon-heavy", "exim4-config", "exim4"],
              "service": "exim4", "install": False, "about": "Debian's default mail transfer agent."},
    "ssmtp": {"group": "Mail", "label": "sSMTP", "packages": ["ssmtp"], "install": False,
              "about": "Unmaintained sendmail replacement."},
    "nullmailer": {"group": "Mail", "label": "Nullmailer", "packages": ["nullmailer"], "service": "nullmailer",
                   "install": False, "about": "Relay-only mail transfer agent."},
    "dma": {"group": "Mail", "label": "DragonFly Mail Agent", "packages": ["dma"], "install": False,
            "about": "Small local mail transfer agent."},
    "resolvconf": {"group": "DNS", "label": "resolvconf", "packages": ["resolvconf"],
                   "about": "Applies the DNS servers set on the Networking page (ifupdown systems)."},
    "systemd-timesyncd": {"group": "Time sync", "label": "systemd-timesyncd", "packages": ["systemd-timesyncd"],
                          "service": "systemd-timesyncd", "about": "Simple NTP client (recommended)."},
    "chrony": {"group": "Time sync", "label": "chrony", "packages": ["chrony"], "service": "chrony",
               "install": False, "about": "Full NTP client/server."},
    "ntpsec": {"group": "Time sync", "label": "NTPsec", "packages": ["ntpsec", "ntp"], "service": "ntpsec",
               "install": False, "about": "Classic NTP daemon."},
    "unattended-upgrades": {"group": "Updates", "label": "unattended-upgrades", "packages": ["unattended-upgrades"],
                            "removable": False, "about": "Installs security updates automatically."},
    "cron": {"group": "Scheduling", "label": "cron", "packages": ["cron"], "service": "cron",
             "removable": False, "about": "Runs scheduled jobs (the Cron page)."},
}
GROUP_ORDER = ["Firewall", "Mail", "DNS", "Time sync", "Updates", "Scheduling"]
# mail.classify_sendmail_target names -> component ids
SENDMAIL_PROVIDERS = {"postfix": "postfix", "msmtp": "msmtp-mta", "exim": "exim4", "ssmtp": "ssmtp",
                      "nullmailer": "nullmailer", "dma": "dma"}


# --------------------------------------------------------------------------
# Pure decisions
# --------------------------------------------------------------------------

def installed_packages_of(component: Mapping[str, object], installed: Sequence[str]) -> List[str]:
    return [name for name in component["packages"] if name in installed]  # type: ignore[union-attr]


def classify(
    cid: str,
    installed: Sequence[str],
    *,
    in_use: Mapping[str, str],
    active_services: Sequence[str],
    blocked: Mapping[str, str],
) -> Dict[str, object]:
    """The row the Components card shows for one component.

    *in_use* maps component ids to why they are in use; *blocked* maps ids
    to why installing or removing them is refused on this machine.
    """
    component = COMPONENTS[cid]
    present = installed_packages_of(component, installed)
    service = component.get("service")
    running = bool(service) and service in active_services
    why = in_use.get(cid) or (f"{service} is running" if running else "")
    row: Dict[str, object] = {
        "id": cid,
        "group": component["group"],
        "label": component["label"],
        "about": component["about"],
        "packages": present or [component["packages"][0]],  # type: ignore[index]
        "installed": bool(present),
        "in_use": bool(present) and bool(why),
        "detail": why,
        "can_install": False,
        "can_remove": False,
        "blocked": blocked.get(cid, ""),
    }
    if not present:
        row["state"] = "not installed"
        row["can_install"] = component.get("install", True) is not False and not row["blocked"]
    elif why:
        row["state"] = "in use"
    else:
        row["state"] = "installed, unused"
        row["can_remove"] = component.get("removable", True) is not False and not row["blocked"]
    return row


def removal_extras(simulation: str, allowed: Sequence[str]) -> List[str]:
    """Packages ``apt-get -s remove`` would take along beyond *allowed*."""
    removed = [m.group("name") for m in (REMV_RE.match(line.strip()) for line in simulation.splitlines()) if m]
    return [name for name in removed if name.split(":", 1)[0] not in allowed]


def install_command(cid: str) -> List[str]:
    """apt-get install that aborts rather than remove a conflicting package."""
    argv = packages.install_command([COMPONENTS[cid]["packages"][0]])  # type: ignore[index]
    return argv[:2] + ["--no-remove"] + argv[2:]


def remove_command(names: Sequence[str]) -> List[str]:
    return packages.remove_command(list(names))


# --------------------------------------------------------------------------
# Live
# --------------------------------------------------------------------------

async def _installed() -> List[str]:
    try:
        result = await run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"], timeout=60)
    except RuntimeError:
        return []
    return [p["name"] for p in packages.parse_dpkg_query(result.stdout)]


async def _active(services: Sequence[str]) -> List[str]:
    active = []
    for service in services:
        try:
            if (await run(["systemctl", "is-active", "--quiet", service])).ok:
                active.append(service)
        except RuntimeError:
            continue
    return active


async def _in_use(installed: Sequence[str]) -> Dict[str, str]:
    """Ask the module owning each area what it is using right now."""
    from . import firewall, mail, network

    in_use: Dict[str, str] = {}
    try:
        backend = await firewall.detect_backend()
        in_use[backend] = "the firewall managed by the panel"
    except RuntimeError:
        pass
    if shutil.which("systemctl"):
        try:
            if (await run(["systemctl", "is-enabled", "--quiet", "nftables"])).ok:
                in_use.setdefault("nftables", "nftables.service loads rules at boot")
        except RuntimeError:
            pass
    try:
        mailer = await mail.mailer_status()
        provider = SENDMAIL_PROVIDERS.get(str(mailer.get("sendmail_provider") or ""))
        if provider:
            in_use[provider] = "provides sendmail (alerts and reports go through it)"
        transport = mail.TRANSPORT_PACKAGE.get(mail.current_transport())
        if transport and transport in installed:
            in_use.setdefault(transport, "the panel's mail transport")
    except (RuntimeError, ValueError):
        pass
    try:
        resolver = await network.resolver_status()
        if resolver.get("manager") == "resolvconf":
            in_use["resolvconf"] = "manages /etc/resolv.conf"
    except (RuntimeError, ValueError, OSError):
        pass
    return in_use


async def _blocked(installed: Sequence[str]) -> Dict[str, str]:
    """Installs and removals refused on this machine, and why."""
    from . import mail, network, resolvconf

    blocked: Dict[str, str] = {}
    try:
        server = await mail.mail_server_status()
    except (RuntimeError, ValueError):
        server = {"detected": False}
    if server.get("detected"):
        reason = f"this machine is a mail server ({server.get('detail')})"
        for cid, component in COMPONENTS.items():
            if component["group"] == "Mail" and cid != "msmtp-mta":
                blocked[cid] = reason
    blocked.update(exclusive_blocks(installed))
    if "resolvconf" not in installed:
        try:
            backend = await network.detect_backend()
            resolver = await network.resolver_status(backend)
            if not resolvconf.setup_offered(backend, resolver):
                blocked["resolvconf"] = "not needed here: this system already applies the panel's DNS"
        except (RuntimeError, ValueError, OSError):
            blocked["resolvconf"] = "could not tell whether it is needed"
    return blocked


# Areas where one installed component excludes installing another: a
# second firewall would take over from the first (the panel prefers ufw
# when both exist), a second mail transfer agent conflicts in apt, and two
# time-sync daemons fight over the clock.
EXCLUSIVE_GROUPS = {
    "Firewall": "the panel would switch to the new one and the rules managed now stop being used",
    "Mail": "mail transfer agents replace each other",
    "Time sync": "two time-sync services would fight over the clock",
}


def exclusive_blocks(installed: Sequence[str]) -> Dict[str, str]:
    blocked: Dict[str, str] = {}
    for group, why in EXCLUSIVE_GROUPS.items():
        present = [cid for cid, c in COMPONENTS.items()
                   if c["group"] == group and installed_packages_of(c, installed)]
        if not present:
            continue
        names = ", ".join(str(COMPONENTS[cid]["label"]) for cid in present)
        for cid, component in COMPONENTS.items():
            if component["group"] == group and cid not in present:
                blocked[cid] = f"{names} is installed; {why} (remove it first if it is unused)"
    return blocked


async def status() -> Dict[str, object]:
    installed = await _installed()
    services = [str(c["service"]) for c in COMPONENTS.values() if c.get("service")]
    active = await _active(services)
    in_use = await _in_use(installed)
    blocked = await _blocked(installed)
    rows = [classify(cid, installed, in_use=in_use, active_services=active, blocked=blocked) for cid in COMPONENTS]
    groups = [{"name": name, "items": [r for r in rows if r["group"] == name]} for name in GROUP_ORDER]
    return {"groups": groups}


async def row(cid: str) -> Dict[str, object]:
    if cid not in COMPONENTS:
        raise ValueError(f"unknown component: {cid!r}")
    data = await status()
    for group in data["groups"]:  # type: ignore[union-attr]
        for item in group["items"]:
            if item["id"] == cid:
                return item
    raise ValueError(f"unknown component: {cid!r}")


async def check_removal(cid: str) -> List[str]:
    """The packages a removal acts on, after proving nothing else goes with them."""
    item = await row(cid)
    if not item["can_remove"]:
        reason = item.get("blocked") or (item.get("detail") and f"it is in use: {item['detail']}") or item["state"]
        raise ValueError(f"{item['label']} cannot be removed: {reason}")
    names = list(item["packages"])  # type: ignore[arg-type]
    simulation = await run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "remove", *names], timeout=180)
    if not simulation.ok:
        raise RuntimeError(f"apt-get could not plan the removal: {(simulation.stderr or simulation.stdout).strip()}")
    extras = removal_extras(simulation.stdout, names)
    if extras:
        raise ValueError(f"removing {item['label']} would also remove {', '.join(extras)}; leaving it installed")
    return names


async def check_install(cid: str) -> Optional[str]:
    """None when the component may be installed, else the reason it may not."""
    item = await row(cid)
    if item["can_install"]:
        return None
    return str(item.get("blocked") or f"{item['label']} is {item['state']}")
