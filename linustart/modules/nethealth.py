"""Network setups that are not the distribution's default, and their cleanup.

The Networking page edits one backend, but a machine can carry leftovers of
another, or a tool that quietly rewrites what the panel saves:

* ``cloud-init``  - regenerates its netplan (or interfaces.d) file, so an
  address saved there is lost when the instance boots again;
* ``dhcpcd``      - a dhcpcd daemon next to ifupdown runs DHCP on every
  interface, so a static interface gets a second, leased address;
* ``ifupdown-leftover`` - an old /etc/network/interfaces stanza next to
  netplan configures the same interface a second time at boot;
* ``nm-unmanaged`` and ``networkd`` - informational: interfaces
  NetworkManager leaves to ifupdown, and a hand-written systemd-networkd
  setup the panel shows read-only.

Each finding says what is wrong and, where a safe fix exists, offers it.
Pure helpers take text so they can be tested without root.
"""

from __future__ import annotations

import fnmatch
import re
import shutil
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from ..paths import CLOUD_CFG, CLOUD_CFG_D, DHCPCD_CONF, ROOT, rooted
from ..util import read_text, run, write_text
from . import network

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

CLOUD_DISABLE_FILE = rooted("etc", "cloud", "cloud.cfg.d", "99-disable-network-config.cfg")
CLOUD_DISABLED_MARKER = rooted("etc", "cloud", "cloud-init.disabled")
CLOUD_DISABLE_TEXT = (
    "# Written by LinuStart: the network is configured on the Networking page,\n"
    "# so cloud-init must not regenerate it at boot. Delete this file to undo.\n"
    "network: {config: disabled}\n"
)
# cloud-init's own header in the files it renders.
CLOUD_GENERATED_RE = re.compile(r"generated from information provided by the datasource|cloud-init", re.I)

DHCPCD_BEGIN = "# BEGIN LinuStart - interfaces configured by ifupdown"
DHCPCD_END = "# END LinuStart"
ALLOW_LINE_RE = re.compile(r"^\s*(?:auto|allow-[A-Za-z0-9-]+)\s+(?P<names>.+?)\s*$")


def finding(fid: str, severity: str, title: str, detail: str, fix: Optional[Dict[str, str]] = None):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


# --------------------------------------------------------------------------
# cloud-init
# --------------------------------------------------------------------------

def cloud_config_disables_network(texts: Sequence[str]) -> bool:
    """Does any cloud.cfg / cloud.cfg.d file say ``network: {config: disabled}``?"""
    for text in texts:
        try:
            data = yaml.safe_load(text) if yaml is not None else None
        except Exception:  # noqa: BLE001 - a broken file is cloud-init's problem
            continue
        if isinstance(data, dict) and isinstance(data.get("network"), dict):
            if str(data["network"].get("config", "")).lower() == "disabled":
                return True
    return False


def cloud_generated(name: str, text: str) -> bool:
    head = "\n".join((text or "").splitlines()[:6])
    return "cloud-init" in name or bool(CLOUD_GENERATED_RE.search(head))


def cloud_init_finding(
    installed: bool, disabled: bool, files: Mapping[str, str]
) -> Optional[Dict[str, object]]:
    owned = [path for path, text in files.items() if cloud_generated(path.rsplit("/", 1)[-1], text)]
    if not installed or disabled or not owned:
        return None
    return finding(
        "cloud-init", "warn", "cloud-init regenerates the network configuration",
        f"{', '.join(owned)} is written by cloud-init, which can rewrite it when the machine boots: "
        "addresses saved here may silently revert. Stopping cloud-init from managing the network "
        f"writes {CLOUD_DISABLE_FILE} (delete it to undo); the current configuration stays.",
        {"label": "Stop cloud-init managing the network",
         "confirm": "cloud-init will no longer configure the network at boot; the configuration "
                    "you see here is kept. Continue?"},
    )


def _cloud_cfg_texts() -> List[str]:
    texts = [read_text(CLOUD_CFG)]
    if CLOUD_CFG_D.is_dir():
        texts += [read_text(path) for path in sorted(CLOUD_CFG_D.glob("*.cfg"))]
    return texts


def cloud_init_installed() -> bool:
    return shutil.which("cloud-init") is not None or ROOT.joinpath("usr", "bin", "cloud-init").exists()


def fix_cloud_init() -> str:
    write_text(CLOUD_DISABLE_FILE, CLOUD_DISABLE_TEXT)
    return f"wrote {CLOUD_DISABLE_FILE}"


# --------------------------------------------------------------------------
# dhcpcd daemon next to ifupdown
# --------------------------------------------------------------------------

def dhcpcd_patterns(text: str, keyword: str) -> List[str]:
    patterns: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == keyword:
            patterns += [p for p in re.split(r"[\s,]+", parts[1]) if p]
    return patterns


def dhcpcd_handles(text: str, names: Sequence[str]) -> List[str]:
    """Which of *names* a dhcpcd daemon with this dhcpcd.conf would run DHCP on."""
    deny = dhcpcd_patterns(text, "denyinterfaces")
    allow = dhcpcd_patterns(text, "allowinterfaces")
    handled = []
    for name in names:
        if any(fnmatch.fnmatch(name, p) for p in deny):
            continue
        if allow and not any(fnmatch.fnmatch(name, p) for p in allow):
            continue
        handled.append(name)
    return handled


def deny_in_dhcpcd_conf(text: str, names: Sequence[str]) -> str:
    """dhcpcd.conf with a marked ``denyinterfaces`` block covering *names*."""
    existing: List[str] = []
    begin, end = text.find(DHCPCD_BEGIN), text.find(DHCPCD_END)
    if begin != -1 and end > begin:
        existing = dhcpcd_patterns(text[begin:end], "denyinterfaces")
        text = text[:begin] + text[end + len(DHCPCD_END):].lstrip("\n")
    merged = list(dict.fromkeys([*existing, *(network.validate_interface_name(n) for n in names)]))
    block = f"{DHCPCD_BEGIN}\ndenyinterfaces {' '.join(merged)}\n{DHCPCD_END}\n"
    body = text.rstrip("\n")
    return (body + "\n\n" if body else "") + block


def dhcpcd_finding(daemon_active: bool, conf: str, ifupdown_names: Sequence[str]) -> Optional[Dict[str, object]]:
    handled = dhcpcd_handles(conf, ifupdown_names) if daemon_active else []
    if not handled:
        return None
    return finding(
        "dhcpcd", "warn", "dhcpcd also runs DHCP on interfaces ifupdown configures",
        f"The dhcpcd service is running and handles {', '.join(handled)}, which /etc/network/interfaces "
        "also configures - a static interface ends up with a second, leased address. The fix adds "
        f"'denyinterfaces {' '.join(handled)}' to {DHCPCD_CONF}, restarts dhcpcd and re-applies the "
        "interfaces, with the 90-second auto-revert.",
        {"label": "Leave these interfaces to ifupdown",
         "confirm": f"dhcpcd will stop handling {', '.join(handled)} and the interfaces are re-applied "
                    "(they go down briefly). Unconfirmed changes revert after 90 seconds. Continue?"},
    )


def write_dhcpcd_deny(names: Sequence[str]) -> None:
    write_text(DHCPCD_CONF, deny_in_dhcpcd_conf(read_text(DHCPCD_CONF), names))


async def apply_dhcpcd_fix(names: Sequence[str]) -> List[str]:
    """Restart dhcpcd with the new deny list and re-apply the interfaces."""
    ran: List[str] = []
    result = await run(["systemctl", "restart", "dhcpcd"])
    ran.append("systemctl restart dhcpcd")
    if not result.ok:
        raise RuntimeError(f"systemctl restart dhcpcd failed: {result.stderr.strip()}")
    for name in names:
        ran += await network.apply_backend("ifupdown", name)
    return ran


# --------------------------------------------------------------------------
# ifupdown leftovers next to netplan
# --------------------------------------------------------------------------

def drop_from_auto_lines(text: str, names: Sequence[str]) -> str:
    """Remove *names* from ``auto`` / ``allow-*`` lines (empty lines go)."""
    out = []
    for line in text.splitlines():
        match = ALLOW_LINE_RE.match(line)
        if match:
            keep = [n for n in match.group("names").split() if n not in names]
            if not keep:
                continue
            line = line[: match.start("names")] + " ".join(keep)
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def remove_ifupdown_leftovers(documents: Mapping[str, str], names: Sequence[str]) -> Dict[str, str]:
    """Every ifupdown file without *names*' stanzas and auto lines; only changed files."""
    changed: Dict[str, str] = {}
    for source, text in documents.items():
        updated = text
        for name in names:
            updated = network.remove_ifupdown_interface(updated, name, "inet")
            updated = network.remove_ifupdown_interface(updated, name, "inet6")
        updated = drop_from_auto_lines(updated, names)
        if updated != text:
            changed[source] = updated
    return changed


def ifupdown_leftover_finding(ifup_installed: bool, netplan_names: Sequence[str],
                              ifupdown_names: Sequence[str]) -> Optional[Dict[str, object]]:
    both = [name for name in ifupdown_names if name in netplan_names]
    if not ifup_installed or not both:
        return None
    return finding(
        "ifupdown-leftover", "warn", "Old /etc/network/interfaces entries configure netplan's interfaces too",
        f"{', '.join(both)} is configured by netplan and also has a stanza in /etc/network/interfaces "
        "(or a file it sources). ifupdown still applies it at boot, next to netplan. The fix removes "
        "those stanzas and auto lines (the files are backed up first); netplan's configuration is "
        "untouched and nothing changes until the next boot.",
        {"label": "Remove the old ifupdown entries",
         "confirm": f"Remove the /etc/network/interfaces entries for {', '.join(both)}? netplan keeps "
                    "configuring them. The old files are backed up. Continue?"},
    )


def fix_ifupdown_leftovers(names: Sequence[str]) -> List[str]:
    documents = {str(path): read_text(path) for path in network.ifupdown_files()}
    changed = remove_ifupdown_leftovers(documents, names)
    for source, text in changed.items():
        write_text(Path(source), text)  # write_text backs up the previous file
    return sorted(changed)


# --------------------------------------------------------------------------
# Informational
# --------------------------------------------------------------------------

def nm_unmanaged_finding(interfaces: Sequence[Mapping[str, object]]) -> Optional[Dict[str, object]]:
    legacy = [str(i.get("name")) for i in interfaces if i.get("backend") == "ifupdown"]
    if not legacy:
        return None
    return finding(
        "nm-unmanaged", "info", "Some interfaces are configured by ifupdown, not NetworkManager",
        f"{', '.join(legacy)} is defined in /etc/network/interfaces, so NetworkManager leaves it "
        "alone. It is listed below and edited through ifupdown.",
    )


def networkd_finding() -> Dict[str, object]:
    return finding(
        "networkd", "info", "Managed by systemd-networkd",
        f"This machine is configured by hand-written systemd-networkd files in {network.NETWORKD_DIR}. "
        "The panel shows them read-only; edit the .network files and run 'networkctl reload'.",
    )


# --------------------------------------------------------------------------
# Live
# --------------------------------------------------------------------------

def _netplan_names() -> List[str]:
    if yaml is None:
        return []
    names: List[str] = []
    for path in network._netplan_files():
        try:
            data = yaml.safe_load(read_text(path)) or {}
        except Exception:  # noqa: BLE001
            continue
        for _section, name, _node in network.netplan_devices(data):
            if name not in names:
                names.append(name)
    return names


async def findings(backend: str, config: Mapping[str, object]) -> List[Dict[str, object]]:
    """Everything the Networking page should warn about (never raises)."""
    found: List[Optional[Dict[str, object]]] = []
    try:
        if backend == "systemd-networkd":
            found.append(networkd_finding())
        if backend == "NetworkManager":
            found.append(nm_unmanaged_finding(config.get("interfaces") or []))  # type: ignore[arg-type]
        files: Dict[str, str] = {str(p): read_text(p) for p in network._netplan_files()}
        files.update({str(p): read_text(p) for p in network.ifupdown_files()[1:]})
        found.append(cloud_init_finding(
            cloud_init_installed(),
            CLOUD_DISABLED_MARKER.exists() or cloud_config_disables_network(_cloud_cfg_texts()),
            files,
        ))
        if backend == "ifupdown":
            found.append(dhcpcd_finding(
                await network._unit_active("dhcpcd"), read_text(DHCPCD_CONF), network.ifupdown_interface_names()
            ))
        if backend == "netplan":
            found.append(ifupdown_leftover_finding(
                shutil.which("ifup") is not None or ROOT.joinpath("sbin", "ifup").exists(),
                _netplan_names(), network.ifupdown_interface_names(),
            ))
    except (OSError, ValueError, RuntimeError) as exc:
        found.append(finding("check-failed", "info", "Some network checks could not run", str(exc)))
    return [f for f in found if f]


async def dhcpcd_conflicts() -> List[str]:
    if not await network._unit_active("dhcpcd"):
        return []
    return dhcpcd_handles(read_text(DHCPCD_CONF), network.ifupdown_interface_names())


def ifupdown_leftover_names() -> List[str]:
    netplan = _netplan_names()
    return [name for name in network.ifupdown_interface_names() if name in netplan]
