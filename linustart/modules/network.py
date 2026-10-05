"""Networking: detect the active backend (netplan / NetworkManager / ifupdown),
read the current configuration and apply changes with SSH-lockout protection.

Pure helpers operate on strings and dicts so they can be tested without root.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..paths import INTERFACES_FILE, INTERFACES_D_DIR, NETPLAN_DIR
from ..util import read_text, run, write_text

try:  # PyYAML is only required for the netplan backend.
    import yaml
except ImportError:  # pragma: no cover - exercised on minimal installs
    yaml = None  # type: ignore[assignment]

MANAGED_KEYS = ("address", "netmask", "gateway", "dns-nameservers")
IFACE_HEADER_RE = re.compile(r"^(?P<indent>\s*)iface\s+(?P<name>\S+)\s+(?P<family>\S+)\s+(?P<method>\S+)\s*$")
AUTO_RE = re.compile(r"^\s*auto\s+(?P<names>.+?)\s*$")


# --------------------------------------------------------------------------
# Address helpers
# --------------------------------------------------------------------------

def split_cidr(cidr: str) -> Tuple[str, str]:
    """'10.0.0.5/24' -> ('10.0.0.5', '255.255.255.0')."""
    iface = ipaddress.ip_interface(cidr.strip())
    return str(iface.ip), str(iface.netmask)


def join_cidr(ip: str, netmask: str) -> str:
    """('10.0.0.5', '255.255.255.0') -> '10.0.0.5/24'."""
    iface = ipaddress.ip_interface(f"{ip.strip()}/{netmask.strip()}")
    return f"{iface.ip}/{iface.network.prefixlen}"


# --------------------------------------------------------------------------
# ifupdown (/etc/network/interfaces) - pure text handling
# --------------------------------------------------------------------------

def _managed_key(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    key = stripped.split()[0]
    return key if key in MANAGED_KEYS else None


def _all_stanza_spans(lines: Sequence[str]) -> List[Tuple[str, int, int]]:
    """Every 'iface' stanza in file order as ('name family', start, end_exclusive)."""
    spans: List[Tuple[str, int, int]] = []
    current: Optional[Tuple[str, int]] = None
    for index, line in enumerate(lines):
        header = IFACE_HEADER_RE.match(line)
        if header:
            if current is not None:
                spans.append((current[0], current[1], index))
            current = (f"{header.group('name')} {header.group('family')}", index)
            continue
        if current is not None:
            stripped = line.strip()
            if stripped and not line.startswith((" ", "\t")) and not stripped.startswith("#"):
                spans.append((current[0], current[1], index))
                current = None
    if current is not None:
        spans.append((current[0], current[1], len(lines)))
    return spans


def _stanza_spans(lines: Sequence[str]) -> Dict[str, Tuple[int, int]]:
    """Map 'name family' -> (header_index, end_index_exclusive), first wins."""
    spans: Dict[str, Tuple[int, int]] = {}
    for key, start, end in _all_stanza_spans(lines):
        spans.setdefault(key, (start, end))
    return spans


def stanza_counts(text: str) -> Dict[str, int]:
    """How many stanzas each 'name family' has - repeats included.

    ifupdown applies every stanza that names an interface, so two stanzas for
    one interface means both configurations take effect. That is how an
    interface ends up with a DHCP lease and a static address at the same time,
    and it is invisible unless something counts them.
    """
    counts: Dict[str, int] = {}
    for key, _start, _end in _all_stanza_spans(text.splitlines()):
        counts[key] = counts.get(key, 0) + 1
    return counts


def read_ifupdown_interface(text: str, name: str) -> Optional[Dict[str, object]]:
    """Extract the managed settings of one interface stanza."""
    lines = text.splitlines()
    for key, (start, end) in _stanza_spans(lines).items():
        stanza_name, family = key.split(" ", 1)
        if stanza_name != name or family != "inet":
            continue
        header = IFACE_HEADER_RE.match(lines[start])
        assert header is not None
        info: Dict[str, object] = {
            "name": name,
            "family": family,
            "method": header.group("method"),
            "auto": any(
                name in (m.group("names") or "").split()
                for line in lines
                for m in [AUTO_RE.match(line)]
                if m
            ),
            "address": None,
            "gateway": None,
            "dns": [],
            "managed": True,
        }
        raw_address: Optional[str] = None
        raw_netmask: Optional[str] = None
        dns: List[str] = []
        for line in lines[start + 1 : end]:
            key_name = _managed_key(line)
            if key_name is None:
                continue
            value = line.strip().split(None, 1)[1] if len(line.strip().split(None, 1)) > 1 else ""
            if key_name == "address":
                raw_address = value
            elif key_name == "netmask":
                raw_netmask = value
            elif key_name == "gateway":
                info["gateway"] = value
            elif key_name == "dns-nameservers":
                dns.extend(value.split())
        if raw_address:
            if "/" in raw_address:
                info["address"] = raw_address
            elif raw_netmask:
                info["address"] = join_cidr(raw_address, raw_netmask)
            else:
                info["address"] = raw_address
        info["dns"] = dns
        return info
    return None


def update_ifupdown_interface(
    text: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
) -> str:
    """Return new /etc/network/interfaces content for *name*.

    Everything outside the managed keys is preserved verbatim.
    """
    if method not in ("static", "dhcp", "manual"):
        raise ValueError(f"unsupported method: {method!r}")
    if method == "static":
        if not address:
            raise ValueError("a static interface needs an address")
        split_cidr(address)  # validate
    if gateway:
        ipaddress.ip_address(gateway)
    dns = [server for server in (dns or []) if server]

    lines = text.splitlines()
    # Every stanza for this interface, not just the first: a hand-edited file
    # can easily carry an 'iface eth0 inet dhcp' block next to the static one,
    # and ifupdown brings the interface up both ways. Rewriting only the first
    # would leave DHCP running next to the address we just set.
    occurrences = [
        (start, end) for key, start, end in _all_stanza_spans(lines) if key == f"{name} inet"
    ]

    if not occurrences:
        # Append a fresh stanza.
        block: List[str] = [f"auto {name}", f"iface {name} inet {method}"]
        block.extend(_render_options(method, address, gateway, dns))
        prefix = list(lines)
        if prefix and prefix[-1] != "":
            prefix.append("")
        return "\n".join(prefix + block) + "\n"

    header_index, end_index = occurrences[0]
    header = IFACE_HEADER_RE.match(lines[header_index])
    assert header is not None
    # The 'iface' header is written flush left, the way ifupdown itself writes
    # stanzas and the only form we can rely on being read back. The body keeps
    # the file's own indentation, which must stay indented: an unindented,
    # non-blank line is what ends a stanza for the parser above.
    body_indent = header.group("indent") or "    "
    new_lines = [f"iface {name} inet {method}"]
    body = lines[header_index + 1 : end_index]
    kept = [line for line in body if _managed_key(line) is None]
    options = _render_options(method, address, gateway, dns, indent=body_indent)
    # Keep leading comments/blank lines from the body before managed options.
    leading: List[str] = []
    rest = list(kept)
    while rest and (not rest[0].strip() or rest[0].strip().startswith("#")):
        leading.append(rest.pop(0))
    new_lines.extend(leading)
    new_lines.extend(options)
    new_lines.extend(rest)

    # Drop the other stanzas for this interface - they are the ones that would
    # keep DHCP (or a stale address) configured alongside the managed one.
    duplicates: Set[int] = set()
    for start, end in occurrences[1:]:
        duplicates.update(range(start, end))
    before = [lines[index] for index in range(header_index) if index not in duplicates]
    after = [lines[index] for index in range(end_index, len(lines)) if index not in duplicates]
    # Make sure 'auto <name>' exists somewhere before the stanza.
    has_auto = any(
        name in (m.group("names") or "").split()
        for line in lines
        for m in [AUTO_RE.match(line)]
        if m
    )
    if not has_auto:
        before = before + [f"auto {name}"]
    return "\n".join(before + new_lines + after) + "\n"


def _render_options(
    method: str,
    address: Optional[str],
    gateway: Optional[str],
    dns: Sequence[str],
    indent: str = "    ",
) -> List[str]:
    options: List[str] = []
    if method == "static" and address:
        ip, netmask = split_cidr(address)
        options.append(f"{indent}address {ip}")
        options.append(f"{indent}netmask {netmask}")
        if gateway:
            options.append(f"{indent}gateway {gateway}")
    if dns:
        options.append(f"{indent}dns-nameservers {' '.join(dns)}")
    return options


# --------------------------------------------------------------------------
# netplan - pure dict handling
# --------------------------------------------------------------------------

def read_netplan_interfaces(data: Dict[str, object]) -> List[Dict[str, object]]:
    network = data.get("network") if isinstance(data, dict) else None
    ethernets = network.get("ethernets") if isinstance(network, dict) else None
    if not isinstance(ethernets, dict):
        return []
    result: List[Dict[str, object]] = []
    for name, node in sorted(ethernets.items()):
        node = node if isinstance(node, dict) else {}
        addresses = [str(a) for a in node.get("addresses", []) or []]
        nameservers = node.get("nameservers") or {}
        dns = [str(a) for a in nameservers.get("addresses", [])] if isinstance(nameservers, dict) else []
        gateway = node.get("gateway4")
        if gateway is None:
            for route in node.get("routes", []) or []:
                if isinstance(route, dict) and str(route.get("to", "")).lower() in ("default", "0.0.0.0/0"):
                    gateway = route.get("via")
        result.append(
            {
                "name": name,
                "method": "dhcp" if node.get("dhcp4") else ("static" if addresses else "manual"),
                "address": addresses[0] if addresses else None,
                "gateway": str(gateway) if gateway else None,
                "dns": dns,
                "auto": True,
                "managed": True,
            }
        )
    return result


def update_netplan_interface(
    data: Dict[str, object],
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Return updated netplan data for one interface (pure, non-mutating)."""
    if yaml is None:
        raise RuntimeError("netplan support requires the PyYAML package")
    data = copy.deepcopy(data)
    network = data.setdefault("network", {})
    if not isinstance(network, dict):
        raise ValueError("invalid netplan document: 'network' must be a mapping")
    network.setdefault("version", 2)
    ethernets = network.setdefault("ethernets", {})
    if not isinstance(ethernets, dict):
        raise ValueError("invalid netplan document: 'ethernets' must be a mapping")
    node = ethernets.get(name)
    node = node if isinstance(node, dict) else {}

    if method == "dhcp":
        node.pop("addresses", None)
        node["dhcp4"] = True
        node.pop("gateway4", None)
        node.pop("routes", None)
    elif method == "static":
        if not address:
            raise ValueError("a static interface needs an address")
        split_cidr(address)
        node["dhcp4"] = False
        node["addresses"] = [address]
        node.pop("gateway4", None)
        if gateway:
            ipaddress.ip_address(gateway)
            node["routes"] = [{"to": "default", "via": gateway}]
        else:
            node.pop("routes", None)
    else:
        raise ValueError(f"unsupported netplan method: {method!r}")
    if dns:
        node["nameservers"] = {"addresses": list(dns)}
    else:
        node.pop("nameservers", None)
    ethernets[name] = node
    return data


# --------------------------------------------------------------------------
# Backend detection and IO
# --------------------------------------------------------------------------

async def detect_backend() -> str:
    if NETPLAN_DIR.is_dir() and any(NETPLAN_DIR.glob("*.yaml")):
        return "netplan"
    nm = await run(["systemctl", "is-active", "--quiet", "NetworkManager"])
    if nm.ok:
        return "NetworkManager"
    return "ifupdown"


def _netplan_files() -> List:
    return sorted(NETPLAN_DIR.glob("*.yaml")) if NETPLAN_DIR.is_dir() else []


def managed_config_files(backend: str) -> List:
    if backend == "netplan":
        return _netplan_files()
    if backend == "ifupdown":
        return [INTERFACES_FILE]
    return []


async def get_config(backend: Optional[str] = None) -> Dict[str, object]:
    backend = backend or await detect_backend()
    if backend == "ifupdown":
        text = read_text(INTERFACES_FILE)
        for extra in sorted(INTERFACES_D_DIR.glob("*.cfg")) if INTERFACES_D_DIR.is_dir() else []:
            text += "\n" + read_text(extra)
        names = re.findall(r"^\s*iface\s+(\S+)\s+inet\s+\S+", text, re.M)
        counts = stanza_counts(text)
        interfaces = []
        for name in dict.fromkeys(names):
            info = read_ifupdown_interface(text, name)
            # Only surface interfaces we can actually manage.
            if info and info.get("method") in ("static", "dhcp", "manual"):
                info["stanza_count"] = counts.get(f"{name} inet", 0)
                interfaces.append(info)
        return {"backend": backend, "interfaces": interfaces, "source": str(INTERFACES_FILE)}
    if backend == "netplan":
        if yaml is None:
            raise RuntimeError("netplan support requires the PyYAML package")
        interfaces: List[Dict[str, object]] = []
        for path in _netplan_files():
            data = yaml.safe_load(read_text(path)) or {}
            for info in read_netplan_interfaces(data):
                info["source"] = str(path)
                interfaces.append(info)
        return {"backend": backend, "interfaces": interfaces}
    if backend == "NetworkManager":
        listing = await run(["nmcli", "-t", "-f", "NAME,DEVICE,TYPE", "con", "show", "--active"])
        interfaces: List[Dict[str, object]] = []
        for line in listing.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 3 or parts[2] not in ("ethernet", "wifi", "802-3-ethernet", "802-11-wireless"):
                continue
            con_name, device = parts[0], parts[1]
            show = await run(["nmcli", "-t", "con", "show", con_name])
            settings: Dict[str, str] = {}
            for line2 in show.stdout.splitlines():
                key, sep, value = line2.partition(":")
                if sep:
                    settings[key.strip()] = value.strip()
            addresses = [a for a in settings.get("ipv4.addresses", "").split(",") if a]
            dns = [d for d in settings.get("ipv4.dns", "").split(",") if d]
            interfaces.append(
                {
                    "name": device,
                    "connection": con_name,
                    "method": "dhcp" if settings.get("ipv4.method") in ("auto", "shared") else "static",
                    "address": addresses[0] if addresses else None,
                    "gateway": settings.get("ipv4.gateway") or None,
                    "dns": dns,
                    "auto": True,
                    "managed": True,
                }
            )
        return {"backend": backend, "interfaces": interfaces}
    raise ValueError(f"unknown backend: {backend!r}")


async def write_interface_config(
    backend: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
) -> None:
    if backend == "ifupdown":
        text = read_text(INTERFACES_FILE)
        updated = update_ifupdown_interface(text, name, method, address, gateway, dns)
        write_text(INTERFACES_FILE, updated)
        return
    if backend == "netplan":
        if yaml is None:
            raise RuntimeError("netplan support requires the PyYAML package")
        target = None
        for path in _netplan_files():
            data = yaml.safe_load(read_text(path)) or {}
            ethernets = (data.get("network") or {}).get("ethernets") or {}
            if name in ethernets:
                target = path
                break
        if target is None:
            files = _netplan_files()
            if not files:
                raise RuntimeError("no netplan YAML files found in /etc/netplan")
            target = files[0]
        data = yaml.safe_load(read_text(target)) or {}
        data = update_netplan_interface(data, name, method, address, gateway, dns)
        write_text(target, yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
        return
    if backend == "NetworkManager":
        config = await get_config(backend)
        connection = None
        for info in config["interfaces"]:  # type: ignore[index]
            if info.get("name") == name:
                connection = info.get("connection")
                break
        if not connection:
            raise RuntimeError(f"no NetworkManager connection found for {name}")
        argv = ["nmcli", "connection", "mod", str(connection), "ipv4.method",
                "manual" if method == "static" else "auto"]
        if method == "static" and address:
            argv += ["ipv4.addresses", address]
            if gateway:
                argv += ["ipv4.gateway", gateway]
            if dns:
                argv += ["ipv4.dns", ",".join(dns)]
        await run(argv, check=True)
        return
    raise ValueError(f"unknown backend: {backend!r}")


async def apply_backend(backend: str, name: Optional[str] = None) -> List[str]:
    """Apply the written configuration and return the commands that ran."""
    if backend == "ifupdown":
        commands = [["ifdown", "--force", name], ["ifup", name]] if name else [["systemctl", "restart", "networking"]]
    elif backend == "netplan":
        commands = [["netplan", "apply"]]
    elif backend == "NetworkManager":
        commands = [["nmcli", "connection", "up", name]] if name else [["nmcli", "connection", "up", "--all"]]
    else:
        raise ValueError(f"unknown backend: {backend!r}")
    ran: List[str] = []
    for argv in commands:
        if any(part is None for part in argv):
            continue
        result = await run(argv)
        ran.append(" ".join(str(part) for part in argv))
        if not result.ok and backend == "ifupdown" and argv[0] == "ifdown":
            # Interface may not be up yet; ifup must still run.
            continue
        if not result.ok:
            raise RuntimeError(f"{' '.join(str(p) for p in argv)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return ran


async def runtime_status() -> Dict[str, object]:
    """Live interface state straight from the kernel."""
    addr = await run(["ip", "-j", "addr", "show"])
    route = await run(["ip", "-j", "route", "show"])
    try:
        import json

        addresses = json.loads(addr.stdout) if addr.ok and addr.stdout.strip() else []
        routes = json.loads(route.stdout) if route.ok and route.stdout.strip() else []
    except ValueError:
        addresses, routes = [], []
    interfaces = []
    for item in addresses:
        interfaces.append(
            {
                "name": item.get("ifname"),
                "mac": item.get("address"),
                "state": item.get("operstate", "").lower(),
                "mtu": item.get("mtu"),
                "addresses": [
                    f"{a.get('local')}/{a.get('prefixlen')}"
                    for a in item.get("addr_info", [])
                    if a.get("family") == "inet"
                ],
            }
        )
    default_route = next((r for r in routes if r.get("dst") == "default"), None)
    return {
        "interfaces": interfaces,
        "default_route": {
            "via": default_route.get("gateway"),
            "dev": default_route.get("dev"),
        }
        if default_route
        else None,
    }
