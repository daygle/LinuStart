"""Networking: detect the active backend (netplan / NetworkManager / ifupdown),
read the current configuration and apply changes with SSH-lockout protection.

Pure helpers operate on strings and dicts so they can be tested without root.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

from ..paths import DHCPCD_CONF, INTERFACES_FILE, NETPLAN_DIR, NETWORKD_DIR, RESOLV_CONF_FILE, ROOT
from ..util import is_within, read_text, run, write_text

try:  # PyYAML is only required for the netplan backend.
    import yaml
except ImportError:  # pragma: no cover - exercised on minimal installs
    yaml = None  # type: ignore[assignment]

MANAGED_KEYS = ("address", "netmask", "gateway", "dns-nameservers")
# Kernel interface names: at most 15 bytes (IFNAMSIZ - 1), no whitespace or
# '/'. The name is written into config files and passed to ifup/nmcli, so a
# newline or a leading '-' must never get through.
IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,14}$")
IFACE_HEADER_RE = re.compile(r"^(?P<indent>\s*)iface\s+(?P<name>\S+)\s+(?P<family>\S+)\s+(?P<method>\S+)\s*$")
AUTO_RE = re.compile(r"^\s*auto\s+(?P<names>.+?)\s*$")
SOURCE_RE = re.compile(r"^\s*(?P<kind>source|source-directory)\s+(?P<target>\S+)\s*$")
# source-directory only picks up files run-parts would run: no dots, so
# editor backups (eth0.cfg~) and dpkg leftovers (eth0.dpkg-old) are skipped.
RUN_PARTS_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


# --------------------------------------------------------------------------
# Address helpers
# --------------------------------------------------------------------------

def validate_interface_name(name: str) -> str:
    name = (name or "").strip()
    if not IFACE_NAME_RE.match(name):
        raise ValueError(f"not a valid interface name: {name!r}")
    return name


def validate_dns(servers: Optional[Sequence[str]]) -> List[str]:
    """Every DNS server must be a literal IP address.

    The list lands verbatim on a ``dns-nameservers`` line (ifupdown) or in
    nmcli arguments, so anything else - a hostname, a stray newline - is
    refused instead of being written into the configuration.
    """
    cleaned: List[str] = []
    for server in servers or []:
        server = str(server).strip()
        if not server:
            continue
        try:
            cleaned.append(str(ipaddress.ip_address(server)))
        except ValueError:
            raise ValueError(f"not a valid DNS server address: {server!r}") from None
    return cleaned


IPV6_METHODS = ("none", "auto", "dhcp", "static")


def validate_ipv6(
    method: Optional[str], address: Optional[str] = None, gateway: Optional[str] = None
) -> Optional[Dict[str, Optional[str]]]:
    """Normalize an IPv6 request; None means "leave IPv6 exactly as it is".

    ``none`` = not configured by the panel's backend, ``auto`` = SLAAC
    (router advertisements), ``dhcp`` = DHCPv6, ``static`` = fixed address.
    """
    if method is None or method == "":
        return None
    method = method.strip().lower()
    if method not in IPV6_METHODS:
        raise ValueError(f"ipv6 method must be one of: {', '.join(IPV6_METHODS)}")
    result: Dict[str, Optional[str]] = {"method": method, "address": None, "gateway": None}
    if method == "static":
        if not address:
            raise ValueError("a static IPv6 configuration needs an address")
        try:
            iface = ipaddress.ip_interface(address.strip())
        except ValueError:
            raise ValueError(f"not a valid IPv6 address: {address!r}") from None
        if iface.version != 6:
            raise ValueError(f"not an IPv6 address: {address!r}")
        result["address"] = f"{iface.ip}/{iface.network.prefixlen}"
        if gateway:
            try:
                gw = ipaddress.ip_address(gateway.strip())
            except ValueError:
                raise ValueError(f"not a valid IPv6 gateway: {gateway!r}") from None
            if gw.version != 6:
                raise ValueError(f"not an IPv6 gateway: {gateway!r}")
            result["gateway"] = str(gw)
    return result


def _require_v4(address: Optional[str], gateway: Optional[str]) -> None:
    if address and ipaddress.ip_interface(address.strip()).version != 4:
        raise ValueError(f"the IPv4 address must be IPv4 (set IPv6 below): {address!r}")
    if gateway and ipaddress.ip_address(gateway.strip()).version != 4:
        raise ValueError(f"the IPv4 gateway must be IPv4: {gateway!r}")


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


def read_ifupdown_interface(text: str, name: str, family_wanted: str = "inet") -> Optional[Dict[str, object]]:
    """Extract the managed settings of one interface stanza.

    For ``inet`` the result also carries ``ipv6`` (the ``inet6`` stanza's
    method/address/gateway, or None when there is none).
    """
    lines = text.splitlines()
    for key, (start, end) in _stanza_spans(lines).items():
        stanza_name, family = key.split(" ", 1)
        if stanza_name != name or family != family_wanted:
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
        if family_wanted == "inet":
            v6 = read_ifupdown_interface(text, name, "inet6")
            info["ipv6"] = (
                {"method": v6["method"], "address": v6["address"], "gateway": v6["gateway"]} if v6 else None
            )
        return info
    return None


def update_ifupdown_interface(
    text: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
    *,
    ensure_auto: bool = True,
    family: str = "inet",
) -> str:
    """Return new /etc/network/interfaces content for *name*.

    Everything outside the managed keys is preserved verbatim. With
    *ensure_auto* off no ``auto`` line is added - the caller knows another
    sourced file already brings the interface up. ``family="inet6"`` edits
    the IPv6 stanza instead (methods static/dhcp/auto/manual).
    """
    allowed = ("static", "dhcp", "manual") if family == "inet" else ("static", "dhcp", "auto", "manual")
    if family not in ("inet", "inet6") or method not in allowed:
        raise ValueError(f"unsupported method: {method!r}")
    name = validate_interface_name(name)
    if method == "static":
        if not address:
            raise ValueError("a static interface needs an address")
        split_cidr(address)  # validate
    if family == "inet":
        _require_v4(address if method == "static" else None, gateway)
    elif gateway:
        ipaddress.ip_address(gateway)
    dns = validate_dns(dns) if family == "inet" else []

    lines = text.splitlines()
    # Every stanza for this interface, not just the first: a hand-edited file
    # can easily carry an 'iface eth0 inet dhcp' block next to the static one,
    # and ifupdown brings the interface up both ways. Rewriting only the first
    # would leave DHCP running next to the address we just set.
    occurrences = [
        (start, end) for key, start, end in _all_stanza_spans(lines) if key == f"{name} {family}"
    ]

    if not occurrences:
        # Append a fresh stanza.
        block: List[str] = ([f"auto {name}"] if ensure_auto else []) + [f"iface {name} {family} {method}"]
        block.extend(_render_options(method, address, gateway, dns, family=family))
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
    new_lines = [f"iface {name} {family} {method}"]
    body = lines[header_index + 1 : end_index]
    kept = [line for line in body if _managed_key(line) is None]
    options = _render_options(method, address, gateway, dns, indent=body_indent, family=family)
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
    if ensure_auto and not has_auto:
        before = before + [f"auto {name}"]
    return "\n".join(before + new_lines + after) + "\n"


def has_auto_line(text: str, name: str) -> bool:
    return any(
        name in (m.group("names") or "").split()
        for line in text.splitlines()
        for m in [AUTO_RE.match(line)]
        if m
    )


def remove_ifupdown_interface(text: str, name: str, family: str = "inet") -> str:
    """Drop every ``iface <name> <family>`` stanza from *text*; nothing else changes."""
    lines = text.splitlines()
    drop: Set[int] = set()
    for key, start, end in _all_stanza_spans(lines):
        if key == f"{name} {family}":
            drop.update(range(start, end))
    if not drop:
        return text
    kept = [line for index, line in enumerate(lines) if index not in drop]
    return "\n".join(kept) + ("\n" if kept else "")


def apply_ifupdown_across(
    documents: Mapping[str, str],
    main: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
    ipv6: Optional[Mapping[str, Optional[str]]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Configure *name* across the interfaces file and everything it sources.

    ifupdown reads ``/etc/network/interfaces`` and every file pulled in with
    ``source``/``source-directory`` as one configuration, so the interface is
    edited where it is already defined (the first file that has it, or the
    main file for a new one) and its stanzas in every other file are removed;
    a leftover DHCP stanza in ``interfaces.d`` would otherwise still run next
    to the static address. Returns the updated documents and the sources that
    changed, so only those are rewritten.
    """
    if main not in documents:
        raise ValueError(f"main interfaces file was not loaded: {main!r}")
    key = f"{name} inet"
    holders = [source for source, text in documents.items() if stanza_counts(text).get(key)]
    target = holders[0] if holders else main
    auto_elsewhere = any(
        has_auto_line(text, name) for source, text in documents.items() if source != target
    )
    updated = dict(documents)
    updated[target] = update_ifupdown_interface(
        documents[target], name, method, address, gateway, dns, ensure_auto=not auto_elsewhere
    )
    for source in holders[1:]:
        updated[source] = remove_ifupdown_interface(documents[source], name)
    if ipv6 is not None:
        # The inet6 stanza lives next to the inet one; copies elsewhere would
        # apply too, so they go.
        for source in updated:
            if source != target:
                updated[source] = remove_ifupdown_interface(updated[source], name, "inet6")
        if ipv6["method"] == "none":
            updated[target] = remove_ifupdown_interface(updated[target], name, "inet6")
        else:
            updated[target] = update_ifupdown_interface(
                updated[target], name, str(ipv6["method"]), ipv6.get("address"), ipv6.get("gateway"),
                ensure_auto=False, family="inet6",
            )
    changed = [source for source in updated if updated[source] != documents[source]]
    return updated, changed


def parse_source_directives(text: str) -> List[Tuple[str, str]]:
    """``(kind, target)`` for each ``source`` / ``source-directory`` line."""
    directives: List[Tuple[str, str]] = []
    for line in text.splitlines():
        match = SOURCE_RE.match(line)
        if match:
            directives.append((match.group("kind"), match.group("target")))
    return directives


def _render_options(
    method: str,
    address: Optional[str],
    gateway: Optional[str],
    dns: Sequence[str],
    indent: str = "    ",
    family: str = "inet",
) -> List[str]:
    options: List[str] = []
    if method == "static" and address and family == "inet6":
        # ifupdown takes the prefix length on the address line for inet6
        options.append(f"{indent}address {address}")
        if gateway:
            options.append(f"{indent}gateway {gateway}")
    elif method == "static" and address:
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

# Device sections whose members take addresses, routes and DHCP the same way.
NETPLAN_SECTIONS = ("ethernets", "bonds", "bridges", "vlans", "wifis")
NETPLAN_DHCP_KEYS = ("dhcp4", "dhcp6")
V4_DEFAULTS = ("default", "0.0.0.0/0")
V6_DEFAULTS = ("default", "::/0")


def _addr_str(entry: object) -> str:
    """netplan addresses are strings, or one-key maps with per-address options."""
    if isinstance(entry, dict) and entry:
        return str(next(iter(entry)))
    return str(entry)


def _addr_version(entry: object) -> Optional[int]:
    try:
        return ipaddress.ip_interface(_addr_str(entry)).version
    except ValueError:
        return None


def _default_route_version(route: object) -> Optional[int]:
    """4 or 6 for a default route (by its destination or gateway), else None."""
    if not isinstance(route, dict):
        return None
    to = str(route.get("to", "")).lower()
    if to not in V4_DEFAULTS and to not in V6_DEFAULTS:
        return None
    if to == "0.0.0.0/0":
        return 4
    if to == "::/0":
        return 6
    try:
        return ipaddress.ip_address(str(route.get("via", ""))).version
    except ValueError:
        return None


def netplan_devices(data: Mapping[str, object]):
    """Yield ``(section, name, node)`` for every device in a netplan document."""
    network = data.get("network") if isinstance(data, Mapping) else None
    if not isinstance(network, Mapping):
        return
    for section in NETPLAN_SECTIONS:
        devices = network.get(section)
        if isinstance(devices, dict):
            for name, node in devices.items():
                yield section, str(name), node if isinstance(node, dict) else {}


def netplan_node(data: Mapping[str, object], name: str) -> Tuple[Optional[str], Optional[Dict[str, object]]]:
    for section, device, node in netplan_devices(data):
        if device == name:
            return section, node
    return None, None


def _netplan_ipv6_state(node: Mapping[str, object]) -> Dict[str, Optional[str]]:
    addresses = [_addr_str(a) for a in node.get("addresses", []) or [] if _addr_version(a) == 6]
    gateway = node.get("gateway6")
    if gateway is None:
        for route in node.get("routes", []) or []:
            if _default_route_version(route) == 6:
                gateway = route.get("via")  # type: ignore[union-attr]
    if addresses:
        method = "static"
    elif node.get("dhcp6"):
        method = "dhcp"
    elif node.get("accept-ra") is False:
        method = "none"
    else:
        method = "auto"  # networkd follows router advertisements by default
    return {
        "method": method,
        "address": addresses[0] if addresses else None,
        "gateway": str(gateway) if gateway else None,
    }


def read_netplan_interfaces(data: Dict[str, object]) -> List[Dict[str, object]]:
    result: List[Dict[str, object]] = []
    devices = sorted(netplan_devices(data), key=lambda item: (NETPLAN_SECTIONS.index(item[0]), item[1]))
    for section, name, node in devices:
        addresses = [_addr_str(a) for a in node.get("addresses", []) or [] if _addr_version(a) == 4]
        nameservers = node.get("nameservers") or {}
        dns = [str(a) for a in nameservers.get("addresses", [])] if isinstance(nameservers, dict) else []
        gateway = node.get("gateway4")
        if gateway is None:
            for route in node.get("routes", []) or []:
                if _default_route_version(route) == 4:
                    gateway = route.get("via")
        result.append(
            {
                "name": name,
                "kind": section,
                "method": "dhcp" if node.get("dhcp4") else ("static" if addresses else "manual"),
                "address": addresses[0] if addresses else None,
                "gateway": str(gateway) if gateway else None,
                "dns": dns,
                "ipv6": _netplan_ipv6_state(node),
                "auto": True,
                "managed": True,
            }
        )
    return result


def netplan_dhcp_sources(
    documents: Mapping[str, Mapping[str, object]],
    name: str,
    keys: Sequence[str] = NETPLAN_DHCP_KEYS,
) -> List[str]:
    """Every document that enables DHCP (any of *keys*) on *name*.

    netplan merges all the files in /etc/netplan, so a `dhcp4: true` in one
    file still applies after a static address is written into another one.
    That is how an interface ends up requesting a lease and holding a static
    address at the same time, and it is invisible in the file being edited.
    """
    sources: List[str] = []
    for source in sorted(documents):
        _section, node = netplan_node(documents[source], name)
        if isinstance(node, dict) and any(node.get(key) for key in keys):
            sources.append(source)
    return sources


def clear_netplan_dhcp(
    data: Mapping[str, object], name: str, keys: Sequence[str] = NETPLAN_DHCP_KEYS
) -> Tuple[Dict[str, object], bool]:
    """A copy of *data* with DHCP (*keys*) switched off for *name*, plus whether it changed.

    Only the DHCP keys are touched: another file's addresses, routes and
    nameservers belong to whoever wrote them and must survive.
    """
    section, node = netplan_node(data, name)
    if section is None or not isinstance(node, dict) or not any(node.get(key) for key in keys):
        return dict(data), False
    updated = copy.deepcopy(dict(data))
    devices = updated["network"][section]  # type: ignore[index]
    devices[name] = {**node, **{key: False for key in keys if key in node}}
    return updated, True


def apply_netplan_across(
    documents: Mapping[str, Dict[str, object]],
    target: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
    ipv6: Optional[Mapping[str, Optional[str]]] = None,
) -> Tuple[Dict[str, Dict[str, object]], List[str]]:
    """Set *name* to *method* in *target* and clear conflicting DHCP everywhere.

    Returns the updated documents and the sources that actually changed, so
    only those are rewritten - a netplan directory is full of files the panel
    has no business touching.
    """
    if target not in documents:
        raise ValueError(f"target document was not loaded: {target!r}")
    updated: Dict[str, Dict[str, object]] = {
        source: copy.deepcopy(data) for source, data in documents.items()
    }
    updated[target] = update_netplan_interface(
        updated[target], name, method, address, gateway, dns, ipv6=ipv6
    )
    changed = [target]
    # Which DHCP flags must be off in every file. Asking for DHCP leaves the
    # other files' DHCP exactly as it is (clearing it would turn DHCP off in
    # the file that had it on). Without an explicit IPv6 choice a static
    # address also ends DHCPv6, as it always has: a file configured with
    # dhcp6 would otherwise keep its lease next to the address.
    clear: List[str] = []
    if method != "dhcp":
        clear.append("dhcp4")
    if (ipv6 is None and method != "dhcp") or (ipv6 is not None and ipv6.get("method") != "dhcp"):
        clear.append("dhcp6")
    if not clear:
        return updated, changed
    updated[target], _rewritten = clear_netplan_dhcp(updated[target], name, clear)
    for source in netplan_dhcp_sources(updated, name, clear):
        if source == target:
            continue
        updated[source], rewritten = clear_netplan_dhcp(updated[source], name, clear)
        if rewritten:
            changed.append(source)
    return updated, changed


def update_netplan_interface(
    data: Dict[str, object],
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
    *,
    ipv6: Optional[Mapping[str, Optional[str]]] = None,
) -> Dict[str, object]:
    """Return updated netplan data for one interface (pure, non-mutating).

    The device is edited in whichever section holds it (a bond, a VLAN, ...);
    a new one goes under ``ethernets``. IPv4 and IPv6 are handled per family,
    so setting one never drops the other's addresses or default route.
    """
    if yaml is None:
        raise RuntimeError("netplan support requires the PyYAML package")
    name = validate_interface_name(name)
    dns = validate_dns(dns)
    data = copy.deepcopy(data)
    network = data.setdefault("network", {})
    if not isinstance(network, dict):
        raise ValueError("invalid netplan document: 'network' must be a mapping")
    network.setdefault("version", 2)
    section, _existing = netplan_node(data, name)
    section = section or "ethernets"
    devices = network.setdefault(section, {})
    if not isinstance(devices, dict):
        raise ValueError(f"invalid netplan document: '{section}' must be a mapping")
    node = devices.get(name)
    node = copy.deepcopy(node) if isinstance(node, dict) else {}

    addresses = list(node.get("addresses", []) or [])
    routes = list(node.get("routes", []) or [])

    if method not in ("dhcp", "static"):
        raise ValueError(f"unsupported netplan method: {method!r}")
    if method == "static":
        if not address:
            raise ValueError("a static interface needs an address")
        split_cidr(address)
    _require_v4(address if method == "static" else None, gateway)
    addresses = [a for a in addresses if _addr_version(a) != 4]
    routes = [r for r in routes if _default_route_version(r) != 4]
    node.pop("gateway4", None)
    if method == "dhcp":
        node["dhcp4"] = True
    else:
        node["dhcp4"] = False
        addresses.insert(0, address)
        if gateway:
            routes.append({"to": "default", "via": gateway})

    if ipv6 is not None:
        addresses = [a for a in addresses if _addr_version(a) != 6]
        routes = [r for r in routes if _default_route_version(r) != 6]
        node.pop("gateway6", None)
        v6 = ipv6.get("method")
        if v6 == "dhcp":
            node["dhcp6"] = True
            node.pop("accept-ra", None)
        else:
            if "dhcp6" in node or v6 != "auto":
                node["dhcp6"] = False
            if v6 == "auto":
                node["accept-ra"] = True
            else:
                # static and none: no SLAAC addresses appearing next to them
                node["accept-ra"] = False
            if v6 == "static":
                addresses.append(ipv6["address"])
                if ipv6.get("gateway"):
                    routes.append({"to": "::/0", "via": ipv6["gateway"]})

    if addresses:
        node["addresses"] = addresses
    else:
        node.pop("addresses", None)
    if routes:
        node["routes"] = routes
    else:
        node.pop("routes", None)
    if dns:
        node["nameservers"] = {"addresses": list(dns)}
    else:
        node.pop("nameservers", None)
    devices[name] = node
    return data


# --------------------------------------------------------------------------
# Backend detection and IO
# --------------------------------------------------------------------------

async def _unit_active(unit: str) -> bool:
    try:
        return (await run(["systemctl", "is-active", "--quiet", unit])).ok
    except RuntimeError:
        return False


async def detect_backend() -> str:
    if NETPLAN_DIR.is_dir() and any(NETPLAN_DIR.glob("*.yaml")):
        return "netplan"
    if await _unit_active("NetworkManager"):
        return "NetworkManager"
    # systemd-networkd configured by hand (no netplan): the panel shows it
    # read-only rather than writing an /etc/network/interfaces nobody reads.
    if networkd_files() and not ifupdown_interface_names() and await _unit_active("systemd-networkd"):
        return "systemd-networkd"
    return "ifupdown"


def networkd_files() -> List[Path]:
    return sorted(NETWORKD_DIR.glob("*.network")) if NETWORKD_DIR.is_dir() else []


def ifupdown_interface_names() -> List[str]:
    """Interfaces (not loopback) with an inet or inet6 stanza in the ifupdown files."""
    names: List[str] = []
    for path in ifupdown_files():
        for key in stanza_counts(read_text(path)):
            name = key.split(" ", 1)[0]
            if name != "lo" and name not in names:
                names.append(name)
    return names


def parse_networkd_file(text: str) -> Optional[Dict[str, object]]:
    """The settings the Networking page shows for one ``.network`` file."""
    section = ""
    names: List[str] = []
    info: Dict[str, object] = {"addresses": [], "gateway": None, "dns": [], "dhcp": ""}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if section == "match" and key == "name":
            names.extend(value.split())
        elif section == "network":
            if key == "address":
                info["addresses"].append(value)  # type: ignore[union-attr]
            elif key == "gateway" and not info["gateway"]:
                info["gateway"] = value
            elif key == "dns":
                info["dns"].extend(value.split())  # type: ignore[union-attr]
            elif key == "dhcp":
                info["dhcp"] = value.lower()
        elif section == "address" and key == "address":
            info["addresses"].append(value)  # type: ignore[union-attr]
        elif section == "route" and key == "gateway" and not info["gateway"]:
            info["gateway"] = value
    if not names:
        return None
    addresses = [str(a) for a in info["addresses"]]  # type: ignore[union-attr]
    dhcp = str(info["dhcp"])
    method = "dhcp" if dhcp in ("yes", "true", "ipv4", "both") else ("static" if addresses else "manual")
    v4 = next((a for a in addresses if ":" not in a), None)
    return {
        "name": " ".join(names),
        "method": method,
        "address": v4,
        "gateway": info["gateway"],
        "dns": info["dns"],
        "readonly": True,
    }


async def backend_for(name: str, detected: Optional[str] = None) -> str:
    """The backend that really configures interface *name*.

    NetworkManager leaves interfaces listed in /etc/network/interfaces alone
    (its ifupdown plugin marks them unmanaged), so on such a machine those
    are still ifupdown's to edit.
    """
    detected = detected or await detect_backend()
    if detected == "NetworkManager" and name in ifupdown_interface_names():
        config = await get_config("NetworkManager")
        nm_names = {str(i.get("name")) for i in config["interfaces"] if i.get("backend") != "ifupdown"}  # type: ignore[union-attr]
        if name not in nm_names:
            return "ifupdown"
    return detected


def _netplan_files() -> List[Path]:
    return sorted(NETPLAN_DIR.glob("*.yaml")) if NETPLAN_DIR.is_dir() else []


def _rooted_relative(target: str) -> Optional[str]:
    """A source target as a pattern relative to ROOT (None if it is unsafe).

    Relative targets are resolved against /etc/network, as ifupdown does.
    """
    pure = PurePosixPath(target)
    if ".." in pure.parts:
        return None
    if pure.is_absolute():
        return str(pure.relative_to("/"))
    return str(PurePosixPath("etc", "network", pure))


def ifupdown_files() -> List[Path]:
    """/etc/network/interfaces plus every file it sources, in ifupdown order.

    Debian's default is ``source /etc/network/interfaces.d/*`` (any name, not
    just ``*.cfg``); ``source-directory`` takes run-parts style names only.
    One level is followed, which is how every stock layout is built.
    """
    files: List[Path] = [INTERFACES_FILE]
    for kind, target in parse_source_directives(read_text(INTERFACES_FILE)):
        relative = _rooted_relative(target)
        if not relative:
            continue
        if kind == "source":
            candidates = sorted(ROOT.glob(relative))
        else:
            directory = ROOT / relative
            candidates = (
                sorted(p for p in directory.iterdir() if RUN_PARTS_NAME_RE.match(p.name))
                if directory.is_dir()
                else []
            )
        for path in candidates:
            # a symlink in interfaces.d must not lead the panel outside ROOT
            if path.is_file() and path not in files and is_within(ROOT, path):
                files.append(path)
    return files


def managed_config_files(backend: str) -> List:
    if backend == "netplan":
        return _netplan_files()
    if backend == "ifupdown":
        return ifupdown_files()
    return []


NM_TYPES = {
    "ethernet": "ethernet", "802-3-ethernet": "ethernet",
    "wifi": "wifi", "802-11-wireless": "wifi",
    "bond": "bond", "bridge": "bridge", "vlan": "vlan",
}
NM_V6_TO_PANEL = {"auto": "auto", "dhcp": "dhcp", "manual": "static", "ignore": "none", "disabled": "none"}
NM_V6_FROM_PANEL = {"auto": "auto", "dhcp": "dhcp", "static": "manual", "none": "ignore"}


def nm_split(line: str) -> List[str]:
    """Split one ``nmcli -t`` line on unescaped ':' and undo the escaping.

    Terse output escapes ':' and '\\' inside values, which matters as soon
    as a value is an IPv6 address (``2001\\:db8\\:\\:5/64``).
    """
    fields: List[str] = []
    current: List[str] = []
    chars = iter(line)
    for char in chars:
        if char == "\\":
            current.append(next(chars, ""))
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def parse_nm_settings(text: str) -> Dict[str, str]:
    """``nmcli -t con show <id>`` -> {property: value}."""
    settings: Dict[str, str] = {}
    for line in text.splitlines():
        parts = nm_split(line)
        if len(parts) >= 2:
            settings[parts[0].strip()] = ":".join(parts[1:]).strip()
    return settings


def _nm_list(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip() and item.strip() != "--"]


def nm_interface_info(con_name: str, device: str, kind: str, settings: Mapping[str, str]) -> Dict[str, object]:
    addresses = _nm_list(settings.get("ipv4.addresses", ""))
    dns = _nm_list(settings.get("ipv4.dns", "")) + _nm_list(settings.get("ipv6.dns", ""))
    v6_addresses = _nm_list(settings.get("ipv6.addresses", ""))
    v6_gateway = settings.get("ipv6.gateway", "")
    gateway = settings.get("ipv4.gateway", "")
    return {
        # an inactive connection has no device yet; it names its interface
        "name": device or settings.get("connection.interface-name", "") or con_name,
        "connection": con_name,
        "kind": kind,
        "active": bool(device),
        "method": "dhcp" if settings.get("ipv4.method") in ("auto", "shared") else "static",
        "address": addresses[0] if addresses else None,
        "gateway": gateway if gateway and gateway != "--" else None,
        "dns": dns,
        "ipv6": {
            "method": NM_V6_TO_PANEL.get(settings.get("ipv6.method", "auto"), "auto"),
            "address": v6_addresses[0] if v6_addresses else None,
            "gateway": v6_gateway if v6_gateway and v6_gateway != "--" else None,
        },
        "auto": settings.get("connection.autoconnect", "yes") == "yes",
        "managed": True,
    }


async def get_config(backend: Optional[str] = None) -> Dict[str, object]:
    backend = backend or await detect_backend()
    if backend == "ifupdown":
        documents = {path: read_text(path) for path in ifupdown_files()}
        # Each file is joined on a fresh line so a stanza never runs into the
        # next file's first line.
        text = "\n".join(content.rstrip("\n") for content in documents.values()) + "\n"
        names = re.findall(r"^\s*iface\s+(\S+)\s+inet\s+\S+", text, re.M)
        counts = stanza_counts(text)
        interfaces = []
        for name in dict.fromkeys(names):
            info = read_ifupdown_interface(text, name)
            # Only surface interfaces we can actually manage.
            if info and info.get("method") in ("static", "dhcp", "manual"):
                info["stanza_count"] = counts.get(f"{name} inet", 0)
                info["source"] = next(
                    (str(path) for path, content in documents.items()
                     if stanza_counts(content).get(f"{name} inet")),
                    str(INTERFACES_FILE),
                )
                interfaces.append(info)
        return {
            "backend": backend,
            "interfaces": interfaces,
            "source": str(INTERFACES_FILE),
            "files": [str(path) for path in documents],
        }
    if backend == "netplan":
        if yaml is None:
            raise RuntimeError("netplan support requires the PyYAML package")
        interfaces: List[Dict[str, object]] = []
        documents = {str(path): (yaml.safe_load(read_text(path)) or {}) for path in _netplan_files()}
        for source, data in documents.items():
            for info in read_netplan_interfaces(data):
                info["source"] = source
                # DHCP set anywhere else merges into this one on apply.
                info["dhcp_sources"] = [
                    other
                    for other in netplan_dhcp_sources(documents, str(info["name"]))
                    if other != source
                ]
                interfaces.append(info)
        return {"backend": backend, "interfaces": interfaces}
    if backend == "NetworkManager":
        # Every saved connection, not just the active ones: a connection that
        # is down right now is still one the operator may need to fix.
        listing = await run(["nmcli", "-t", "-f", "NAME,DEVICE,TYPE", "con", "show"])
        rows = []
        for line in listing.stdout.splitlines():
            parts = nm_split(line)
            if len(parts) >= 3 and parts[2] in NM_TYPES:
                rows.append((parts[0], parts[1], NM_TYPES[parts[2]]))
        shows = await asyncio.gather(*(run(["nmcli", "-t", "con", "show", con]) for con, _d, _k in rows))
        interfaces: List[Dict[str, object]] = [
            nm_interface_info(con, device, kind, parse_nm_settings(show.stdout))
            for (con, device, kind), show in zip(rows, shows)
        ]
        # active connections first, then by name
        interfaces.sort(key=lambda info: (not info["active"], str(info["name"])))
        # Interfaces in /etc/network/interfaces are left unmanaged by
        # NetworkManager; they are still configured (by ifupdown), so list
        # them instead of hiding what is often the main uplink.
        nm_names = {str(info["name"]) for info in interfaces}
        legacy = await get_config("ifupdown")
        for info in legacy["interfaces"]:  # type: ignore[union-attr]
            if info.get("name") not in nm_names:
                info["backend"] = "ifupdown"
                interfaces.append(info)
        return {"backend": backend, "interfaces": interfaces}
    if backend == "systemd-networkd":
        interfaces = []
        for path in networkd_files():
            info = parse_networkd_file(read_text(path))
            if info:
                info["source"] = str(path)
                interfaces.append(info)
        return {"backend": backend, "interfaces": interfaces, "source": str(NETWORKD_DIR), "readonly": True}
    raise ValueError(f"unknown backend: {backend!r}")


READONLY_BACKENDS = ("systemd-networkd",)


async def write_interface_config(
    backend: str,
    name: str,
    method: str,
    address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns: Optional[Sequence[str]] = None,
    ipv6: Optional[Mapping[str, Optional[str]]] = None,
) -> None:
    """Write the configuration; *ipv6* (from :func:`validate_ipv6`) or None
    to leave IPv6 exactly as it is."""
    name = validate_interface_name(name)
    dns = validate_dns(dns)
    if backend in READONLY_BACKENDS:
        raise ValueError(
            f"this machine's network is managed by {backend} ({NETWORKD_DIR}); "
            "the panel shows it read-only - edit the .network files and run 'networkctl reload'"
        )
    if backend == "ifupdown":
        documents = {str(path): read_text(path) for path in ifupdown_files()}
        updated, changed = apply_ifupdown_across(
            documents, str(INTERFACES_FILE), name, method, address, gateway, dns, ipv6
        )
        for source in changed:
            write_text(Path(source), updated[source])
        return
    if backend == "netplan":
        if yaml is None:
            raise RuntimeError("netplan support requires the PyYAML package")
        files = _netplan_files()
        if not files:
            raise RuntimeError("no netplan YAML files found in /etc/netplan")
        documents = {str(path): (yaml.safe_load(read_text(path)) or {}) for path in files}
        target = next(
            (source for source in documents if netplan_node(documents[source], name)[0]),
            str(files[0]),
        )
        # netplan merges every file in this directory, so writing the address
        # into one of them is not enough: a 'dhcp4: true' in another file
        # still applies, and the interface comes up with both.
        updated, changed = apply_netplan_across(
            documents, target, name, method, address, gateway, dns, ipv6
        )
        for source in changed:
            write_text(
                Path(source),
                yaml.safe_dump(updated[source], sort_keys=False, default_flow_style=False),
            )
        return
    if backend == "NetworkManager":
        connection = await nm_connection_for(name)
        if method == "static":
            if not address:
                raise ValueError("a static interface needs an address")
            split_cidr(address)
            _require_v4(address, gateway)
            argv = ["nmcli", "connection", "mod", str(connection),
                    "ipv4.method", "manual",
                    "ipv4.addresses", address,
                    "ipv4.gateway", gateway or ""]
        else:
            # With ipv4.method auto NetworkManager keeps any ipv4.addresses as
            # extra static addresses, so switching to DHCP has to clear them.
            argv = ["nmcli", "connection", "mod", str(connection),
                    "ipv4.method", "auto",
                    "ipv4.addresses", "",
                    "ipv4.gateway", ""]
        argv += ["ipv4.dns", ",".join(d for d in dns if ":" not in d)]
        argv += nm_ipv6_args(ipv6, [d for d in dns if ":" in d])
        await run(argv, check=True)
        return
    raise ValueError(f"unknown backend: {backend!r}")


def nm_ipv6_args(ipv6: Optional[Mapping[str, Optional[str]]], dns6: Sequence[str]) -> List[str]:
    """nmcli properties for an IPv6 request (nothing when IPv6 is unchanged)."""
    if ipv6 is None:
        return ["ipv6.dns", ",".join(dns6)] if dns6 else []
    method = str(ipv6["method"])
    args = ["ipv6.method", NM_V6_FROM_PANEL[method]]
    if method == "static":
        args += ["ipv6.addresses", str(ipv6["address"]), "ipv6.gateway", ipv6.get("gateway") or ""]
    else:
        # manual addresses would otherwise linger as extras next to SLAAC/DHCPv6
        args += ["ipv6.addresses", "", "ipv6.gateway", ""]
    return args + ["ipv6.dns", ",".join(dns6)]


async def nm_connection_for(name: str) -> str:
    """The connection id behind interface *name* (active ones win)."""
    config = await get_config("NetworkManager")
    for info in config["interfaces"]:  # type: ignore[index]
        if info.get("name") == name and info.get("backend") != "ifupdown":
            return str(info["connection"])
    raise RuntimeError(f"no NetworkManager connection found for {name}")


def dhcp_release_commands(name: str) -> List[List[str]]:
    """Stop a DHCP client left running for *name*, whichever ifupdown used.

    ``ifdown`` reads the configuration as it is *now*: after a switch from
    DHCP to static it sees "static", never stops the client started for the
    old DHCP stanza, and that client keeps renewing and re-adding its address
    next to the static one. Best effort: each command fails harmlessly when
    no such client runs.
    """
    name = validate_interface_name(name)
    commands: List[List[str]] = []
    pidfile = ROOT / "run" / f"dhclient.{name}.pid"
    # The pidfile path is assembled from a validated interface name; confirm the
    # resolved path still sits under ROOT so a symlink in $ROOT/run cannot drag
    # the check (and any later removal) onto a host path.
    if not is_within(ROOT, pidfile):
        raise ValueError(f"pidfile path escapes ROOT: {pidfile!r}")
    if shutil.which("dhclient") and pidfile.exists():
        commands.append(["dhclient", "-r", "-pf", str(pidfile), name])
    if shutil.which("dhcpcd"):
        commands.append(["dhcpcd", "-k", "-4", name])
    return commands


def ifupdown_apply_commands(name: Optional[str]) -> List[List[str]]:
    """ifdown, clear what the old configuration left behind, ifup.

    The IPv4 addresses are flushed between the two so the interface ends up
    with exactly what its stanza says - the same stale-configuration problem
    leaves a static address behind after a switch to DHCP.
    """
    if not name:
        return [["systemctl", "restart", "networking"]]
    name = validate_interface_name(name)
    return (
        [["ifdown", "--force", name]]
        + dhcp_release_commands(name)
        + [["ip", "-4", "addr", "flush", "dev", name, "scope", "global"], ["ifup", name]]
    )


async def apply_backend(backend: str, name: Optional[str] = None) -> List[str]:
    """Apply the written configuration and return the commands that ran."""
    if backend in READONLY_BACKENDS:
        raise ValueError(f"{backend} is shown read-only; the panel does not apply it")
    if backend == "ifupdown":
        commands = ifupdown_apply_commands(name)
    elif backend == "netplan":
        commands = [["netplan", "apply"]]
    elif backend == "NetworkManager":
        # `connection up` takes a connection id, not an interface name; the
        # two only coincide when the connection happens to be named after it.
        commands = (
            [["nmcli", "connection", "up", "id", await nm_connection_for(name)]]
            if name
            else [["nmcli", "networking", "on"]]
        )
    else:
        raise ValueError(f"unknown backend: {backend!r}")
    ran: List[str] = []
    for argv in commands:
        if any(part is None for part in argv):
            continue
        result = await run(argv)
        ran.append(" ".join(str(part) for part in argv))
        if not result.ok and backend == "ifupdown" and argv[0] in ("ifdown", "dhclient", "dhcpcd", "ip"):
            # Interface may not be up yet, and no DHCP client may be running
            # (or have anything to flush); ifup must still run.
            continue
        if not result.ok:
            raise RuntimeError(f"{' '.join(str(p) for p in argv)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return ran


async def runtime_status() -> Dict[str, object]:
    """Live interface state straight from the kernel."""
    async def query(argv):
        # A missing `ip` (no iproute2) leaves live status empty instead of
        # failing the whole page; the configuration can still be edited.
        try:
            return await run(argv)
        except RuntimeError:
            return None

    addr, route, route6 = await asyncio.gather(
        query(["ip", "-j", "addr", "show"]),
        query(["ip", "-j", "route", "show"]),
        query(["ip", "-j", "-6", "route", "show", "default"]),
    )

    def parsed(result) -> list:
        try:
            return json.loads(result.stdout) if result and result.ok and result.stdout.strip() else []
        except ValueError:
            return []

    addresses, routes, routes6 = parsed(addr), parsed(route), parsed(route6)
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
                # link-local fe80:: addresses exist on every interface; leave them out
                "addresses6": [
                    f"{a.get('local')}/{a.get('prefixlen')}"
                    for a in item.get("addr_info", [])
                    if a.get("family") == "inet6" and a.get("scope") != "link"
                ],
            }
        )

    def route_summary(candidates: list) -> Optional[Dict[str, object]]:
        found = next((r for r in candidates if r.get("dst") == "default"), None)
        return {"via": found.get("gateway"), "dev": found.get("dev")} if found else None

    return {
        "interfaces": interfaces,
        "default_route": route_summary(routes),
        "default_route6": route_summary(routes6),
    }


# --------------------------------------------------------------------------
# Resolver (/etc/resolv.conf) status
#
# The panel writes DNS servers into the backend configuration, but something
# else has to turn them into a working resolver: netplan feeds
# systemd-resolved, NetworkManager carries its own servers, and ifupdown's
# ``dns-nameservers`` line does nothing unless resolvconf (or openresolv, or
# resolvectl's compatibility shim) is installed. dhcpcd is the trap: it
# regenerates /etc/resolv.conf on every lease renewal and ignores
# dns-nameservers entirely, so the panel can report success while the machine
# resolves nothing. These helpers make that state visible instead of silent.
# --------------------------------------------------------------------------

STUB_RESOLVER = "127.0.0.53"

# Tools that rewrite /etc/resolv.conf announce themselves in the first
# comment lines ("# Generated by dhcpcd", "managed by man:systemd-resolved(8)").
# The comment is the strongest ownership signal available without parsing
# every tool's private state, so it is matched case-insensitively.
GENERATED_BY_MARKERS = (
    ("systemd-resolved", "systemd-resolved"),
    ("networkmanager", "NetworkManager"),
    ("resolvconf", "resolvconf"),
    ("dhcpcd", "dhcpcd"),
)


def parse_resolv_conf(text: str) -> Dict[str, object]:
    """Nameservers, search domains and generator of /etc/resolv.conf.

    Entries are returned verbatim: a malformed ``nameserver`` value is a
    real misconfiguration worth reporting, not something to silently drop.
    ``domain`` is only used when no ``search`` line is present, matching
    glibc's resolver behaviour.
    """
    nameservers: List[str] = []
    search: List[str] = []
    generated_by = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            if not generated_by:
                lowered = line.lower()
                for marker, name in GENERATED_BY_MARKERS:
                    if marker in lowered:
                        generated_by = name
                        break
            continue
        parts = line.split()
        if parts[0] == "nameserver" and len(parts) >= 2:
            nameservers.append(parts[1])
        elif parts[0] == "search" and len(parts) >= 2:
            search.extend(parts[1:])
        elif parts[0] == "domain" and len(parts) >= 2 and not search:
            search.append(parts[1])
    return {
        "nameservers": nameservers,
        "search": search,
        "generated_by": generated_by,
    }


def resolver_manager(
    generated_by: str,
    has_stub_address: bool,
    resolved_active: Optional[bool],
    has_resolvconf: bool,
    has_dhcpcd: bool,
) -> str:
    """Who owns /etc/resolv.conf, strongest signal first.

    A generator comment beats everything: a file dhcpcd wrote will be
    rewritten by dhcpcd again, whatever else is installed. Without one, the
    resolved stub address plus a running systemd-resolved (the Ubuntu
    default) wins, then an installed resolvconf, then dhcpcd. ``static``
    means a plain file nobody regenerates - which is fine until it isn't.
    """
    if generated_by:
        return generated_by
    if has_stub_address and resolved_active:
        return "systemd-resolved"
    if has_resolvconf:
        return "resolvconf"
    if resolved_active:
        return "systemd-resolved"
    if has_dhcpcd:
        return "dhcpcd"
    return "static"


def dns_setting_applies(backend: str, manager: str, has_resolvconf: bool) -> bool:
    """Does the panel's per-interface DNS field reach the live resolver?"""
    if backend == "NetworkManager":
        return True  # nmcli writes ipv4.dns straight into the connection
    if backend == "netplan":
        return True  # netplan apply feeds systemd-resolved / systemd-networkd
    if backend == "systemd-networkd":
        return True  # its own DNS= lines feed systemd-resolved; the panel only shows them
    # ifupdown: `dns-nameservers` is a request, not a write - something has
    # to pick it up and rewrite /etc/resolv.conf. resolvconf and its
    # equivalents (openresolv, resolvectl's shim) do; dhcpcd, which owns the
    # file on many minimal installs, does not.
    if manager == "dhcpcd":
        return False
    return has_resolvconf


def resolver_summary(
    backend: str,
    info: Mapping[str, object],
    *,
    resolved_active: Optional[bool],
    has_resolvconf: bool,
    has_dhcpcd: bool,
) -> Dict[str, object]:
    """Pure resolver status + the warnings the Networking page shows."""
    nameservers = [str(item) for item in info.get("nameservers") or []]
    search = [str(item) for item in info.get("search") or []]
    manager = resolver_manager(
        str(info.get("generated_by") or ""),
        STUB_RESOLVER in nameservers,
        resolved_active,
        has_resolvconf,
        has_dhcpcd,
    )
    applies = dns_setting_applies(backend, manager, has_resolvconf)

    warnings: List[str] = []
    invalid = [item for item in nameservers if _is_ip(item) is None]
    if invalid:
        warnings.append(
            f"/etc/resolv.conf has nameserver entries that are not IP addresses: {', '.join(invalid)}"
        )
    if not nameservers:
        warnings.append(
            "/etc/resolv.conf contains no nameserver lines: the machine cannot resolve "
            "any name, which looks like 'no internet' from the outside"
        )
    if backend == "ifupdown" and not applies:
        if manager == "dhcpcd":
            warnings.append(
                "dhcpcd owns /etc/resolv.conf and ignores the panel's DNS setting: set "
                "static domain_name_servers in /etc/dhcpcd.conf, or install resolvconf"
            )
        else:
            warnings.append(
                "the DNS servers saved on this page (dns-nameservers) are never applied: "
                "no resolvconf hook is installed. Install resolvconf, or write the "
                "nameservers into /etc/resolv.conf directly"
            )

    return {
        "nameservers": nameservers,
        "search": search,
        "generated_by": str(info.get("generated_by") or ""),
        "manager": manager,
        "resolved_active": resolved_active,
        "has_resolvconf": has_resolvconf,
        "has_dhcpcd": has_dhcpcd,
        "dns_setting_applies": applies,
        "warnings": warnings,
    }


def _is_ip(value: str) -> Optional[str]:
    """The normalized IP address, or None when the entry is not one."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


async def resolver_status(backend: Optional[str] = None) -> Dict[str, object]:
    """Live resolver state: read /etc/resolv.conf, ask who owns it.

    Read-only and fault-tolerant: a missing resolv.conf, a missing systemctl
    or a non-systemd machine all degrade to a report instead of failing the
    whole Networking page.
    """
    backend = backend or await detect_backend()

    async def query(argv) -> Optional[bool]:
        try:
            return (await run(argv)).ok
        except RuntimeError:
            return None

    resolved_active, info = await asyncio.gather(
        query(["systemctl", "is-active", "--quiet", "systemd-resolved"]),
        asyncio.to_thread(parse_resolv_conf, read_text(RESOLV_CONF_FILE)),
    )
    summary = resolver_summary(
        backend,
        info,
        resolved_active=resolved_active,
        has_resolvconf=shutil.which("resolvconf") is not None,
        has_dhcpcd=shutil.which("dhcpcd") is not None or DHCPCD_CONF.is_file(),
    )
    summary["path"] = str(RESOLV_CONF_FILE)
    summary["exists"] = RESOLV_CONF_FILE.is_file()
    return summary
