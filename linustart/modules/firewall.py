"""Firewall management for UFW and nftables.

The panel supports two backends and detects which one is available:

* ``ufw``      - rules are managed through the ``ufw`` CLI, state parsed from
  ``ufw status verbose``. Snapshots of ``/etc/ufw`` back every change.
* ``nftables`` - a clearly marked managed block inside ``/etc/nftables.conf``
  holds the panel's table (``inet linustart``); the rest of the file is left
  untouched. Every apply is validated with ``nft -c`` first.

A firewall change can lock you out of a server just like a network change, so
routes.py wraps every apply in a confirm-or-revert session: the old state is
restored automatically unless the change is confirmed within 90 seconds.

Pure helpers operate on text/payloads so they can be tested without root.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from typing import Dict, List, Mapping, Optional, Sequence

from ..paths import NFTABLES_CONF, SSHD_CONFIG, UFW_DIR
from ..util import read_text, run, write_text
from .sshd import parse_sshd_config

MANAGED_BEGIN = "# >>> linustart firewall (managed) >>>"
MANAGED_END = "# <<< linustart firewall (managed) <<<"

ACTIONS = ("allow", "deny")
DIRECTIONS = ("in", "out")
PROTOCOLS = ("tcp", "udp", "any")
POLICIES = ("allow", "deny")

PORT_SPEC_RE = re.compile(r"^\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*$")
# The panel speaks allow/deny; nftables chains speak accept/drop.
NFT_POLICY = {"allow": "accept", "deny": "drop"}
PANEL_POLICY = {"accept": "allow", "drop": "deny"}
UFW_PORT_RE = re.compile(r"^(?P<port>[\d,:]+)/(?P<proto>[a-z0-9]+)$", re.IGNORECASE)
NFT_RULE_RE = re.compile(
    r"^(?:(?P<side>saddr|daddr)\s+(?P<address>\S+)\s+)?"
    r"(?:(?P<proto>tcp|udp)\s+dport\s+(?P<port>\S+)\s+)?"
    r"(?P<verdict>accept|drop)$"
)


# --------------------------------------------------------------------------
# Rule model: {action, direction, protocol, port, address}
# --------------------------------------------------------------------------

def valid_address(value: str) -> bool:
    if value == "any":
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def normalize_rule(raw: Mapping[str, object]) -> Dict[str, str]:
    """Validate a rule payload and return a normalized copy.

    Raises ``ValueError`` describing the first problem found.
    """
    action = str(raw.get("action", "")).strip().lower()
    if action not in ACTIONS:
        raise ValueError(f"action must be one of: {', '.join(ACTIONS)}")
    direction = str(raw.get("direction", "")).strip().lower()
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of: {', '.join(DIRECTIONS)}")
    protocol = str(raw.get("protocol", "any")).strip().lower() or "any"
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of: {', '.join(PROTOCOLS)}")
    port = str(raw.get("port", "")).strip().replace(" ", "")
    if port:
        if protocol == "any":
            raise ValueError("a port needs a concrete protocol (tcp or udp)")
        if not PORT_SPEC_RE.match(port):
            raise ValueError("port must look like 22, 80,443 or 8000:8100")
    address = str(raw.get("address", "any")).strip() or "any"
    if not valid_address(address):
        raise ValueError(f"not a valid address or network: {address}")
    return {
        "action": action,
        "direction": direction,
        "protocol": protocol,
        "port": port,
        "address": address,
    }


def rule_label(rule: Mapping[str, str]) -> str:
    target = f"{rule['protocol']}/{rule['port']}" if rule["port"] else rule["protocol"]
    side = "from" if rule["direction"] == "in" else "to"
    where = f" {side} {rule['address']}" if rule["address"] != "any" else ""
    return f"{rule['action']} {rule['direction']} {target}{where}"


def _spec_contains(spec: str, port: str) -> bool:
    for token in spec.split(","):
        token = token.strip()
        if ":" in token:
            low, _, high = token.partition(":")
            if low.isdigit() and high.isdigit() and int(low) <= int(port) <= int(high):
                return True
        elif token == port:
            return True
    return False


def rule_covers_port(rule: Mapping[str, object], port: str) -> bool:
    """Does *rule* (structured or parsed ufw row) keep *port* reachable?"""
    if str(rule.get("action", "")).lower() != "allow":
        return False
    if str(rule.get("direction", "in")).lower() != "in":
        return False
    if "to" in rule:  # ufw row shape: {to, action, direction, from}
        to = str(rule.get("to", ""))
        if to in ("Anywhere", "any", ""):
            return True
        match = UFW_PORT_RE.match(to)
        if not match:
            return False
        if match.group("proto").lower() not in ("tcp", "any"):
            return False
        return _spec_contains(match.group("port"), port)
    # structured rule shape: {action, direction, protocol, port, address}
    if str(rule.get("protocol", "any")).lower() not in ("tcp", "any"):
        return False
    spec = str(rule.get("port", ""))
    return True if not spec else _spec_contains(spec, port)


# --------------------------------------------------------------------------
# ufw parsing and command building
# --------------------------------------------------------------------------

def parse_ufw_status(text: str) -> Dict[str, object]:
    """Parse ``ufw status verbose`` into structured state.

    v4/v6 duplicates of the same dual-stack rule are collapsed into one entry
    (``ipv6`` marks a rule that only exists for v6).
    """
    lines = text.splitlines()
    enabled = bool(lines) and lines[0].strip().lower() == "status: active"
    default_incoming = "deny"
    default_outgoing = "allow"
    rules: List[Dict[str, object]] = []
    seen: Dict[tuple, Dict[str, object]] = {}
    in_table = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Default:"):
            for policy, scope in re.findall(r"(\w+) \((\w+)\)", stripped):
                if scope == "incoming":
                    default_incoming = policy.lower()
                elif scope == "outgoing":
                    default_outgoing = policy.lower()
            continue
        if stripped.startswith("To") and "Action" in stripped and "From" in stripped:
            in_table = True
            continue
        if not in_table or not stripped or set(stripped) <= {"-", " "}:
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 3:
            continue
        to, action_cell, from_cell = parts[0], parts[1], parts[2]
        cells = action_cell.split()
        if len(cells) != 2:
            continue
        action, direction = cells[0].lower(), cells[1].lower()
        ipv6 = "(v6)" in to or "(v6)" in from_cell
        to = to.replace("(v6)", "").strip()
        from_cell = from_cell.replace("(v6)", "").strip()
        key = (to, action, direction, from_cell)
        if key in seen:
            seen[key]["ipv6"] = False if not ipv6 else seen[key]["ipv6"]
            continue
        entry: Dict[str, object] = {
            "to": to,
            "action": action,
            "direction": direction,
            "from": from_cell,
            "ipv6": ipv6,
        }
        seen[key] = entry
        rules.append(entry)
    return {
        "enabled": enabled,
        "default_incoming": default_incoming,
        "default_outgoing": default_outgoing,
        "rules": rules,
    }


def ufw_add_argv(rule: Mapping[str, object]) -> List[str]:
    """Build the ``ufw`` command that adds *rule* (always dual-stack)."""
    r = normalize_rule(rule)
    argv = ["ufw", r["action"]]
    if r["direction"] == "out":
        argv.append("out")
    if r["protocol"] != "any":
        argv += ["proto", r["protocol"]]
    if r["direction"] == "in":
        if r["address"] != "any":
            argv += ["from", r["address"]]
        if r["port"]:
            argv += ["to", "any", "port", r["port"]]
    else:
        destination = r["address"] if r["address"] != "any" else "any"
        if r["port"]:
            argv += ["to", destination, "port", r["port"]]
        elif r["address"] != "any":
            argv += ["to", destination]
    argv += ["comment", "linustart"]
    return argv


def ufw_delete_argv(row: Mapping[str, object]) -> List[str]:
    """Build the ``ufw`` command that deletes a row produced by the parser."""
    action = str(row.get("action", "")).strip().lower()
    direction = str(row.get("direction", "in")).strip().lower()
    to = str(row.get("to", "")).strip()
    from_cell = str(row.get("from", "")).strip() or "Anywhere"
    argv = ["ufw", "delete", action]
    if direction == "out":
        argv.append("out")
    port = proto = None
    destination = None
    tokens = to.split()
    spec = ""
    if len(tokens) == 2 and UFW_PORT_RE.match(tokens[1]):
        destination, spec = tokens[0], tokens[1]  # "10.0.0.5 22/tcp"
    elif len(tokens) == 1 and UFW_PORT_RE.match(tokens[0]):
        spec = tokens[0]
    elif to and to != "Anywhere":
        destination = to
    if spec:
        match = UFW_PORT_RE.match(spec)
        port, proto = match.group("port"), match.group("proto").lower()  # type: ignore[union-attr]
    if proto:
        argv += ["proto", proto]
    if from_cell != "Anywhere":
        argv += ["from", from_cell]
    if destination:
        argv += ["to", destination]
    if port:
        if not destination:
            argv += ["to", "any"]
        argv += ["port", port]
    return argv


# --------------------------------------------------------------------------
# nftables managed block
# --------------------------------------------------------------------------

def nft_rule_line(rule: Mapping[str, str]) -> str:
    """Canonical ``nft`` line for a rule inside the managed input/output chain."""
    parts: List[str] = []
    if rule["address"] != "any":
        side = "saddr" if rule["direction"] == "in" else "daddr"
        parts += [side, rule["address"]]
    if rule["port"]:
        parts += [rule["protocol"], "dport", rule["port"]]
    parts.append("drop" if rule["action"] == "deny" else "accept")
    return " ".join(parts)


def nft_line_to_rule(line: str, direction: str) -> Optional[Dict[str, str]]:
    """Inverse of :func:`nft_rule_line`; returns None for foreign lines."""
    match = NFT_RULE_RE.match(line.strip())
    if not match:
        return None
    side = match.group("side")
    expected = "saddr" if direction == "in" else "daddr"
    if side and side != expected:
        return None
    return {
        "action": "deny" if match.group("verdict") == "drop" else "allow",
        "direction": direction,
        "protocol": match.group("proto") or "any",
        "port": match.group("port") or "",
        "address": match.group("address") or "any",
    }


def _managed_block(default_incoming: str, default_outgoing: str, rules: Sequence[Mapping[str, str]]) -> str:
    incoming = [r for r in rules if r["direction"] == "in"]
    outgoing = [r for r in rules if r["direction"] == "out"]
    in_lines = "\n".join(f"\t\t{r}" for r in (nft_rule_line(x) for x in incoming))
    out_lines = "\n".join(f"\t\t{r}" for r in (nft_rule_line(x) for x in outgoing))
    block = [
        MANAGED_BEGIN,
        "# Managed by LinuStart - do not edit between these markers.",
        "table inet linustart {",
        "\tchain input {",
        f"\t\ttype filter hook input priority 0; policy {NFT_POLICY.get(default_incoming, default_incoming)};",
        "\t\tct state established,related accept",
        '\t\tiif "lo" accept',
        (in_lines + "\n") if in_lines else "",
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority 0; policy drop;",
        "\t}",
        "\tchain output {",
        f"\t\ttype filter hook output priority 0; policy {NFT_POLICY.get(default_outgoing, default_outgoing)};",
        (out_lines + "\n") if out_lines else "",
        "\t}",
        "}",
        MANAGED_END,
    ]
    return "\n".join(line for line in block if line != "") + "\n"


def build_nftables_conf(
    text: str,
    default_incoming: str = "deny",
    default_outgoing: str = "allow",
    rules: Sequence[Mapping[str, str]] = (),
    enabled: bool = True,
) -> str:
    """Return *text* with the managed block replaced (or removed when disabled)."""
    begin = text.find(MANAGED_BEGIN)
    end = text.find(MANAGED_END)
    if begin != -1 and end != -1:
        head = text[:begin]
        tail = text[end + len(MANAGED_END):].lstrip("\n")
    else:
        head = text
        tail = ""
        if head and not head.endswith("\n"):
            head += "\n"
    if not enabled:
        return head + tail
    block = _managed_block(default_incoming, default_outgoing, rules)
    if tail:
        return head + block + "\n" + tail
    return head + block


def parse_nftables_managed(text: str) -> Dict[str, object]:
    """Read the panel's state back out of the managed block (import-first)."""
    state: Dict[str, object] = {
        "enabled": False,
        "default_incoming": "deny",
        "default_outgoing": "allow",
        "rules": [],
    }
    begin = text.find(MANAGED_BEGIN)
    end = text.find(MANAGED_END)
    if begin == -1 or end == -1 or end < begin:
        return state
    state["enabled"] = True
    chain: Optional[str] = None
    for line in text[begin:end].splitlines():
        stripped = line.strip()
        chain_match = re.match(r"^chain\s+(\w+)\s*\{", stripped)
        if chain_match:
            chain = chain_match.group(1)
            continue
        if stripped == "}":
            chain = None
            continue
        policy = re.search(r"policy\s+(\w+)\s*;", stripped)
        if policy and chain in ("input", "output"):
            key = "default_incoming" if chain == "input" else "default_outgoing"
            state[key] = PANEL_POLICY.get(policy.group(1), policy.group(1))
            continue
        if chain in ("input", "output"):
            rule = nft_line_to_rule(stripped, "in" if chain == "input" else "out")
            if rule:
                state["rules"].append(rule)  # type: ignore[union-attr]
    return state


# --------------------------------------------------------------------------
# Async backend operations
# --------------------------------------------------------------------------

async def detect_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("nft"):
        return "nftables"
    raise RuntimeError("no supported firewall backend found (install 'ufw' or 'nftables')")


def ssh_port() -> str:
    """The port sshd currently listens on - kept open when enabling a lockdown."""
    return parse_sshd_config(read_text(SSHD_CONFIG)).get("Port", "22")


def managed_config_files(backend: str) -> List:
    if backend == "ufw":
        return [
            UFW_DIR / "user.rules",
            UFW_DIR / "user6.rules",
            UFW_DIR / "before.rules",
            UFW_DIR / "after.rules",
            UFW_DIR / "ufw.conf",
        ]
    return [NFTABLES_CONF]


async def status() -> Dict[str, object]:
    backend = await detect_backend()
    if backend == "ufw":
        result = await run(["ufw", "status", "verbose"])
        data = parse_ufw_status(result.stdout)
        data["installed"] = True
    else:
        data = parse_nftables_managed(read_text(NFTABLES_CONF))
        probe = await run(["nft", "list", "table", "inet", "linustart"])
        data["enabled"] = data["enabled"] and probe.ok
        data["installed"] = shutil.which("nft") is not None
    data["backend"] = backend
    data["ssh_port"] = ssh_port()
    return data


async def ufw_apply(argv: Sequence[str]) -> None:
    result = await run(list(argv))
    if not result.ok:
        raise RuntimeError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout).strip()}")


async def nftables_apply(
    *,
    enabled: bool,
    default_incoming: str = "deny",
    default_outgoing: str = "allow",
    rules: Sequence[Mapping[str, str]] = (),
) -> None:
    """Regenerate the managed block from state, validate, persist and load it."""
    candidate = build_nftables_conf(
        read_text(NFTABLES_CONF), default_incoming, default_outgoing, rules, enabled
    )
    if enabled:
        check = await run(["nft", "-c", "-f", "-"], input_text=candidate)
        if not check.ok:
            raise ValueError(f"nftables rejected the ruleset: {(check.stderr or check.stdout).strip()}")
    write_text(NFTABLES_CONF, candidate)
    if enabled:
        applied = await run(["nft", "-f", "-"], input_text=candidate)
        if not applied.ok:
            raise RuntimeError(f"loading the nftables ruleset failed: {(applied.stderr or applied.stdout).strip()}")
    else:
        await run(["nft", "delete", "table", "inet", "linustart"])


async def reapply(backend: str) -> None:
    """Re-apply the on-disk configuration (used when reverting a change)."""
    if backend == "ufw":
        result = await run(["ufw", "--force", "reload"])
        if not result.ok:
            raise RuntimeError(f"ufw reload failed: {(result.stderr or result.stdout).strip()}")
    else:
        text = read_text(NFTABLES_CONF)
        if MANAGED_BEGIN in text:
            result = await run(["nft", "-f", "-"], input_text=text)
            if not result.ok:
                raise RuntimeError(f"nftables reload failed: {(result.stderr or result.stdout).strip()}")
        else:
            await run(["nft", "delete", "table", "inet", "linustart"])
