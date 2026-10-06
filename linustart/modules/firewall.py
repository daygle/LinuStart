"""Firewall management for UFW, nftables and firewalld.

The panel supports three backends and detects which one is in use:

* ``ufw``      - rules are managed through the ``ufw`` CLI, state parsed from
  ``ufw status verbose``. Snapshots of ``/etc/ufw`` back every change.
* ``nftables`` - a clearly marked managed block inside ``/etc/nftables.conf``
  holds the panel's table (``inet linustart``); the rest of the file is left
  untouched. Every apply is validated with ``nft -c`` first.
* ``firewalld`` - the default zone's permanent configuration, changed with
  ``firewall-cmd --permanent`` (``firewall-offline-cmd`` while the daemon is
  stopped) and then reloaded; ``/etc/firewalld/zones`` backs every change.
  Zones filter incoming traffic only, so outgoing rules are refused.

A firewall change can lock you out of a server just like a network change, so
routes.py wraps every apply in a confirm-or-revert session: the old state is
restored automatically unless the change is confirmed within 90 seconds.

Pure helpers operate on text/payloads so they can be tested without root.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from ..paths import FIREWALLD_DIR, NFTABLES_CONF, UFW_DIR
from ..util import read_text, run, write_text

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
# Lines written by nft_rule_line. The family prefix is optional when reading
# so blocks written by older panel versions still import.
NFT_RULE_RE = re.compile(
    r"^(?:(?:ip6?\s+)?(?P<side>saddr|daddr)\s+(?P<address>\S+)\s+)?"
    r"(?:(?P<proto>tcp|udp)\s+dport\s+(?P<port>\{[^}]*\}|\S+)\s+"
    r"|meta\s+l4proto\s+(?P<l4proto>tcp|udp)\s+)?"
    r"(?P<verdict>accept|drop)$"
)
NFT_TABLE = "inet linustart"


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

def nft_port_spec(spec: str) -> str:
    """Panel port syntax -> nft: '8000:8100' -> '8000-8100', '80,443' -> '{ 80, 443 }'."""
    tokens = [token.strip().replace(":", "-") for token in spec.split(",") if token.strip()]
    return tokens[0] if len(tokens) == 1 else "{ " + ", ".join(tokens) + " }"


def panel_port_spec(spec: str) -> str:
    """Inverse of :func:`nft_port_spec`."""
    tokens = [token.strip().replace("-", ":") for token in spec.strip("{} ").split(",")]
    return ",".join(token for token in tokens if token)


def nft_rule_line(rule: Mapping[str, str]) -> str:
    """Canonical ``nft`` line for a rule inside the managed input/output chain.

    Address matches need their family (``ip saddr`` / ``ip6 saddr``) in an
    inet table, and a protocol without a port still has to match the
    protocol - dropping it would turn "allow tcp" into "allow everything".
    """
    parts: List[str] = []
    if rule["address"] != "any":
        side = "saddr" if rule["direction"] == "in" else "daddr"
        family = "ip6" if ":" in rule["address"] else "ip"
        parts += [family, side, rule["address"]]
    if rule["port"]:
        parts += [rule["protocol"], "dport", nft_port_spec(rule["port"])]
    elif rule["protocol"] != "any":
        parts += ["meta", "l4proto", rule["protocol"]]
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
        "protocol": match.group("proto") or match.group("l4proto") or "any",
        "port": panel_port_spec(match.group("port")) if match.group("port") else "",
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
        in_lines,
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority 0; policy drop;",
        "\t}",
        "\tchain output {",
        f"\t\ttype filter hook output priority 0; policy {NFT_POLICY.get(default_outgoing, default_outgoing)};",
        out_lines,
        "\t}",
        "}",
        MANAGED_END,
    ]
    return "\n".join(line for line in block if line != "") + "\n"


def managed_block_text(text: str) -> str:
    """Just the managed block of an nftables.conf ('' when there is none)."""
    begin = text.find(MANAGED_BEGIN)
    end = text.find(MANAGED_END)
    if begin == -1 or end == -1 or end < begin:
        return ""
    return text[begin:end + len(MANAGED_END)] + "\n"


def nft_load_script(block: str) -> str:
    """An nft script that replaces the panel's table in one transaction.

    Loading ``table inet linustart { ... }`` on top of an existing table adds
    to it - every apply would duplicate the rules, and a removed rule would
    stay loaded. Declaring the table (a no-op when it exists), deleting it and
    redefining it in one ``nft -f`` run swaps it atomically. Only the managed
    block is loaded: re-running the whole file would also re-run whatever
    else it holds (``flush ruleset`` wipes Docker's and fail2ban's rules).
    """
    return f"table {NFT_TABLE}\ndelete table {NFT_TABLE}\n{block}"


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
# firewalld: pure helpers
# --------------------------------------------------------------------------

FIREWALLD_PORT_RE = re.compile(r"^(?P<low>\d{1,5})(?:-(?P<high>\d{1,5}))?/(?P<proto>tcp|udp|sctp|dccp)$")
RICH_RE = re.compile(
    r'^rule(?:\s+family="(?P<family>ipv4|ipv6)")?'
    r'(?:\s+source\s+address="(?P<address>[^"]+)")?'
    r'(?:\s+port\s+port="(?P<port>\d{1,5}(?:-\d{1,5})?)"\s+protocol="(?P<proto>tcp|udp)"'
    r'|\s+protocol\s+value="(?P<l4>tcp|udp)")?'
    r'\s+(?P<verdict>accept|drop|reject)$'
)
# zone target -> panel policy; "default" rejects what no rule allows
FIREWALLD_TARGET_POLICY = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny", "%%REJECT%%": "deny", "default": "deny"}
FIREWALLD_POLICY_TARGET = {"allow": "ACCEPT", "deny": "DROP"}


def parse_firewalld_ports(text: str, *, source: str = "port", name: str = "") -> List[Dict[str, str]]:
    """``22/tcp 8000-8100/udp`` -> allow-in rules in the panel's shape."""
    rules: List[Dict[str, str]] = []
    for token in (text or "").split():
        match = FIREWALLD_PORT_RE.match(token)
        if not match or match.group("proto") not in ("tcp", "udp"):
            continue
        port = match.group("low") + (f":{match.group('high')}" if match.group("high") else "")
        rules.append({
            "action": "allow", "direction": "in", "protocol": match.group("proto"),
            "port": port, "address": "any", "source": source, "name": name or token,
        })
    return rules


def parse_rich_rule(line: str) -> Dict[str, str]:
    """A rich rule in the panel's shape; rules it cannot express stay raw."""
    raw = (line or "").strip()
    match = RICH_RE.match(raw)
    if not match:
        return {"action": "custom", "direction": "in", "protocol": "any", "port": "",
                "address": "any", "source": "rich", "raw": raw}
    port = (match.group("port") or "").replace("-", ":")
    return {
        "action": "allow" if match.group("verdict") == "accept" else "deny",
        "direction": "in",
        "protocol": match.group("proto") or match.group("l4") or "any",
        "port": port,
        "address": match.group("address") or "any",
        "source": "rich",
        "raw": raw,
    }


def rich_rules_for(rule: Mapping[str, str]) -> List[str]:
    """Rich rules expressing a normalized panel rule (one per port token)."""
    if rule["direction"] != "in":
        raise ValueError("firewalld zones filter incoming traffic only; outgoing rules are not supported")
    verdict = "accept" if rule["action"] == "allow" else "drop"
    head = "rule"
    if rule["address"] != "any":
        family = "ipv6" if ":" in rule["address"] else "ipv4"
        head += f' family="{family}" source address="{rule["address"]}"'
    if rule["port"]:
        return [
            f'{head} port port="{token.replace(":", "-")}" protocol="{rule["protocol"]}" {verdict}'
            for token in rule["port"].split(",")
        ]
    if rule["protocol"] != "any":
        return [f'{head} protocol value="{rule["protocol"]}" {verdict}']
    if rule["address"] == "any":
        raise ValueError("a rule matching all traffic is the default policy; change that instead")
    return [f"{head} {verdict}"]


def firewalld_add_args(rule: Mapping[str, str]) -> List[str]:
    """firewall-cmd arguments adding a normalized rule.

    A plain "allow this port from anywhere" becomes ``--add-port`` (how
    firewalld users write it); everything else is a rich rule.
    """
    if rule["direction"] == "in" and rule["action"] == "allow" and rule["address"] == "any" and rule["port"]:
        return [f"--add-port={token.replace(':', '-')}/{rule['protocol']}" for token in rule["port"].split(",")]
    return [f"--add-rich-rule={line}" for line in rich_rules_for(rule)]


def firewalld_remove_args(row: Mapping[str, str]) -> List[str]:
    source = row.get("source")
    if source == "service":
        return [f"--remove-service={row['name']}"]
    if source == "port":
        return [f"--remove-port={row['name']}"]
    if source == "rich" and row.get("raw"):
        return [f"--remove-rich-rule={row['raw']}"]
    raise ValueError("this firewalld entry cannot be removed from the panel")


def firewalld_default_zone(conf_text: str) -> str:
    for line in conf_text.splitlines():
        key, _, value = line.strip().partition("=")
        if key.strip() == "DefaultZone" and value.strip():
            return value.strip()
    return "public"


# --------------------------------------------------------------------------
# Async backend operations
# --------------------------------------------------------------------------

async def firewalld_running() -> bool:
    if not shutil.which("firewall-cmd"):
        return False
    result = await run(["firewall-cmd", "--state"])
    return result.ok and result.stdout.strip() == "running"


async def detect_backend() -> str:
    # A running firewalld owns the ruleset; managing ufw or nft next to it
    # would fight it, so it wins even when the others are installed.
    if await firewalld_running():
        return "firewalld"
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("nft"):
        return "nftables"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    raise RuntimeError("no supported firewall backend found (install 'ufw', 'nftables' or 'firewalld')")


# --------------------------------------------------------------------------
# Living next to other firewalls
# --------------------------------------------------------------------------

async def _systemctl_ok(*args: str) -> bool:
    try:
        return (await run(["systemctl", *args])).ok
    except RuntimeError:
        return False


def firewall_findings(
    backend: str,
    panel_enabled: bool,
    *,
    nft_service_enabled: bool,
    firewalld_enabled: bool,
    firewalld_running: bool,
    ufw_active: bool,
    docker: bool,
) -> List[Dict[str, object]]:
    """Problems with the firewall setup as a whole (pure, see :func:`findings`)."""
    from .nethealth import finding

    found: List[Dict[str, object]] = []
    if backend == "nftables" and panel_enabled and not nft_service_enabled:
        found.append(finding(
            "nftables-persist", "warn", "The firewall is not loaded at boot",
            "nftables.service is disabled, so the rules in /etc/nftables.conf are lost when the machine "
            "restarts and the server comes back with no firewall. Enabling the service loads them at boot "
            "(it is not started now, so nothing changes until the next boot).",
            {"label": "Load the firewall at boot", "confirm": "Enable nftables.service so the rules load at boot?"},
            endpoint="/firewall/fix",
        ))
    if backend in ("ufw", "firewalld") and nft_service_enabled:
        found.append(finding(
            "nftables-service", "warn", "nftables.service also loads rules at boot",
            f"The panel manages the firewall through {backend}, but nftables.service is enabled and loads "
            "/etc/nftables.conf at boot as well - two rule sets that can contradict each other, and that "
            "file usually starts with 'flush ruleset'. Disabling the service stops that at the next boot; "
            "it is not stopped now (stopping it would flush the live rules).",
            {"label": "Disable nftables.service", "confirm": "Disable nftables.service (it is not stopped now)?"},
            endpoint="/firewall/fix",
        ))
    if backend != "firewalld" and firewalld_enabled and not firewalld_running:
        found.append(finding(
            "firewalld-enabled", "warn", "firewalld will take over at the next boot",
            f"firewalld is stopped but enabled: when the machine restarts it starts and owns the firewall, "
            f"replacing the {backend} rules managed here.",
            {"label": "Disable firewalld", "confirm": "Disable firewalld so it does not start at boot?"},
            endpoint="/firewall/fix",
        ))
    if backend == "firewalld" and ufw_active:
        found.append(finding(
            "ufw-active", "warn", "ufw is active next to firewalld",
            "Both ufw and firewalld are loading rules; they fight over the same tables. firewalld is the one "
            "managed here, so ufw should be turned off.",
            {"label": "Turn ufw off", "confirm": "Run 'ufw disable'? firewalld keeps filtering."},
            endpoint="/firewall/fix",
        ))
    if docker:
        found.append(finding(
            "docker", "info", "Docker publishes ports around this firewall",
            "Docker inserts its own rules for published container ports ahead of ufw and nftables input "
            "rules, so rules here neither open nor block those ports. Control them where the containers "
            "are published (or in Docker's DOCKER-USER chain).",
        ))
    return found


async def findings(backend: str, panel_enabled: bool) -> List[Dict[str, object]]:
    ufw_active = False
    if backend == "firewalld" and shutil.which("ufw"):
        try:
            ufw_active = bool(parse_ufw_status((await run(["ufw", "status"])).stdout).get("enabled"))
        except RuntimeError:
            ufw_active = False
    return firewall_findings(
        backend, panel_enabled,
        nft_service_enabled=await _systemctl_ok("is-enabled", "--quiet", "nftables"),
        firewalld_enabled=await _systemctl_ok("is-enabled", "--quiet", "firewalld"),
        firewalld_running=await firewalld_running(),
        ufw_active=ufw_active,
        docker=shutil.which("docker") is not None or await _systemctl_ok("is-active", "--quiet", "docker"),
    )


FIX_COMMANDS = {
    "nftables-persist": ["systemctl", "enable", "nftables"],
    "nftables-service": ["systemctl", "disable", "nftables"],
    "firewalld-enabled": ["systemctl", "disable", "firewalld"],
    "ufw-active": ["ufw", "disable"],
}


async def apply_fix(fid: str) -> str:
    argv = FIX_COMMANDS[fid]
    result = await run(argv)
    if not result.ok:
        raise RuntimeError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout).strip()}")
    return " ".join(argv)


def ssh_port() -> str:
    """The port sshd currently listens on - kept open when enabling a lockdown."""
    from .sshd import effective

    return effective().get("Port", ("22", ""))[0]


def firewalld_zone_file() -> Path:
    zone = firewalld_default_zone(read_text(FIREWALLD_DIR / "firewalld.conf"))
    return FIREWALLD_DIR / "zones" / f"{zone}.xml"


def managed_config_files(backend: str) -> List:
    if backend == "firewalld":
        # The default zone's file is listed even when it does not exist yet:
        # the first permanent change creates it, and reverting must remove it
        # again so the shipped defaults apply.
        zones = FIREWALLD_DIR / "zones"
        files = sorted(zones.glob("*.xml")) if zones.is_dir() else []
        target = firewalld_zone_file()
        return files if target in files else files + [target]
    if backend == "ufw":
        return [
            UFW_DIR / "user.rules",
            UFW_DIR / "user6.rules",
            UFW_DIR / "before.rules",
            UFW_DIR / "after.rules",
            UFW_DIR / "ufw.conf",
        ]
    return [NFTABLES_CONF]


async def firewalld_cmd() -> List[str]:
    """firewall-cmd talks to the daemon; firewall-offline-cmd edits the
    permanent configuration while it is stopped."""
    if await firewalld_running():
        return ["firewall-cmd", "--permanent"]
    if shutil.which("firewall-offline-cmd"):
        return ["firewall-offline-cmd"]
    raise RuntimeError("firewalld is stopped and firewall-offline-cmd is not available")


async def firewalld_status() -> Dict[str, object]:
    running = await firewalld_running()
    base = await firewalld_cmd()
    zone_result = await run(base + ["--get-default-zone"])
    zone = zone_result.stdout.strip() or "public"
    scoped = base + [f"--zone={zone}"]
    target, services, ports, rich = await asyncio.gather(
        run(scoped + ["--get-target"]),
        run(scoped + ["--list-services"]),
        run(scoped + ["--list-ports"]),
        run(scoped + ["--list-rich-rules"]),
    )
    service_names = services.stdout.split()
    service_ports = await asyncio.gather(
        *(run(base + [f"--service={name}", "--get-ports"]) for name in service_names)
    )
    rules: List[Dict[str, object]] = []
    for name, result in zip(service_names, service_ports):
        expanded = parse_firewalld_ports(result.stdout, source="service", name=name)
        if expanded:
            rules.extend({**rule, "label": f"service {name}"} for rule in expanded)
        else:  # a service without plain ports (helpers, protocols): show it anyway
            rules.append({"action": "allow", "direction": "in", "protocol": "any", "port": "",
                          "address": "any", "source": "service", "name": name, "label": f"service {name}"})
    rules.extend(parse_firewalld_ports(ports.stdout))
    rules.extend(parse_rich_rule(line) for line in rich.stdout.splitlines() if line.strip())
    return {
        "enabled": running,
        "default_incoming": FIREWALLD_TARGET_POLICY.get(target.stdout.strip(), "deny"),
        "default_outgoing": "allow",
        "zone": zone,
        "rules": rules,
        "installed": True,
    }


async def firewalld_apply(args: Sequence[str]) -> List[str]:
    """Run permanent changes, then reload so they take effect."""
    base = await firewalld_cmd()
    ran: List[str] = []
    for arg in args:
        argv = base + [arg]
        result = await run(argv)
        ran.append(" ".join(argv))
        if not result.ok and "ALREADY_ENABLED" not in result.stderr and "NOT_ENABLED" not in result.stderr:
            raise RuntimeError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout).strip()}")
    if await firewalld_running():
        await _firewalld_reload()
        ran.append("firewall-cmd --reload")
    return ran


async def _firewalld_reload() -> None:
    result = await run(["firewall-cmd", "--reload"])
    if not result.ok:
        raise RuntimeError(f"firewall-cmd --reload failed: {(result.stderr or result.stdout).strip()}")


async def firewalld_set_running(enabled: bool) -> str:
    argv = ["systemctl", "enable" if enabled else "disable", "--now", "firewalld"]
    result = await run(argv)
    if not result.ok:
        raise RuntimeError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout).strip()}")
    return " ".join(argv)


async def status() -> Dict[str, object]:
    try:
        backend = await detect_backend()
    except RuntimeError as exc:
        # A fresh minimal install may have no firewall at all: say so, and
        # let the page offer one to install instead of failing.
        return {
            "backend": "", "installed": False, "enabled": False, "rules": [],
            "default_incoming": "deny", "default_outgoing": "allow", "ssh_port": ssh_port(),
            "findings": [{
                "id": "no-firewall", "severity": "warn", "title": "No firewall is installed",
                "detail": f"{exc}. Install ufw (simplest) from Software → System Components.",
                "fix": None,
            }],
        }
    if backend == "firewalld":
        data = await firewalld_status()
    elif backend == "ufw":
        result = await run(["ufw", "status", "verbose"])
        data = parse_ufw_status(result.stdout)
        data["installed"] = True
    else:
        data = parse_nftables_managed(read_text(NFTABLES_CONF))
        probe = await run(["nft", "list", "table", *NFT_TABLE.split()])
        data["enabled"] = data["enabled"] and probe.ok
        data["installed"] = shutil.which("nft") is not None
    data["backend"] = backend
    data["ssh_port"] = ssh_port()
    data["findings"] = await findings(backend, bool(data.get("enabled")))
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
    script = nft_load_script(managed_block_text(candidate)) if enabled else ""
    if enabled:
        check = await run(["nft", "-c", "-f", "-"], input_text=script)
        if not check.ok:
            raise ValueError(f"nftables rejected the ruleset: {(check.stderr or check.stdout).strip()}")
    write_text(NFTABLES_CONF, candidate)
    if enabled:
        applied = await run(["nft", "-f", "-"], input_text=script)
        if not applied.ok:
            raise RuntimeError(f"loading the nftables ruleset failed: {(applied.stderr or applied.stdout).strip()}")
        # Without the service the rules are gone after a reboot. Enabled
        # only, not started: starting it would re-run the whole file.
        if not await _systemctl_ok("is-enabled", "--quiet", "nftables"):
            await run(["systemctl", "enable", "nftables"])
    else:
        await run(["nft", "delete", "table", *NFT_TABLE.split()])


async def reapply(backend: str, running: Optional[str] = None) -> None:
    """Re-apply the on-disk configuration (used when reverting a change).

    For firewalld, *running* ("yes"/"no") restores whether the daemon was
    running before the change, since enabling or disabling it is a change
    too.
    """
    if backend == "firewalld":
        if running == "no":
            if await firewalld_running():
                await firewalld_set_running(False)
            return
        if running == "yes" and not await firewalld_running():
            await firewalld_set_running(True)
        if await firewalld_running():
            await _firewalld_reload()
        return
    if backend == "ufw":
        result = await run(["ufw", "--force", "reload"])
        if not result.ok:
            raise RuntimeError(f"ufw reload failed: {(result.stderr or result.stdout).strip()}")
    else:
        block = managed_block_text(read_text(NFTABLES_CONF))
        if block:
            result = await run(["nft", "-f", "-"], input_text=nft_load_script(block))
            if not result.ok:
                raise RuntimeError(f"nftables reload failed: {(result.stderr or result.stdout).strip()}")
        else:
            await run(["nft", "delete", "table", *NFT_TABLE.split()])
