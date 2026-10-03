"""Tests for the firewall rule model, ufw parsing and the nftables block."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.firewall import (  # noqa: E402
    build_nftables_conf,
    nft_rule_line,
    normalize_rule,
    parse_nftables_managed,
    parse_ufw_status,
    rule_covers_port,
    rule_label,
    ufw_add_argv,
    ufw_delete_argv,
)

UFW_STATUS = """Status: active

Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
25/tcp                     DENY OUT    Anywhere
10.0.0.5 22/tcp            ALLOW IN    192.168.1.0/24
"""

RULES = [
    {"action": "allow", "direction": "in", "protocol": "tcp", "port": "22", "address": "any"},
    {"action": "deny", "direction": "in", "protocol": "udp", "port": "53", "address": "10.0.0.0/8"},
    {"action": "deny", "direction": "out", "protocol": "tcp", "port": "25", "address": "any"},
]


def test_normalize_rule_accepts_shapes():
    rule = normalize_rule({"action": "ALLOW", "direction": "In", "protocol": "TCP", "port": "22", "address": "10.0.0.0/8"})
    assert rule == {"action": "allow", "direction": "in", "protocol": "tcp", "port": "22", "address": "10.0.0.0/8"}
    bare = normalize_rule({"action": "deny", "direction": "out"})
    assert bare["protocol"] == "any" and bare["address"] == "any"


def test_normalize_rule_rejects_bad_input():
    for bad in [
        {"action": "block", "direction": "in"},
        {"action": "allow", "direction": "sideways"},
        {"action": "allow", "direction": "in", "protocol": "any", "port": "22"},  # port needs proto
        {"action": "allow", "direction": "in", "protocol": "tcp", "port": "http"},
        {"action": "allow", "direction": "in", "protocol": "tcp", "address": "not-an-ip"},
    ]:
        try:
            normalize_rule(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


def test_rule_label():
    label = rule_label(RULES[1])
    assert label == "deny in udp/53 from 10.0.0.0/8"


def test_parse_ufw_status():
    state = parse_ufw_status(UFW_STATUS)
    assert state["enabled"] is True
    assert state["default_incoming"] == "deny"
    assert state["default_outgoing"] == "allow"
    # the v6 twin of 22/tcp is collapsed into the v4 row
    assert len(state["rules"]) == 4
    assert state["rules"][0] == {
        "to": "22/tcp", "action": "allow", "direction": "in", "from": "Anywhere", "ipv6": False,
    }
    assert state["rules"][3]["from"] == "192.168.1.0/24"


def test_parse_ufw_status_inactive():
    state = parse_ufw_status("Status: inactive\n")
    assert state["enabled"] is False
    assert state["rules"] == []


def test_ufw_add_argv():
    argv = ufw_add_argv({"action": "allow", "direction": "in", "protocol": "tcp", "port": "22", "address": "any"})
    assert argv == ["ufw", "allow", "proto", "tcp", "to", "any", "port", "22", "comment", "linustart"]
    argv = ufw_add_argv({"action": "deny", "direction": "out", "protocol": "tcp", "port": "25", "address": "any"})
    assert argv == ["ufw", "deny", "out", "proto", "tcp", "to", "any", "port", "25", "comment", "linustart"]
    argv = ufw_add_argv({"action": "allow", "direction": "in", "protocol": "any", "port": "", "address": "10.0.0.0/8"})
    assert argv == ["ufw", "allow", "from", "10.0.0.0/8", "comment", "linustart"]


def test_ufw_delete_argv():
    row = {"to": "22/tcp", "action": "allow", "direction": "in", "from": "Anywhere"}
    assert ufw_delete_argv(row) == ["ufw", "delete", "allow", "proto", "tcp", "to", "any", "port", "22"]
    row = {"to": "25/tcp", "action": "deny", "direction": "out", "from": "Anywhere"}
    assert ufw_delete_argv(row) == ["ufw", "delete", "deny", "out", "proto", "tcp", "to", "any", "port", "25"]
    row = {"to": "10.0.0.5 22/tcp", "action": "allow", "direction": "in", "from": "192.168.1.0/24"}
    argv = ufw_delete_argv(row)
    assert argv == ["ufw", "delete", "allow", "proto", "tcp", "from", "192.168.1.0/24", "to", "10.0.0.5", "port", "22"]


def test_nftables_round_trip():
    text = build_nftables_conf("#!/usr/sbin/nft -f\nflush ruleset\n", "deny", "allow", RULES)
    assert "flush ruleset" in text  # user content preserved
    assert "policy drop;" in text and "policy accept;" in text  # nft vocabulary
    state = parse_nftables_managed(text)
    assert state["enabled"] is True
    assert state["default_incoming"] == "deny"
    assert state["default_outgoing"] == "allow"
    assert state["rules"] == RULES  # exact round trip


def test_nftables_block_replaced_not_duplicated():
    once = build_nftables_conf("", "deny", "allow", RULES)
    twice = build_nftables_conf(once, "deny", "allow", RULES)
    assert once == twice


def test_nftables_disabled_removes_block():
    text = build_nftables_conf("#!/usr/sbin/nft -f\n", "deny", "allow", RULES, enabled=False)
    assert "linustart" not in text
    assert parse_nftables_managed(text)["enabled"] is False


def test_nftables_imports_foreign_file():
    state = parse_nftables_managed("flush ruleset\ntable inet firewall { }\n")
    assert state == {
        "enabled": False, "default_incoming": "deny", "default_outgoing": "allow", "rules": [],
    }


def test_nft_rule_line_shapes():
    assert nft_rule_line(RULES[0]) == "tcp dport 22 accept"
    assert nft_rule_line(RULES[1]) == "saddr 10.0.0.0/8 udp dport 53 drop"


def test_rule_covers_port():
    assert rule_covers_port(RULES[0], "22")
    assert not rule_covers_port(RULES[1], "22")  # udp
    assert not rule_covers_port(RULES[2], "22")
    assert rule_covers_port({"action": "allow", "direction": "in", "protocol": "any", "port": ""}, "22")
    assert rule_covers_port({"to": "22/tcp", "action": "allow", "direction": "in", "from": "Anywhere"}, "22")
    assert rule_covers_port({"to": "Anywhere", "action": "allow", "direction": "in", "from": "Anywhere"}, "22")
    assert rule_covers_port({"to": "8000:9000/tcp", "action": "allow", "direction": "in", "from": "Anywhere"}, "8080")
    assert not rule_covers_port({"to": "80,443/tcp", "action": "allow", "direction": "in", "from": "Anywhere"}, "22")
    assert not rule_covers_port({"to": "22/udp", "action": "allow", "direction": "in", "from": "Anywhere"}, "22")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all firewall tests passed")
