"""Tests for /etc/network/interfaces parsing and editing."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.network import (  # noqa: E402
    join_cidr,
    read_ifupdown_interface,
    split_cidr,
    stanza_counts,
    update_ifupdown_interface,
)

BASE = """# Server interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
    dns-nameservers 1.1.1.1
"""


def test_cidr_round_trip():
    ip, netmask = split_cidr("10.0.0.5/24")
    assert ip == "10.0.0.5"
    assert netmask == "255.255.255.0"
    assert join_cidr(ip, netmask) == "10.0.0.5/24"
    ip6, mask6 = split_cidr("10.0.0.5/255.255.255.128")
    assert join_cidr(ip6, mask6) == "10.0.0.5/25"


def test_read_dhcp_interface():
    info = read_ifupdown_interface(BASE, "eth0")
    assert info is not None
    assert info["method"] == "dhcp"
    assert info["dns"] == ["1.1.1.1"]
    assert info["auto"] is True
    assert info["address"] is None


def test_write_static_then_read_back():
    updated = update_ifupdown_interface(
        BASE, "eth0", "static", "192.168.1.10/24", "192.168.1.1", ["8.8.8.8", "8.8.4.4"]
    )
    info = read_ifupdown_interface(updated, "eth0")
    assert info is not None
    assert info["method"] == "static"
    assert info["address"] == "192.168.1.10/24"
    assert info["gateway"] == "192.168.1.1"
    assert info["dns"] == ["8.8.8.8", "8.8.4.4"]
    # unrelated stanzas and comments survive
    assert "# Server interfaces" in updated
    assert "iface lo inet loopback" in updated
    assert "auto lo" in updated


def test_static_replaces_old_managed_options():
    text = update_ifupdown_interface(BASE, "eth0", "static", "10.0.0.2/24", "10.0.0.1", [])
    text = update_ifupdown_interface(text, "eth0", "static", "10.0.0.3/24", "10.0.0.254", ["1.1.1.1"])
    info = read_ifupdown_interface(text, "eth0")
    assert info["address"] == "10.0.0.3/24"
    assert info["gateway"] == "10.0.0.254"
    assert info["dns"] == ["1.1.1.1"]
    assert text.count("address ") == 1
    assert text.count("gateway ") == 1


def test_switch_back_to_dhcp_removes_static_options():
    text = update_ifupdown_interface(BASE, "eth0", "static", "10.0.0.2/24", "10.0.0.1", ["1.1.1.1"])
    text = update_ifupdown_interface(text, "eth0", "dhcp")
    info = read_ifupdown_interface(text, "eth0")
    assert info["method"] == "dhcp"
    assert info["address"] is None
    assert info["gateway"] is None
    assert "address " not in text


def test_add_missing_interface():
    updated = update_ifupdown_interface(BASE, "eth1", "static", "10.1.0.5/24", "10.1.0.1", [])
    info = read_ifupdown_interface(updated, "eth1")
    assert info is not None
    assert info["address"] == "10.1.0.5/24"
    assert "auto eth1" in updated
    # original content untouched
    assert "iface eth0 inet dhcp" in updated


def test_preserves_manual_options_and_comments():
    base = """auto eth0
iface eth0 inet dhcp
    # keep this comment
    post-up /usr/local/bin/hook.sh
"""
    updated = update_ifupdown_interface(base, "eth0", "static", "10.0.0.2/24", None, [])
    assert "# keep this comment" in updated
    assert "post-up /usr/local/bin/hook.sh" in updated


def test_auto_line_added_when_missing():
    base = "iface eth0 inet dhcp\n"
    updated = update_ifupdown_interface(base, "eth0", "dhcp")
    assert "auto eth0" in updated


def test_static_requires_address():
    try:
        update_ifupdown_interface(BASE, "eth0", "static", None, None, [])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for static without address")


def test_invalid_address_rejected():
    try:
        update_ifupdown_interface(BASE, "eth0", "static", "not-an-ip", None, [])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad address")


def test_a_leftover_dhcp_stanza_is_removed():
    """The reported fault: a static address saved next to a DHCP stanza.

    ifupdown brings an interface up from every stanza that names it, so a
    file carrying both leaves the box with a lease and a static address at
    the same time. Setting static must leave exactly one stanza behind.
    """
    text = (
        "# Server interfaces\n"
        "auto lo\n"
        "iface lo inet loopback\n"
        "\n"
        "auto eth0\n"
        "iface eth0 inet dhcp\n"
        "\n"
        "auto eth0\n"
        "iface eth0 inet static\n"
        "    address 10.0.0.5/24\n"
        "    gateway 10.0.0.1\n"
    )
    result = update_ifupdown_interface(text, "eth0", "static", "10.0.0.5/24", "10.0.0.1")
    assert result.count("iface eth0 inet") == 1
    assert "iface eth0 inet dhcp" not in result
    assert "iface eth0 inet static" in result
    # The interface must still read back as the one we configured.
    info = read_ifupdown_interface(result, "eth0")
    assert info is not None and info["method"] == "static"
    assert info["address"] == "10.0.0.5/24"
    assert info["gateway"] == "10.0.0.1"


def test_a_leftover_dhcp_stanza_comes_after_the_static_one():
    """Order must not matter: the DHCP block is removed either way."""
    text = (
        "iface eth0 inet static\n"
        "    address 10.0.0.5/24\n"
        "\n"
        "auto eth0\n"
        "iface eth0 inet dhcp\n"
    )
    result = update_ifupdown_interface(text, "eth0", "static", "10.0.0.9/24")
    assert "dhcp" not in result
    assert result.count("iface eth0 inet") == 1
    info = read_ifupdown_interface(result, "eth0")
    assert info is not None and info["address"] == "10.0.0.9/24"


def test_three_stanzas_collapse_to_one_and_keep_other_interfaces():
    text = (
        "auto eth0\n"
        "iface eth0 inet dhcp\n"
        "\n"
        "auto eth1\n"
        "iface eth1 inet static\n"
        "    address 192.168.1.10/24\n"
        "\n"
        "iface eth0 inet manual\n"
        "\n"
        "iface eth0 inet dhcp\n"
    )
    result = update_ifupdown_interface(text, "eth0", "static", "10.0.0.5/24")
    assert result.count("iface eth0 inet") == 1
    assert "iface eth1 inet static" in result  # untouched
    assert "192.168.1.10/24" in result


def test_single_stanza_behaviour_is_unchanged():
    """The normal case must be byte-identical to what it always produced."""
    result = update_ifupdown_interface(BASE, "eth0", "static", "10.0.0.5/24", "10.0.0.1")
    assert "iface eth0 inet static" in result
    assert "iface lo inet loopback" in result
    assert result.count("iface eth0 inet") == 1


def test_switching_to_dhcp_drops_a_stale_static_stanza():
    text = (
        "auto eth0\n"
        "iface eth0 inet static\n"
        "    address 10.0.0.5/24\n"
        "\n"
        "iface eth0 inet dhcp\n"
    )
    result = update_ifupdown_interface(text, "eth0", "dhcp")
    assert result.count("iface eth0 inet") == 1
    assert "10.0.0.5/24" not in result
    assert "iface eth0 inet dhcp" in result


def test_stanza_header_is_never_written_indented():
    """The 'iface' line must sit at column 0; only options are indented.

    Rewriting an unindented stanza used to emit '    iface eth0 inet static',
    because an empty indent was read as 'use four spaces'. The stanza parser
    in this module only ends a stanza at an unindented line, so the header has
    to stay flush left and the body has to stay indented.
    """
    result = update_ifupdown_interface(BASE, "eth0", "static", "10.0.0.5/24", "10.0.0.1")
    for line in result.splitlines():
        if line.lstrip().startswith("iface "):
            assert line.startswith("iface "), f"stanza header is indented: {line!r}"
    assert "\niface eth0 inet static" in result
    assert "\n    address 10.0.0.5\n" in result  # body stays indented
    # And an already-indented header in the source is normalised, not kept.
    indented = "    iface eth0 inet dhcp\n"
    assert "\niface eth0 inet dhcp\n" in update_ifupdown_interface(indented, "eth0", "dhcp")


def test_stanza_counts_expose_duplicate_configuration():
    counts = stanza_counts(BASE)
    assert counts == {"lo inet": 1, "eth0 inet": 1}
    doubled = stanza_counts(BASE + "\niface eth0 inet static\n    address 10.0.0.5/24\n")
    assert doubled["eth0 inet"] == 2  # what the panel warns about
    # A duplicate for another interface or family does not bleed across.
    other = stanza_counts("iface eth0 inet6 static\n\niface eth0 inet6 static\n")
    assert other == {"eth0 inet6": 2}


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all ifupdown tests passed")
