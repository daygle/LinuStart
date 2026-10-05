"""IPv6, netplan device sections and NetworkManager parsing."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import network as net  # noqa: E402

yaml = pytest.importorskip("yaml")

STATIC6 = {"method": "static", "address": "2001:db8::10/64", "gateway": "fe80::1"}


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------

def test_validate_ipv6():
    assert net.validate_ipv6(None) is None and net.validate_ipv6("") is None
    assert net.validate_ipv6("auto") == {"method": "auto", "address": None, "gateway": None}
    assert net.validate_ipv6("static", "2001:DB8::10/64", "fe80::1") == STATIC6
    for bad in [("static", None, None), ("static", "10.0.0.1/24", None),
                ("static", "2001:db8::1/64", "10.0.0.1"), ("bogus", None, None)]:
        with pytest.raises(ValueError):
            net.validate_ipv6(*bad)


def test_ipv4_fields_refuse_ipv6_addresses():
    with pytest.raises(ValueError):
        net.update_ifupdown_interface("", "eth0", "static", "2001:db8::1/64")
    with pytest.raises(ValueError):
        net.update_netplan_interface({}, "eth0", "static", "10.0.0.5/24", "2001:db8::1")


# --------------------------------------------------------------------------
# ifupdown inet6 stanzas
# --------------------------------------------------------------------------

def test_ifupdown_static_ipv6_stanza_is_written_and_read_back():
    docs = {"/main": "auto eth0\niface eth0 inet dhcp\n"}
    updated, changed = net.apply_ifupdown_across(docs, "/main", "eth0", "dhcp", ipv6=STATIC6)
    text = updated["/main"]
    assert changed == ["/main"]
    assert "iface eth0 inet6 static" in text and "address 2001:db8::10/64" in text
    assert text.count("auto eth0") == 1
    info = net.read_ifupdown_interface(text, "eth0")
    assert info["method"] == "dhcp"
    assert info["ipv6"] == {"method": "static", "address": "2001:db8::10/64", "gateway": "fe80::1"}


def test_ifupdown_ipv6_none_removes_the_stanza_and_unchanged_keeps_it():
    text = "auto eth0\niface eth0 inet dhcp\niface eth0 inet6 auto\n"
    kept, _ = net.apply_ifupdown_across({"/m": text}, "/m", "eth0", "dhcp")
    assert "inet6 auto" in kept["/m"]
    gone, _ = net.apply_ifupdown_across({"/m": text}, "/m", "eth0", "dhcp",
                                        ipv6={"method": "none", "address": None, "gateway": None})
    assert "inet6" not in gone["/m"]


def test_ifupdown_ipv6_copies_in_other_files_are_removed():
    docs = {"/m": "auto eth0\niface eth0 inet dhcp\n", "/d/eth0-v6": "iface eth0 inet6 dhcp\n"}
    updated, changed = net.apply_ifupdown_across(
        docs, "/m", "eth0", "dhcp", ipv6={"method": "auto", "address": None, "gateway": None}
    )
    assert "inet6" not in updated["/d/eth0-v6"]
    assert "iface eth0 inet6 auto" in updated["/m"]
    assert sorted(changed) == ["/d/eth0-v6", "/m"]


# --------------------------------------------------------------------------
# netplan: per-family addresses/routes and device sections
# --------------------------------------------------------------------------

DUAL = {"network": {"version": 2, "ethernets": {"eth0": {
    "dhcp4": False,
    "addresses": ["10.0.0.5/24", "2001:db8::5/64"],
    "routes": [{"to": "default", "via": "10.0.0.1"}, {"to": "::/0", "via": "fe80::1"}],
}}}}


def test_netplan_reads_both_families():
    (iface,) = net.read_netplan_interfaces(DUAL)
    assert iface["address"] == "10.0.0.5/24" and iface["gateway"] == "10.0.0.1"
    assert iface["ipv6"] == {"method": "static", "address": "2001:db8::5/64", "gateway": "fe80::1"}


def test_netplan_ipv4_change_keeps_ipv6_address_and_route():
    data = net.update_netplan_interface(DUAL, "eth0", "dhcp")
    node = data["network"]["ethernets"]["eth0"]
    assert node["addresses"] == ["2001:db8::5/64"]
    assert node["routes"] == [{"to": "::/0", "via": "fe80::1"}]
    assert node["dhcp4"] is True


def test_netplan_ipv6_change_keeps_ipv4():
    data = net.update_netplan_interface(
        DUAL, "eth0", "static", "10.0.0.5/24", "10.0.0.1",
        ipv6={"method": "dhcp", "address": None, "gateway": None},
    )
    node = data["network"]["ethernets"]["eth0"]
    assert node["addresses"] == ["10.0.0.5/24"]
    assert node["routes"] == [{"to": "default", "via": "10.0.0.1"}]
    assert node["dhcp6"] is True
    assert net.read_netplan_interfaces(data)[0]["ipv6"]["method"] == "dhcp"


def test_netplan_ipv6_none_stops_router_advertisements():
    data = net.update_netplan_interface(
        DUAL, "eth0", "static", "10.0.0.5/24", None,
        ipv6={"method": "none", "address": None, "gateway": None},
    )
    node = data["network"]["ethernets"]["eth0"]
    assert node["accept-ra"] is False and node["dhcp6"] is False
    assert net.read_netplan_interfaces(data)[0]["ipv6"]["method"] == "none"


def test_netplan_bonds_vlans_bridges_and_wifis_are_listed_and_edited_in_place():
    data = {"network": {"version": 2,
                        "ethernets": {"eno1": {}},
                        "bonds": {"bond0": {"interfaces": ["eno1"], "dhcp4": True}},
                        "vlans": {"vlan10": {"id": 10, "link": "bond0"}},
                        "bridges": {"br0": {"interfaces": ["vlan10"]}},
                        "wifis": {"wlan0": {"access-points": {"home": {}}, "dhcp4": True}}}}
    kinds = {i["name"]: i["kind"] for i in net.read_netplan_interfaces(data)}
    assert kinds == {"eno1": "ethernets", "bond0": "bonds", "vlan10": "vlans",
                     "br0": "bridges", "wlan0": "wifis"}
    updated = net.update_netplan_interface(data, "bond0", "static", "10.0.0.5/24")
    bond = updated["network"]["bonds"]["bond0"]
    assert bond["addresses"] == ["10.0.0.5/24"] and bond["interfaces"] == ["eno1"]
    assert "bond0" not in updated["network"]["ethernets"]


def test_netplan_dhcp_cleared_for_a_bond_in_another_file():
    docs = {"/a.yaml": {"network": {"version": 2, "bonds": {"bond0": {"dhcp4": True}}}},
            "/b.yaml": {"network": {"version": 2}}}
    updated, changed = net.apply_netplan_across(docs, "/a.yaml", "bond0", "static", "10.0.0.5/24")
    assert net.netplan_dhcp_sources(updated, "bond0") == []
    assert changed == ["/a.yaml"]


def test_netplan_ipv6_dhcp_keeps_dhcp6_elsewhere():
    docs = {"/a.yaml": {"network": {"version": 2, "ethernets": {"eth0": {"dhcp6": True}}}},
            "/b.yaml": {"network": {"version": 2, "ethernets": {"eth0": {}}}}}
    updated, changed = net.apply_netplan_across(
        docs, "/b.yaml", "eth0", "static", "10.0.0.5/24",
        ipv6={"method": "dhcp", "address": None, "gateway": None},
    )
    assert updated["/a.yaml"]["network"]["ethernets"]["eth0"]["dhcp6"] is True
    assert changed == ["/b.yaml"]


def test_netplan_address_maps_are_understood():
    data = {"network": {"ethernets": {"eth0": {"addresses": [{"10.0.0.5/24": {"label": "eth0:0"}}]}}}}
    assert net.read_netplan_interfaces(data)[0]["address"] == "10.0.0.5/24"


# --------------------------------------------------------------------------
# NetworkManager
# --------------------------------------------------------------------------

NM_SHOW = r"""connection.id:Wired connection 1
connection.interface-name:eth0
connection.autoconnect:yes
ipv4.method:manual
ipv4.addresses:10.0.0.5/24
ipv4.gateway:10.0.0.1
ipv4.dns:1.1.1.1
ipv6.method:manual
ipv6.addresses:2001\:db8\:\:5/64
ipv6.gateway:fe80\:\:1
ipv6.dns:2606\:4700\:4700\:\:1111
"""


def test_nm_terse_output_unescapes_ipv6():
    settings = net.parse_nm_settings(NM_SHOW)
    assert settings["ipv6.addresses"] == "2001:db8::5/64"
    info = net.nm_interface_info("Wired connection 1", "", "ethernet", settings)
    assert info["name"] == "eth0" and info["active"] is False  # inactive: name from the profile
    assert info["ipv6"] == {"method": "static", "address": "2001:db8::5/64", "gateway": "fe80::1"}
    assert info["dns"] == ["1.1.1.1", "2606:4700:4700::1111"]


def test_nm_ipv6_arguments():
    assert net.nm_ipv6_args(None, []) == []
    assert net.nm_ipv6_args(None, ["2001:db8::53"]) == ["ipv6.dns", "2001:db8::53"]
    assert net.nm_ipv6_args(STATIC6, []) == [
        "ipv6.method", "manual", "ipv6.addresses", "2001:db8::10/64",
        "ipv6.gateway", "fe80::1", "ipv6.dns", "",
    ]
    assert net.nm_ipv6_args({"method": "none", "address": None, "gateway": None}, [])[:2] == [
        "ipv6.method", "ignore",
    ]
