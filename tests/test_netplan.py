"""Tests for netplan interface editing (pure dict manipulation)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.network import (  # noqa: E402
    read_netplan_interfaces,
    update_netplan_interface,
)

try:
    import yaml  # noqa: F401

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

BASE = {
    "network": {
        "version": 2,
        "renderer": "networkd",
        "ethernets": {
            "eth0": {"dhcp4": True},
        },
    }
}


def _require_yaml():
    if not HAS_YAML:
        print("SKIP: PyYAML not installed")
        return False
    return True


def test_read_netplan_dhcp():
    interfaces = read_netplan_interfaces(BASE)
    assert len(interfaces) == 1
    assert interfaces[0]["name"] == "eth0"
    assert interfaces[0]["method"] == "dhcp"


def test_write_static():
    if not _require_yaml():
        return
    data = update_netplan_interface(dict(BASE), "eth0", "static", "10.0.0.5/24", "10.0.0.1", ["1.1.1.1"])
    interfaces = read_netplan_interfaces(data)
    assert interfaces[0]["method"] == "static"
    assert interfaces[0]["address"] == "10.0.0.5/24"
    assert interfaces[0]["gateway"] == "10.0.0.1"
    assert interfaces[0]["dns"] == ["1.1.1.1"]
    # non-interface keys survive
    assert data["network"]["renderer"] == "networkd"


def test_switch_back_to_dhcp():
    if not _require_yaml():
        return
    data = update_netplan_interface(dict(BASE), "eth0", "static", "10.0.0.5/24", "10.0.0.1", ["1.1.1.1"])
    data = update_netplan_interface(data, "eth0", "dhcp")
    interfaces = read_netplan_interfaces(data)
    assert interfaces[0]["method"] == "dhcp"
    node = data["network"]["ethernets"]["eth0"]
    assert "addresses" not in node
    assert "routes" not in node


def test_add_missing_interface():
    if not _require_yaml():
        return
    data = update_netplan_interface(dict(BASE), "eth1", "static", "10.1.0.5/24", None, [])
    names = [i["name"] for i in read_netplan_interfaces(data)]
    assert names == ["eth0", "eth1"]


def test_static_requires_address():
    if not _require_yaml():
        return
    try:
        update_netplan_interface(dict(BASE), "eth0", "static", None, None, [])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for static without address")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all netplan tests passed")
