"""Tests for netplan interface editing (pure dict manipulation)."""

import copy
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.network import (  # noqa: E402
    apply_netplan_across,
    clear_netplan_dhcp,
    netplan_dhcp_sources,
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


# --- netplan merges every file in /etc/netplan ------------------------------

# What cloud-init writes, with the interface on DHCP.
CLOUD_INIT = {
    "network": {"version": 2, "ethernets": {"eth0": {"dhcp4": True, "mtu": 1500}}}
}
# A second file, which is where a static address would land.
LATE = {"network": {"version": 2, "ethernets": {}}}


def test_dhcp_in_another_file_is_found():
    documents = {"/etc/netplan/01-netcfg.yaml": CLOUD_INIT, "/etc/netplan/99-late.yaml": LATE}
    assert netplan_dhcp_sources(documents, "eth0") == ["/etc/netplan/01-netcfg.yaml"]
    assert netplan_dhcp_sources(documents, "eth1") == []


def test_static_write_clears_dhcp_in_every_file():
    """The reported fault: dhcp4 survives the merge and the interface does both.

    The static address goes into the file we edit; DHCP lives in cloud-init's
    file. netplan merges them, so without clearing DHCP in both places the
    interface comes up with a lease and a static address at the same time.
    """
    if not _require_yaml():
        return
    documents = {"/etc/netplan/01-netcfg.yaml": CLOUD_INIT, "/etc/netplan/99-late.yaml": LATE}
    updated, changed = apply_netplan_across(
        documents, "/etc/netplan/99-late.yaml", "eth0", "static", "10.0.0.5/24", "10.0.0.1"
    )
    assert sorted(changed) == ["/etc/netplan/01-netcfg.yaml", "/etc/netplan/99-late.yaml"]
    # DHCP is off everywhere, so the merged result has no lease.
    assert netplan_dhcp_sources(updated, "eth0") == []
    written = updated["/etc/netplan/99-late.yaml"]["network"]["ethernets"]["eth0"]
    assert written["dhcp4"] is False
    assert written["addresses"] == ["10.0.0.5/24"]
    # And cloud-init's own settings survive: only the DHCP keys are touched.
    assert updated["/etc/netplan/01-netcfg.yaml"]["network"]["ethernets"]["eth0"] == {
        "dhcp4": False,
        "mtu": 1500,
    }


def test_the_documents_passed_in_are_not_mutated():
    if not _require_yaml():
        return
    documents = {"/a.yaml": CLOUD_INIT, "/b.yaml": LATE}
    snapshot = copy.deepcopy(documents)
    apply_netplan_across(documents, "/b.yaml", "eth0", "static", "10.0.0.5/24")
    assert documents == snapshot


def test_only_the_files_that_change_are_rewritten():
    if not _require_yaml():
        return
    documents = {
        "/etc/netplan/01-netcfg.yaml": CLOUD_INIT,
        "/etc/netplan/60-other.yaml": {
            "network": {"version": 2, "ethernets": {"eth9": {"dhcp4": True}}}
        },
        "/etc/netplan/99-late.yaml": LATE,
    }
    _updated, changed = apply_netplan_across(
        documents, "/etc/netplan/99-late.yaml", "eth0", "static", "10.0.0.5/24"
    )
    # eth9's DHCP in another file must not drag that file into the rewrite.
    assert sorted(changed) == ["/etc/netplan/01-netcfg.yaml", "/etc/netplan/99-late.yaml"]


def test_switching_to_dhcp_leaves_other_files_alone():
    if not _require_yaml():
        return
    documents = {"/etc/netplan/01-netcfg.yaml": CLOUD_INIT, "/etc/netplan/99-late.yaml": LATE}
    updated, changed = apply_netplan_across(
        documents, "/etc/netplan/99-late.yaml", "eth0", "dhcp"
    )
    assert changed == ["/etc/netplan/99-late.yaml"]
    assert updated["/etc/netplan/01-netcfg.yaml"] == CLOUD_INIT  # untouched


def test_clear_netplan_dhcp_reports_whether_it_changed_anything():
    data, changed = clear_netplan_dhcp(LATE, "eth0")
    assert changed is False and data == LATE
    data, changed = clear_netplan_dhcp(CLOUD_INIT, "eth9")  # wrong interface
    assert changed is False


def test_dhcp6_is_cleared_too():
    if not _require_yaml():
        return
    documents = {
        "/etc/netplan/01-netcfg.yaml": {
            "network": {"version": 2, "ethernets": {"eth0": {"dhcp6": True}}}
        }
    }
    updated, _changed = apply_netplan_across(documents, list(documents)[0], "eth0", "static", "10.0.0.5/24")
    assert netplan_dhcp_sources(updated, "eth0") == []


def test_target_must_be_one_of_the_loaded_documents():
    try:
        apply_netplan_across({"a": BASE}, "b", "eth0", "static", "10.0.0.5/24")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an unknown target")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all netplan tests passed")
