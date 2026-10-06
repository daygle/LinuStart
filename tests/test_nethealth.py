"""Networks that are not the default: stale DHCP clients, cloud-init, a dhcpcd
daemon next to ifupdown, ifupdown leftovers next to netplan, NetworkManager's
unmanaged interfaces and hand-written systemd-networkd."""

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import nethealth, network  # noqa: E402
from linustart.util import CmdResult  # noqa: E402


# --- 1. switching DHCP <-> static leaves nothing behind ---------------------

def test_apply_clears_what_the_old_configuration_left(monkeypatch, tmp_path):
    monkeypatch.setattr(network, "ROOT", tmp_path)
    monkeypatch.setattr(network.shutil, "which", lambda cmd: f"/sbin/{cmd}")
    commands = network.ifupdown_apply_commands("ens18")
    assert commands[0] == ["ifdown", "--force", "ens18"]
    assert ["dhcpcd", "-k", "-4", "ens18"] in commands
    # dhclient only when ifupdown started one for this interface
    assert not [c for c in commands if c[0] == "dhclient"]
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "dhclient.ens18.pid").write_text("123\n")
    commands = network.ifupdown_apply_commands("ens18")
    assert ["dhclient", "-r", "-pf", str(tmp_path / "run" / "dhclient.ens18.pid"), "ens18"] in commands
    assert commands[-2] == ["ip", "-4", "addr", "flush", "dev", "ens18", "scope", "global"]
    assert commands[-1] == ["ifup", "ens18"]
    assert network.ifupdown_apply_commands(None) == [["systemctl", "restart", "networking"]]
    with pytest.raises(ValueError):
        network.ifupdown_apply_commands("-evil")


def test_cleanup_failures_never_stop_ifup(monkeypatch):
    monkeypatch.setattr(network.shutil, "which", lambda cmd: f"/sbin/{cmd}")
    ran = []

    async def fake_run(argv, **kwargs):
        ran.append(argv[0])
        return CmdResult(argv, 0 if argv[0] == "ifup" else 1, "", "not running")

    monkeypatch.setattr(network, "run", fake_run)
    asyncio.run(network.apply_backend("ifupdown", "ens18"))
    assert ran == ["ifdown", "dhcpcd", "ip", "ifup"]

    async def ifup_fails(argv, **kwargs):
        return CmdResult(argv, 1, "", "boom")

    monkeypatch.setattr(network, "run", ifup_fails)
    with pytest.raises(RuntimeError):
        asyncio.run(network.apply_backend("ifupdown", "ens18"))


# --- 2. cloud-init ----------------------------------------------------------

CLOUD_NETPLAN = """# This file is generated from information provided by the datasource.  Changes
# to it will not persist across an instance reboot.  To disable cloud-init's
# network configuration capabilities, write a file
network:
    ethernets:
        ens3:
            dhcp4: true
    version: 2
"""


def test_cloud_init_finding():
    files = {"/etc/netplan/50-cloud-init.yaml": CLOUD_NETPLAN, "/etc/netplan/01-mine.yaml": "network: {}\n"}
    found = nethealth.cloud_init_finding(True, False, files)
    assert found["id"] == "cloud-init" and found["fix"] and "50-cloud-init.yaml" in found["detail"]
    assert "01-mine" not in found["detail"]
    assert nethealth.cloud_init_finding(True, True, files) is None  # already disabled
    assert nethealth.cloud_init_finding(False, False, files) is None  # not installed
    assert nethealth.cloud_init_finding(True, False, {"/etc/netplan/01-mine.yaml": "network: {}\n"}) is None


def test_cloud_config_disables_network():
    assert nethealth.cloud_config_disables_network(["network: {config: disabled}\n"])
    assert nethealth.cloud_config_disables_network(["", "network:\n  config: disabled\n"])
    assert not nethealth.cloud_config_disables_network(["network: {version: 2}\n", ": not yaml : ["])


def test_cloud_init_fix_writes_the_documented_file(monkeypatch, tmp_path):
    target = tmp_path / "cloud.cfg.d" / "99-disable-network-config.cfg"
    monkeypatch.setattr(nethealth, "CLOUD_DISABLE_FILE", target)
    nethealth.fix_cloud_init()
    assert nethealth.cloud_config_disables_network([target.read_text()])


# --- 3. dhcpcd daemon next to ifupdown --------------------------------------

def test_dhcpcd_handles_respects_deny_and_allow():
    names = ["ens18", "ens19", "wlan0"]
    assert nethealth.dhcpcd_handles("", names) == names
    assert nethealth.dhcpcd_handles("denyinterfaces ens* # mine\n", names) == ["wlan0"]
    assert nethealth.dhcpcd_handles("allowinterfaces wlan0\n", names) == ["wlan0"]
    assert nethealth.dhcpcd_handles("denyinterfaces ens18,wlan0\n", names) == ["ens19"]


def test_deny_block_is_merged_not_stacked():
    conf = "hostname\nclientid\n"
    once = nethealth.deny_in_dhcpcd_conf(conf, ["ens18"])
    assert once.startswith(conf) and "denyinterfaces ens18\n" in once
    twice = nethealth.deny_in_dhcpcd_conf(once, ["ens19", "ens18"])
    assert twice.count(nethealth.DHCPCD_BEGIN) == 1 and "denyinterfaces ens18 ens19\n" in twice
    assert nethealth.dhcpcd_handles(twice, ["ens18", "ens19", "wlan0"]) == ["wlan0"]
    with pytest.raises(ValueError):
        nethealth.deny_in_dhcpcd_conf(conf, ["bad name"])


def test_dhcpcd_finding():
    assert nethealth.dhcpcd_finding(False, "", ["ens18"]) is None
    assert nethealth.dhcpcd_finding(True, "denyinterfaces ens18\n", ["ens18"]) is None
    found = nethealth.dhcpcd_finding(True, "", ["ens18"])
    assert found["id"] == "dhcpcd" and "ens18" in found["detail"] and found["fix"]


def test_dhcpcd_fix_restarts_then_reapplies(monkeypatch):
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        return CmdResult(argv, 0, "", "")

    async def fake_apply(backend, name=None):
        calls.append(["apply", backend, name])
        return [f"ifup {name}"]

    monkeypatch.setattr(nethealth, "run", fake_run)
    monkeypatch.setattr(nethealth.network, "apply_backend", fake_apply)
    asyncio.run(nethealth.apply_dhcpcd_fix(["ens18"]))
    assert calls == [["systemctl", "restart", "dhcpcd"], ["apply", "ifupdown", "ens18"]]


# --- 4a. ifupdown leftovers next to netplan ----------------------------------

LEFTOVER = """source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto lo eth0
allow-hotplug eth0
iface eth0 inet dhcp

iface eth0 inet6 auto
"""


def test_leftovers_are_removed_with_their_auto_lines():
    changed = nethealth.remove_ifupdown_leftovers({"/etc/network/interfaces": LEFTOVER, "/x": "auto lo\n"}, ["eth0"])
    assert list(changed) == ["/etc/network/interfaces"]
    text = changed["/etc/network/interfaces"]
    assert "eth0" not in text
    assert "iface lo inet loopback" in text and text.count("auto lo") == 2
    assert "source /etc/network/interfaces.d/*" in text


def test_leftover_finding():
    assert nethealth.ifupdown_leftover_finding(True, ["eth0"], ["eth0", "eth1"])["id"] == "ifupdown-leftover"
    assert nethealth.ifupdown_leftover_finding(False, ["eth0"], ["eth0"]) is None  # ifupdown not installed
    assert nethealth.ifupdown_leftover_finding(True, ["eth0"], ["eth1"]) is None


# --- 4b. NetworkManager leaves ifupdown's interfaces alone -------------------

def _machine(monkeypatch, tmp_path, interfaces="", netplan=None, networkd=None):
    etc = tmp_path / "etc"
    (etc / "network").mkdir(parents=True)
    (etc / "network" / "interfaces").write_text(interfaces)
    monkeypatch.setattr(network, "ROOT", tmp_path)
    monkeypatch.setattr(network, "INTERFACES_FILE", etc / "network" / "interfaces")
    monkeypatch.setattr(network, "NETPLAN_DIR", etc / "netplan")
    monkeypatch.setattr(network, "NETWORKD_DIR", etc / "systemd" / "network")
    if netplan:
        (etc / "netplan").mkdir()
        for name, text in netplan.items():
            (etc / "netplan" / name).write_text(text)
    if networkd:
        (etc / "systemd" / "network").mkdir(parents=True)
        for name, text in networkd.items():
            (etc / "systemd" / "network" / name).write_text(text)


def test_networkmanager_lists_and_routes_ifupdown_interfaces(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path, "auto ens18\niface ens18 inet static\n    address 10.0.0.2/24\n")

    async def fake_run(argv, **kwargs):
        if argv[:4] == ["nmcli", "-t", "-f", "NAME,DEVICE,TYPE"]:
            return CmdResult(argv, 0, "Wired:wlan0:802-11-wireless\n", "")
        if argv[:3] == ["nmcli", "-t", "con"]:
            return CmdResult(argv, 0, "ipv4.method:auto\nGENERAL.STATE:activated\n", "")
        return CmdResult(argv, 0, "", "")

    monkeypatch.setattr(network, "run", fake_run)
    config = asyncio.run(network.get_config("NetworkManager"))
    legacy = [i for i in config["interfaces"] if i.get("backend") == "ifupdown"]
    assert [i["name"] for i in legacy] == ["ens18"]
    assert asyncio.run(network.backend_for("ens18", "NetworkManager")) == "ifupdown"
    assert asyncio.run(network.backend_for("wlan0", "NetworkManager")) == "NetworkManager"
    assert nethealth.nm_unmanaged_finding(config["interfaces"])["id"] == "nm-unmanaged"


# --- 5. hand-written systemd-networkd ----------------------------------------

NETWORKD_STATIC = """[Match]
Name=ens3

[Network]
Address=192.0.2.10/24
Gateway=192.0.2.1
DNS=192.0.2.53 1.1.1.1
"""


def test_parse_networkd_file():
    info = network.parse_networkd_file(NETWORKD_STATIC)
    assert info["name"] == "ens3" and info["method"] == "static"
    assert info["address"] == "192.0.2.10/24" and info["gateway"] == "192.0.2.1"
    assert info["dns"] == ["192.0.2.53", "1.1.1.1"] and info["readonly"]
    assert network.parse_networkd_file("[Match]\nName=en*\n[Network]\nDHCP=yes\n")["method"] == "dhcp"
    assert network.parse_networkd_file("[Network]\nDHCP=yes\n") is None


def test_networkd_is_detected_and_read_only(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path, "auto lo\niface lo inet loopback\n", networkd={"10-ens3.network": NETWORKD_STATIC})

    async def active(unit):
        return unit == "systemd-networkd"

    monkeypatch.setattr(network, "_unit_active", active)
    assert asyncio.run(network.detect_backend()) == "systemd-networkd"
    config = asyncio.run(network.get_config("systemd-networkd"))
    assert config["readonly"] and config["interfaces"][0]["address"] == "192.0.2.10/24"
    with pytest.raises(ValueError):
        asyncio.run(network.write_interface_config("systemd-networkd", "ens3", "dhcp"))
    with pytest.raises(ValueError):
        asyncio.run(network.apply_backend("systemd-networkd", "ens3"))
    # an ifupdown stanza for a real interface means ifupdown is in use
    (tmp_path / "etc" / "network" / "interfaces").write_text("auto ens3\niface ens3 inet dhcp\n")
    assert asyncio.run(network.detect_backend()) == "ifupdown"


# --- the page's findings, end to end -----------------------------------------

def test_findings_on_an_upgraded_cloud_machine(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path, LEFTOVER, netplan={"50-cloud-init.yaml": CLOUD_NETPLAN.replace("ens3", "eth0")})
    monkeypatch.setattr(nethealth, "ROOT", tmp_path)
    monkeypatch.setattr(nethealth, "CLOUD_DISABLED_MARKER", tmp_path / "nope")
    monkeypatch.setattr(nethealth, "_cloud_cfg_texts", lambda: [""])
    monkeypatch.setattr(nethealth.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    found = asyncio.run(nethealth.findings("netplan", {"interfaces": []}))
    assert {f["id"] for f in found} == {"cloud-init", "ifupdown-leftover"}
    changed = nethealth.fix_ifupdown_leftovers(nethealth.ifupdown_leftover_names())
    assert changed == [str(tmp_path / "etc" / "network" / "interfaces")]
    assert "eth0" not in (tmp_path / "etc" / "network" / "interfaces").read_text()


def test_findings_never_raise(monkeypatch):
    def broken():
        raise OSError("disk on fire")

    monkeypatch.setattr(nethealth.network, "_netplan_files", broken)
    found = asyncio.run(nethealth.findings("netplan", {}))
    assert found[0]["id"] == "check-failed"


def test_networkd_dns_is_not_reported_as_a_no_op():
    assert network.dns_setting_applies("systemd-networkd", "static", False)
