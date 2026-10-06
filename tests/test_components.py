"""System components: install what is missing, remove what is unused - safely."""

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import components  # noqa: E402
from linustart.util import CmdResult  # noqa: E402


def row(cid, installed, in_use=None, active=(), blocked=None):
    return components.classify(cid, installed, in_use=in_use or {}, active_services=list(active),
                               blocked=blocked or {})


def test_missing_components_can_be_installed():
    item = row("ufw", [])
    assert item["state"] == "not installed" and item["can_install"] and not item["can_remove"]
    # Exim is never installed from the panel, only cleaned up
    assert not row("exim4", [])["can_install"]


def test_in_use_is_never_removable():
    item = row("ufw", ["ufw"], in_use={"ufw": "the firewall managed by the panel"})
    assert item["state"] == "in use" and not item["can_remove"]
    # a running daemon counts as in use even when nothing names it
    item = row("chrony", ["chrony"], active=["chrony"])
    assert item["in_use"] and item["detail"] == "chrony is running" and not item["can_remove"]


def test_installed_but_unused_can_be_removed():
    item = row("firewalld", ["firewalld"])
    assert item["state"] == "installed, unused" and item["can_remove"]
    exim = row("exim4", ["exim4-base", "exim4-daemon-light", "exim4-config"])
    assert exim["can_remove"] and exim["packages"] == ["exim4-base", "exim4-daemon-light", "exim4-config"]


def test_choices_are_not_offered_for_removal():
    assert not row("cron", ["cron"])["can_remove"]
    assert not row("unattended-upgrades", ["unattended-upgrades"])["can_remove"]


def test_blocked_components():
    blocked = {"postfix": "this machine is a mail server (mailcow)"}
    assert not row("postfix", [], blocked=blocked)["can_install"]
    assert not row("postfix", ["postfix"], blocked=blocked)["can_remove"]


def test_removal_never_takes_anything_else():
    simulation = "Remv exim4-daemon-light [4.97]\nRemv exim4-base [4.97]\nRemv mailutils [1:3.17]\n"
    assert components.removal_extras(simulation, ["exim4-base", "exim4-daemon-light"]) == ["mailutils"]
    assert components.removal_extras("Remv firewalld [2.1]\n", ["firewalld"]) == []
    assert components.removal_extras("Remv ufw:all [0.36]\n", ["ufw"]) == []


def test_install_never_removes_a_conflicting_package():
    argv = components.install_command("systemd-timesyncd")
    assert argv[:3] == ["apt-get", "-y", "--no-remove"] and argv[-1] == "systemd-timesyncd"


def _live(monkeypatch, installed, simulation="", active=()):
    async def fake_installed():
        return list(installed)

    async def fake_active(services):
        return [s for s in services if s in active]

    async def fake_in_use(_installed):
        return {}

    async def fake_blocked(_installed):
        return {}

    async def fake_run(argv, **kwargs):
        return CmdResult(argv, 0, simulation, "")

    monkeypatch.setattr(components, "_installed", fake_installed)
    monkeypatch.setattr(components, "_active", fake_active)
    monkeypatch.setattr(components, "_in_use", fake_in_use)
    monkeypatch.setattr(components, "_blocked", fake_blocked)
    monkeypatch.setattr(components, "run", fake_run)


def test_check_removal(monkeypatch):
    _live(monkeypatch, ["firewalld"], simulation="Remv firewalld [2.1]\n")
    assert asyncio.run(components.check_removal("firewalld")) == ["firewalld"]
    _live(monkeypatch, ["firewalld"], simulation="Remv firewalld [2.1]\nRemv python3-firewall [2.1]\n")
    with pytest.raises(ValueError, match="python3-firewall"):
        asyncio.run(components.check_removal("firewalld"))
    _live(monkeypatch, ["chrony"], active=["chrony"])
    with pytest.raises(ValueError, match="in use"):
        asyncio.run(components.check_removal("chrony"))


def test_status_groups_every_component(monkeypatch):
    _live(monkeypatch, ["ufw", "cron"])
    data = asyncio.run(components.status())
    assert [g["name"] for g in data["groups"]] == components.GROUP_ORDER
    assert sum(len(g["items"]) for g in data["groups"]) == len(components.COMPONENTS)


def test_one_per_exclusive_area():
    blocked = components.exclusive_blocks(["nftables", "msmtp-mta", "chrony"])
    assert "ufw" in blocked and "firewalld" in blocked and "nftables" not in blocked
    assert "postfix" in blocked and "msmtp-mta" not in blocked
    assert "systemd-timesyncd" in blocked and "chrony" not in blocked
    assert "cron" not in blocked and "resolvconf" not in blocked
    assert components.exclusive_blocks([]) == {}
