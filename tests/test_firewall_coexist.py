"""The firewall next to other firewalls, Docker, and on a machine with none."""

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import firewall  # noqa: E402
from linustart.util import CmdResult  # noqa: E402

QUIET = dict(nft_service_enabled=False, firewalld_enabled=False, firewalld_running=False,
             ufw_active=False, docker=False)


def ids(found):
    return [f["id"] for f in found]


def test_a_clean_setup_has_nothing_to_say():
    assert firewall.firewall_findings("ufw", True, **QUIET) == []
    assert firewall.firewall_findings("nftables", False, **QUIET) == []


def test_nftables_rules_must_survive_a_reboot():
    found = firewall.firewall_findings("nftables", True, **QUIET)
    assert ids(found) == ["nftables-persist"]
    assert found[0]["fix"]["endpoint"] == "/firewall/fix/nftables-persist"
    assert firewall.firewall_findings("nftables", True, **{**QUIET, "nft_service_enabled": True}) == []


def test_competing_firewalls():
    assert ids(firewall.firewall_findings("ufw", True, **{**QUIET, "nft_service_enabled": True})) == ["nftables-service"]
    assert ids(firewall.firewall_findings("ufw", True, **{**QUIET, "firewalld_enabled": True})) == ["firewalld-enabled"]
    # a running firewalld is the backend itself, not a competitor
    assert firewall.firewall_findings("firewalld", True, **{**QUIET, "firewalld_enabled": True,
                                                           "firewalld_running": True}) == []
    assert ids(firewall.firewall_findings("firewalld", True, **{**QUIET, "ufw_active": True})) == ["ufw-active"]
    docker = firewall.firewall_findings("ufw", True, **{**QUIET, "docker": True})
    assert ids(docker) == ["docker"] and docker[0]["fix"] is None
    # every fixable finding has a command, and none of them stops nftables (that would flush)
    for fid, argv in firewall.FIX_COMMANDS.items():
        assert "stop" not in argv and "--now" not in argv, fid


def test_status_without_any_firewall(monkeypatch):
    async def none():
        raise RuntimeError("no supported firewall backend found")

    monkeypatch.setattr(firewall, "detect_backend", none)
    monkeypatch.setattr(firewall, "ssh_port", lambda: "22")
    data = asyncio.run(firewall.status())
    assert data["backend"] == "" and data["installed"] is False
    assert ids(data["findings"]) == ["no-firewall"]


def test_enabling_nftables_enables_the_service_without_starting_it(monkeypatch, tmp_path):
    monkeypatch.setattr(firewall, "NFTABLES_CONF", tmp_path / "nftables.conf")
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        return CmdResult(argv, 1 if argv[:2] == ["systemctl", "is-enabled"] else 0, "", "")

    monkeypatch.setattr(firewall, "run", fake_run)
    asyncio.run(firewall.nftables_apply(enabled=True, rules=[]))
    assert ["systemctl", "enable", "nftables"] in calls
    assert not [c for c in calls if c[:2] == ["systemctl", "start"] or "--now" in c]
