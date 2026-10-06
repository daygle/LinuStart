"""sshd_config.d drop-ins (first value wins) and socket-activated sshd."""

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import sshd  # noqa: E402
from linustart.util import CmdResult  # noqa: E402

DEBIAN_MAIN = """Include /etc/ssh/sshd_config.d/*.conf

#Port 22
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding yes

Match User backup
    PasswordAuthentication yes
"""
CLOUDIMG = "PasswordAuthentication yes\n"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    ssh = tmp_path / "etc" / "ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    monkeypatch.setattr(sshd, "ROOT", tmp_path)
    monkeypatch.setattr(sshd, "SSHD_CONFIG", ssh / "sshd_config")
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")

    async def valid():
        return None

    monkeypatch.setattr(sshd, "validate", valid)
    return ssh


def test_a_cloud_image_dropin_beats_the_main_file(machine):
    (machine / "sshd_config").write_text(DEBIAN_MAIN)
    (machine / "sshd_config.d" / "50-cloudimg-settings.conf").write_text(CLOUDIMG)
    found = sshd.effective()
    assert found["PasswordAuthentication"] == ("yes", str(machine / "sshd_config.d" / "50-cloudimg-settings.conf"))
    assert found["X11Forwarding"][0] == "yes"
    # the Match block is not the global picture
    assert sshd.effective_values([("x", "Match all\nPort 2\n")]) == {}
    assert sshd.dropin_path() == machine / "sshd_config.d" / "00-linustart.conf"


def test_settings_go_to_a_dropin_that_wins(machine):
    (machine / "sshd_config").write_text(DEBIAN_MAIN)
    (machine / "sshd_config.d" / "50-cloudimg-settings.conf").write_text(CLOUDIMG)
    asyncio.run(sshd.apply_settings({"PasswordAuthentication": False, "Port": 2222}))
    dropin = (machine / "sshd_config.d" / "00-linustart.conf").read_text()
    assert "PasswordAuthentication no\n" in dropin and "Port 2222\n" in dropin
    assert sshd.effective()["PasswordAuthentication"][0] == "no"
    # the main file and the other drop-in are left as they were
    assert (machine / "sshd_config").read_text() == DEBIAN_MAIN
    assert (machine / "sshd_config.d" / "50-cloudimg-settings.conf").read_text() == CLOUDIMG
    # a second save merges into the drop-in
    asyncio.run(sshd.apply_settings({"MaxAuthTries": 3}))
    dropin = (machine / "sshd_config.d" / "00-linustart.conf").read_text()
    assert "Port 2222\n" in dropin and "MaxAuthTries 3\n" in dropin
    assert sshd.config_files() == [machine / "sshd_config", machine / "sshd_config.d" / "00-linustart.conf"]


def test_a_main_file_line_above_the_include_is_edited_in_place(machine):
    (machine / "sshd_config").write_text("Port 2200\n" + DEBIAN_MAIN)
    asyncio.run(sshd.apply_settings({"Port": 2222}))
    assert sshd.effective()["Port"][0] == "2222"
    assert (machine / "sshd_config").read_text().startswith("Port 2222\n")


def test_without_an_include_the_main_file_is_edited(machine):
    (machine / "sshd_config").write_text("Port 22\nPasswordAuthentication yes\n")
    assert sshd.dropin_path() is None
    asyncio.run(sshd.apply_settings({"PasswordAuthentication": False}))
    assert "PasswordAuthentication no" in (machine / "sshd_config").read_text()
    assert not (machine / "sshd_config.d" / "00-linustart.conf").exists()
    assert sshd.config_files() == [machine / "sshd_config"]


def test_status_reports_sources_and_overrides(machine, monkeypatch):
    (machine / "sshd_config").write_text(DEBIAN_MAIN)
    (machine / "sshd_config.d" / "50-cloudimg-settings.conf").write_text(CLOUDIMG)

    async def fake_run(argv, **kwargs):
        return CmdResult(argv, 1, "", "")

    monkeypatch.setattr(sshd, "run", fake_run)
    monkeypatch.setattr(sshd.shutil, "which", lambda cmd: None)
    data = asyncio.run(sshd.status())
    assert data["typed"]["PasswordAuthentication"] is True
    assert data["overriding_files"] == [str(machine / "sshd_config.d" / "50-cloudimg-settings.conf")]
    assert data["writes_to"].endswith("00-linustart.conf") and data["socket_activated"] is False


def test_socket_activated_sshd_regenerates_its_socket(monkeypatch):
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        return CmdResult(argv, 0, "", "")

    monkeypatch.setattr(sshd, "run", fake_run)
    asyncio.run(sshd.reload_service())
    assert calls[1:] == [["systemctl", "daemon-reload"], ["systemctl", "restart", "ssh.socket"],
                         ["systemctl", "reload-or-restart", "ssh"]]

    calls.clear()

    async def no_socket(argv, **kwargs):
        calls.append(argv)
        return CmdResult(argv, 1 if "ssh.socket" in argv else 0, "", "")

    monkeypatch.setattr(sshd, "run", no_socket)
    asyncio.run(sshd.reload_service())
    assert calls[-1] == ["systemctl", "reload", "ssh"]
