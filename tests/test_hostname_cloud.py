"""A hostname saved on a cloud-init machine survives the next boot."""

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import hostname, nethealth  # noqa: E402
from linustart.util import CmdResult  # noqa: E402


def test_what_cloud_init_would_undo():
    assert hostname.cloud_resets_hostname({}) == ["hostname"]
    assert hostname.cloud_resets_hostname({"preserve_hostname": True}) == []
    assert hostname.cloud_resets_hostname({"preserve_hostname": True, "manage_etc_hosts": True}) == ["/etc/hosts"]
    assert hostname.cloud_resets_hostname({"manage_etc_hosts": "localhost"}) == ["hostname", "/etc/hosts"]


def test_cloud_settings_merge_later_files_over_earlier():
    merged = nethealth.cloud_settings(["preserve_hostname: false\nusers: [default]\n",
                                       "preserve_hostname: true\n", "not: [valid"])
    assert merged["preserve_hostname"] is True and merged["users"] == ["default"]


def _machine(monkeypatch, tmp_path, cfg, installed=True):
    for name in ("HOSTNAME_FILE", "HOSTS_FILE"):
        monkeypatch.setattr(hostname, name, tmp_path / name.lower())
    (tmp_path / "hosts_file").write_text("127.0.0.1\tlocalhost\n127.0.1.1\told\n")
    monkeypatch.setattr(hostname, "CLOUD_HOSTNAME_FILE", tmp_path / "cloud.cfg.d" / "99-linustart-hostname.cfg")
    monkeypatch.setattr(nethealth, "cloud_init_installed", lambda: installed)
    monkeypatch.setattr(nethealth, "CLOUD_DISABLED_MARKER", tmp_path / "cloud-init.disabled")
    monkeypatch.setattr(nethealth, "_cloud_cfg_texts", lambda: [cfg])
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")

    async def fake_run(argv, **kwargs):
        return CmdResult(argv, 0, "", "")

    monkeypatch.setattr(hostname, "run", fake_run)


def test_saving_on_a_cloud_machine_tells_cloud_init_to_keep_it(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path, "preserve_hostname: false\nmanage_etc_hosts: true\n")
    assert hostname.cloud_init_status() == {"managed": True, "undone": ["hostname", "/etc/hosts"]}
    asyncio.run(hostname.set_hostname("web1"))
    written = (tmp_path / "cloud.cfg.d" / "99-linustart-hostname.cfg").read_text()
    assert nethealth.cloud_settings(["preserve_hostname: false\nmanage_etc_hosts: true\n", written]) == {
        "preserve_hostname": True, "manage_etc_hosts": False}
    assert "127.0.1.1\tweb1" in (tmp_path / "hosts_file").read_text()


def test_nothing_is_written_without_cloud_init(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path, "", installed=False)
    assert hostname.cloud_init_status()["managed"] is False
    asyncio.run(hostname.set_hostname("web1"))
    assert not (tmp_path / "cloud.cfg.d").exists()
    # already preserved: nothing to do either
    _machine(monkeypatch, tmp_path, "preserve_hostname: true\n")
    assert hostname.cloud_init_status()["managed"] is False
