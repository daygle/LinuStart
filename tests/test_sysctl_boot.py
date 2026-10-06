"""Which sysctl file wins at boot, and /etc/sysctl.conf without its link."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import sysctl  # noqa: E402


@pytest.fixture
def machine(tmp_path, monkeypatch):
    etc_d = tmp_path / "etc" / "sysctl.d"
    usr_d = tmp_path / "usr" / "lib" / "sysctl.d"
    etc_d.mkdir(parents=True)
    usr_d.mkdir(parents=True)
    monkeypatch.setattr(sysctl, "ROOT", tmp_path)
    monkeypatch.setattr(sysctl, "SYSCTL_D", etc_d)
    monkeypatch.setattr(sysctl, "SYSCTL_CONF", tmp_path / "etc" / "sysctl.conf")
    monkeypatch.setattr(sysctl, "SYSTEM_SYSCTL_DIRS", [usr_d])
    monkeypatch.setattr(sysctl, "PROC_SYS", tmp_path / "proc")
    return tmp_path, etc_d, usr_d


def test_later_files_win_and_etc_masks_usr(machine):
    _root, etc_d, usr_d = machine
    (usr_d / "10-network.conf").write_text("net.ipv4.ip_forward = 0\n")
    (usr_d / "99-zz-vendor.conf").write_text("vm.swappiness = 60\n")
    (etc_d / "99-linustart.conf").write_text("vm.swappiness = 10\nnet.ipv4.ip_forward = 1\n")
    # a same-named file in /etc masks the vendor one entirely
    (usr_d / "50-masked.conf").write_text("fs.file-max = 1\n")
    (etc_d / "50-masked.conf").write_text("")
    files = sysctl.boot_files()
    assert [p.name for p in files] == ["10-network.conf", "50-masked.conf", "99-linustart.conf", "99-zz-vendor.conf"]
    assert files[1].parent == etc_d
    winners = sysctl.precedence()["winners"]
    assert winners["vm.swappiness"] == ("/usr/lib/sysctl.d/99-zz-vendor.conf", "60")
    assert winners["net.ipv4.ip_forward"] == ("/etc/sysctl.d/99-linustart.conf", "1")
    assert "fs.file-max" not in winners
    listed = sysctl.list_files()
    panel = next(f for f in listed["files"] if f["path"] == "/etc/sysctl.d/99-linustart.conf")
    swappiness = next(e for e in panel["entries"] if e["key"] == "vm.swappiness")
    assert swappiness["overridden_by"] == {"file": "/usr/lib/sysctl.d/99-zz-vendor.conf", "value": "60"}
    assert "overridden_by" not in next(e for e in panel["entries"] if e["key"] == "net.ipv4.ip_forward")


def test_sysctl_conf_needs_its_link_to_apply_at_boot(machine):
    root, etc_d, _usr = machine
    (root / "etc" / "sysctl.conf").write_text("vm.swappiness = 5\n")
    listed = sysctl.list_files()
    assert [f["id"] for f in listed["findings"]] == ["sysctl-conf-boot"]
    assert listed["findings"][0]["fix"]["endpoint"] == "/sysctl/fix/sysctl-conf-boot"
    assert sysctl.link_sysctl_conf() == "/etc/sysctl.d/99-sysctl.conf"
    assert (etc_d / "99-sysctl.conf").resolve() == (root / "etc" / "sysctl.conf").resolve()
    order = sysctl.precedence()
    assert order["sysctl_conf_at_boot"] and order["winners"]["vm.swappiness"] == ("/etc/sysctl.conf", "5")
    assert sysctl.list_files()["findings"] == []
    with pytest.raises(ValueError):
        sysctl.link_sysctl_conf()


def test_an_empty_sysctl_conf_is_not_a_problem(machine):
    root, _etc_d, _usr = machine
    (root / "etc" / "sysctl.conf").write_text("# nothing here\n")
    assert sysctl.list_files()["findings"] == []
