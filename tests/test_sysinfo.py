"""Tests for distro family detection."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.sysinfo import distro_info  # noqa: E402


def test_ubuntu():
    assert distro_info({"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04"})["family"] == "ubuntu"


def test_debian():
    assert distro_info({"ID": "debian"})["family"] == "debian"


def test_mint_is_ubuntu_family():
    info = distro_info({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"})
    assert info["family"] == "ubuntu"
    assert info["id"] == "linuxmint"


def test_raspbian_is_debian_family():
    assert distro_info({"ID": "raspbian", "ID_LIKE": "debian"})["family"] == "debian"


def test_pop_is_ubuntu_family():
    assert distro_info({"ID": "pop", "ID_LIKE": "ubuntu debian"})["family"] == "ubuntu"


def test_unknown_family():
    info = distro_info({"ID": "arch", "PRETTY_NAME": "Arch Linux"})
    assert info["family"] == "unknown"
    assert info["pretty"] == "Arch Linux"


def test_missing_fields_are_safe():
    info = distro_info({})
    assert info["family"] == "unknown"
    assert info["id"] == ""


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all sysinfo tests passed")
