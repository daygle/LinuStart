"""Tests for unattended-upgrades apt.conf editing."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.unattended import (  # noqa: E402
    parse_allowed_origins,
    parse_settings,
    upsert_setting,
)

AUTO = """// Periodic::Update-Package-Lists
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
"""

UNATTENDED = """Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
// Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
"""


def test_parse_settings():
    values = parse_settings(AUTO)
    assert values["APT::Periodic::Update-Package-Lists"] == "1"
    assert values["APT::Periodic::Unattended-Upgrade"] == "1"


def test_parse_settings_ignores_comments():
    values = parse_settings(UNATTENDED)
    # A commented-out line must not count as a setting.
    assert "Unattended-Upgrade::Automatic-Reboot" not in values
    assert values["Unattended-Upgrade::Remove-Unused-Kernel-Packages"] == "true"


def test_upsert_replaces_existing():
    result = upsert_setting(AUTO, "APT::Periodic::Unattended-Upgrade", "0")
    values = parse_settings(result)
    assert values["APT::Periodic::Unattended-Upgrade"] == "0"
    assert values["APT::Periodic::Update-Package-Lists"] == "1"
    assert result.count("APT::Periodic::Unattended-Upgrade") == 1


def test_upsert_appends_missing():
    result = upsert_setting(AUTO, "APT::Periodic::Download-Upgradeable-Packages", "1")
    values = parse_settings(result)
    assert values["APT::Periodic::Download-Upgradeable-Packages"] == "1"
    assert values["APT::Periodic::Unattended-Upgrade"] == "1"


def test_upsert_preserves_comments():
    result = upsert_setting(UNATTENDED, "Unattended-Upgrade::Remove-Unused-Kernel-Packages", "false")
    assert "// Unattended-Upgrade::Automatic-Reboot" in result
    assert parse_settings(result)["Unattended-Upgrade::Remove-Unused-Kernel-Packages"] == "false"


def test_parse_allowed_origins():
    origins = parse_allowed_origins(UNATTENDED)
    assert origins == [
        "${distro_id}:${distro_codename}",
        "${distro_id}:${distro_codename}-security",
    ]


def test_parse_allowed_origins_missing():
    assert parse_allowed_origins(AUTO) == []


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all unattended tests passed")
