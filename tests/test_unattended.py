"""Tests for unattended-upgrades apt.conf editing."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.unattended import (  # noqa: E402
    BLACKLIST_KEY,
    ORIGINS_PATTERN_KEY,
    ORIGINS_KEY,
    origins_state,
    parse_allowed_origins,
    parse_block_list,
    parse_settings,
    remove_block,
    upsert_block_list,
    upsert_setting,
    valid_block_entry,
    valid_days,
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


# The canonical template this panel must be able to reproduce, verbatim.
TEMPLATE_AUTO = """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
// AutocleanInterval 7 = run `apt-get autoclean` weekly to trim the .deb cache.
APT::Periodic::AutocleanInterval "7";
"""

TEMPLATE_UNATTENDED = """// Debian archives only - third-party/vendor repos are never auto-upgraded.
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename}-updates";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};

Unattended-Upgrade::Package-Blacklist {
};

// Email only when an upgrade fails ("always" and "on-change" are louder).
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "only-on-error";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
// Reboot automatically, but only when an update requires it, at this local time.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
// Reboot even if a user is logged in (default true; false skips the reboot).
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
"""

TEMPLATE_ORIGINS = [
    "origin=Debian,codename=${distro_codename},label=Debian",
    "origin=Debian,codename=${distro_codename}-updates",
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
]


def test_template_parses_completely():
    auto = parse_settings(TEMPLATE_AUTO)
    assert auto["APT::Periodic::Update-Package-Lists"] == "1"
    assert auto["APT::Periodic::Download-Upgradeable-Packages"] == "1"
    assert auto["APT::Periodic::Unattended-Upgrade"] == "1"
    assert auto["APT::Periodic::AutocleanInterval"] == "7"
    conf = parse_settings(TEMPLATE_UNATTENDED)
    assert conf["Unattended-Upgrade::Mail"] == "root"
    assert conf["Unattended-Upgrade::MailReport"] == "only-on-error"
    assert conf["Unattended-Upgrade::Remove-Unused-Kernel-Packages"] == "true"
    assert conf["Unattended-Upgrade::Remove-New-Unused-Dependencies"] == "true"
    assert conf["Unattended-Upgrade::Remove-Unused-Dependencies"] == "false"
    assert conf["Unattended-Upgrade::Automatic-Reboot"] == "true"
    assert conf["Unattended-Upgrade::Automatic-Reboot-Time"] == "03:00"
    assert conf["Unattended-Upgrade::Automatic-Reboot-WithUsers"] == "true"
    assert conf["Unattended-Upgrade::AutoFixInterruptedDpkg"] == "true"
    assert parse_block_list(TEMPLATE_UNATTENDED, ORIGINS_PATTERN_KEY) == TEMPLATE_ORIGINS
    assert parse_block_list(TEMPLATE_UNATTENDED, BLACKLIST_KEY) == []


def test_parse_block_list_pattern_vs_allowed():
    assert parse_block_list(UNATTENDED, ORIGINS_KEY) == parse_allowed_origins(UNATTENDED)
    assert parse_block_list(UNATTENDED, ORIGINS_PATTERN_KEY) == []


def test_upsert_block_list_appends_and_replaces():
    text = upsert_block_list("// keep me\n", ORIGINS_PATTERN_KEY, TEMPLATE_ORIGINS)
    assert "// keep me" in text
    assert parse_block_list(text, ORIGINS_PATTERN_KEY) == TEMPLATE_ORIGINS
    replaced = upsert_block_list(text, ORIGINS_PATTERN_KEY, ["origin=Debian"])
    assert parse_block_list(replaced, ORIGINS_PATTERN_KEY) == ["origin=Debian"]
    assert replaced.count(ORIGINS_PATTERN_KEY) == 1


def test_upsert_block_list_empty_block():
    text = upsert_block_list("", BLACKLIST_KEY, [])
    assert parse_block_list(text, BLACKLIST_KEY) == []
    text = upsert_block_list(text, BLACKLIST_KEY, ["linux-image-generic"])
    assert parse_block_list(text, BLACKLIST_KEY) == ["linux-image-generic"]


def test_upsert_block_list_preserves_comments_and_other_settings():
    text = upsert_block_list(TEMPLATE_UNATTENDED, ORIGINS_PATTERN_KEY, ["origin=Debian"])
    assert "// Debian archives only" in text
    assert "// Reboot automatically" in text
    assert parse_settings(text)["Unattended-Upgrade::Automatic-Reboot-Time"] == "03:00"


def test_upsert_block_list_rejects_syntax_in_entries():
    for bad in ['a"b', "a;b", "a\\b", "a\nb"]:
        try:
            upsert_block_list("", ORIGINS_PATTERN_KEY, [bad])
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")
    # blank lines are skipped, not rejected
    assert parse_block_list(upsert_block_list("", ORIGINS_PATTERN_KEY, ["", " "]), ORIGINS_PATTERN_KEY) == []


def test_remove_block_switches_origins_style():
    text = upsert_block_list(TEMPLATE_UNATTENDED, ORIGINS_KEY, ["${distro_id}:${distro_codename}"])
    style, entries = origins_state(text)
    assert style == "pattern"  # pattern wins while both exist
    text = remove_block(text, ORIGINS_PATTERN_KEY)
    style, entries = origins_state(text)
    assert style == "allowed"
    assert entries == ["${distro_id}:${distro_codename}"]
    assert ORIGINS_PATTERN_KEY not in text


def test_origins_state_defaults_to_pattern():
    assert origins_state("") == ("pattern", [])
    assert origins_state(TEMPLATE_UNATTENDED) == ("pattern", TEMPLATE_ORIGINS)


def test_valid_block_entry():
    assert valid_block_entry("origin=Debian,codename=${distro_codename},label=Debian")
    assert valid_block_entry("linux-image-generic")
    assert not valid_block_entry('bad"entry')
    assert not valid_block_entry("bad;entry")


def test_valid_days():
    assert valid_days("0") and valid_days("7") and valid_days("365")
    assert not valid_days("-1") and not valid_days("1.5") and not valid_days("abc") and not valid_days("400")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all unattended tests passed")
