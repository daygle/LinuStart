"""Tests for unattended-upgrades report wiring (Mail / MailReport / Sender)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.mail import resolve_report_target  # noqa: E402
from linustart.modules.unattended import base_config, parse_settings  # noqa: E402


def test_resolve_report_target_prefers_explicit_recipient():
    assert resolve_report_target("admin@example.com", "sender@example.com") == "admin@example.com"


def test_resolve_report_target_falls_back_to_from_address():
    assert resolve_report_target("", "sender@example.com") == "sender@example.com"
    assert resolve_report_target("   ", "sender@example.com") == "sender@example.com"


def test_resolve_report_target_accepts_local_names():
    assert resolve_report_target("root", "sender@example.com") == "root"
    assert resolve_report_target("postmaster", "") == "postmaster"


def test_resolve_report_target_rejects_bad_input():
    for bad in [
        ("bad@", "sender@example.com"),
        ("has space", "sender@example.com"),
        ("me@example", "sender@example.com"),
        ('bad;name', "sender@example.com"),
    ]:
        try:
            resolve_report_target(*bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")
    try:
        resolve_report_target("", "")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError with no recipient and no from address")


def test_base_config_is_parseable():
    conf = base_config()
    settings = parse_settings(conf)
    assert "Unattended-Upgrade::Allowed-Origins" in conf
    assert "${distro_id}:${distro_codename}-security" in conf
    # the base config must not pre-decide where reports go
    assert "Unattended-Upgrade::Mail" not in settings
    assert "Unattended-Upgrade::MailReport" not in settings


def test_report_keys_survive_upsert_round_trip():
    from linustart.modules.unattended import upsert_setting

    conf = base_config()
    conf = upsert_setting(conf, "Unattended-Upgrade::Mail", "admin@example.com")
    conf = upsert_setting(conf, "Unattended-Upgrade::MailReport", "only-on-error")
    conf = upsert_setting(conf, "Unattended-Upgrade::Sender", "sender@example.com")
    settings = parse_settings(conf)
    assert settings["Unattended-Upgrade::Mail"] == "admin@example.com"
    assert settings["Unattended-Upgrade::MailReport"] == "only-on-error"
    assert settings["Unattended-Upgrade::Sender"] == "sender@example.com"
    # upsert replaces instead of duplicating
    conf = upsert_setting(conf, "Unattended-Upgrade::Mail", "other@example.com")
    assert parse_settings(conf)["Unattended-Upgrade::Mail"] == "other@example.com"
    assert conf.count("Unattended-Upgrade::Mail ") == 1


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all report tests passed")
