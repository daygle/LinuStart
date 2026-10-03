"""Tests for importing existing msmtp configurations."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.mail import (  # noqa: E402
    msmtp_import_settings,
    msmtp_password_path,
    parse_msmtprc,
)

# A real-world msmtp setup: defaults block, one account, default alias.
MSMTPRC = """# /etc/msmtprc

defaults
auth           on
tls            on
tls_starttls   on
logfile        /var/log/msmtp.log

account        mailer
host           mail.daygle.net
port           587
set_from_header on
from           notifications@daygle.net
user           notifications@daygle.net
passwordeval   "cat /etc/msmtp-password"

account default : mailer
"""


def test_parse_msmtprc_default_account():
    config = parse_msmtprc(MSMTPRC)
    assert config["host"] == "mail.daygle.net"
    assert config["port"] == "587"
    assert config["user"] == "notifications@daygle.net"
    assert config["from"] == "notifications@daygle.net"
    assert config["auth"] == "on"
    assert config["tls"] == "on"
    assert config["tls_starttls"] == "on"


def test_parse_msmtprc_quoted_values():
    config = parse_msmtprc(MSMTPRC)
    assert config["passwordeval"] == "cat /etc/msmtp-password"


def test_parse_msmtprc_explicit_account_selection():
    text = MSMTPRC + "\naccount backup\nhost other.example.com\nport 25\n"
    assert parse_msmtprc(text, account="backup")["host"] == "other.example.com"
    assert parse_msmtprc(text)["host"] == "mail.daygle.net"  # default alias wins


def test_parse_msmtprc_defaults_merge():
    config = parse_msmtprc(MSMTPRC)
    assert config["tls"] == "on"  # inherited from defaults
    assert config["host"] == "mail.daygle.net"  # from the account section


def test_parse_msmtprc_single_account_without_alias():
    text = "account only\nhost one.example.com\nport 465\ntls on\ntls_starttls off\n"
    config = parse_msmtprc(text)
    assert config["host"] == "one.example.com"


def test_msmtp_import_settings_starttls():
    fields = msmtp_import_settings(parse_msmtprc(MSMTPRC))
    assert fields == {
        "host": "mail.daygle.net",
        "port": 587,
        "security": "starttls",
        "username": "notifications@daygle.net",
        "from_address": "notifications@daygle.net",
    }


def test_msmtp_import_settings_ssl_and_plain():
    assert msmtp_import_settings({"tls": "on", "tls_starttls": "off"})["security"] == "ssl"
    assert msmtp_import_settings({"tls": "off", "tls_starttls": "off"})["security"] == "none"
    assert msmtp_import_settings({"port": "not-a-port"})["port"] == 587


def test_msmtp_password_path():
    assert msmtp_password_path(parse_msmtprc(MSMTPRC)) == "/etc/msmtp-password"
    assert msmtp_password_path({"passwordeval": "gpg -d /etc/pass.gpg"}) == ""
    assert msmtp_password_path({"passwordeval": "cat relative/path"}) == ""
    assert msmtp_password_path({}) == ""


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all msmtp tests passed")
