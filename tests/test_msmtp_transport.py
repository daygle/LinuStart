"""msmtp as the delivery transport."""

import asyncio
import pathlib
import stat
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import mail  # noqa: E402
from linustart.util import CmdResult  # noqa: E402


def test_msmtprc_pins_the_envelope_and_keeps_the_password_out():
    text = mail.build_msmtprc("mail.example.com", 465, "ssl", "relay", "alerts@example.com")
    config = mail.parse_msmtprc(text)
    assert config["host"] == "mail.example.com" and config["port"] == "465"
    assert config["from"] == "relay@example.com"  # the login completed with the from domain
    assert config["tls"] == "on" and config["tls_starttls"] == "off"
    assert "password " not in text and 'passwordeval   "cat /etc/linustart/msmtp-password"' in text
    # and the panel can read its own file back for the form
    assert mail.msmtp_import_settings(config)["security"] == "ssl"


def test_conflicts_depend_on_the_transport():
    installed = ["postfix", "msmtp-mta", "exim4", "bsd-mailx"]
    assert mail.conflicting_mailers(installed, "postfix") == ["exim4", "msmtp-mta"]
    assert mail.conflicting_mailers(installed, "msmtp") == ["exim4", "postfix"]
    assert mail.remove_conflicting_command(["postfix"], "msmtp") == ["apt-get", "remove", "-y", "postfix"]
    for bad, transport in [(["msmtp-mta"], "msmtp"), (["postfix"], "postfix"), (["bsd-mailx"], "msmtp")]:
        with pytest.raises(ValueError):
            mail.remove_conflicting_command(bad, transport)


def test_msmtp_test_send_leaves_the_envelope_to_the_config():
    assert mail.test_command("a@example.com", "b@example.com", "msmtp") == ["sendmail", "-i", "b@example.com"]
    assert "-f" in mail.test_command("a@example.com", "b@example.com", "postfix")


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    for name, rel in [("MSMTPRC", "msmtprc"), ("MSMTP_PASSWORD_FILE", "linustart/msmtp-password"),
                      ("MAIL_STATE_FILE", "linustart/mail.json"), ("UNATTENDED_FILE", "50unattended-upgrades"),
                      ("POSTFIX_SASL_PASSWD", "postfix/sasl_passwd"), ("POSTFIX_MAIN_CF", "postfix/main.cf"),
                      ("POSTFIX_SENDER_CANONICAL", "postfix/sender_canonical")]:
        monkeypatch.setattr(mail, name, tmp_path / rel)
    monkeypatch.setattr(mail.shutil, "which", lambda cmd: f"/usr/bin/{cmd}" if cmd == "msmtp" else None)

    async def fake_run(argv, **kwargs):
        return CmdResult(argv, 1, "", "")

    monkeypatch.setattr(mail, "run", fake_run)
    return tmp_path


def apply_msmtp(**overrides):
    args = dict(host="mail.example.com", port=587, security="starttls", username="relay@example.com",
                from_address="alerts@example.com", password="s3cret pass", report_to="ops@example.com",
                transport="msmtp")
    args.update(overrides)
    return asyncio.run(mail.apply(**args))


def test_apply_msmtp_writes_root_only_files(sandbox):
    result = apply_msmtp()
    rc, secret = sandbox / "msmtprc", sandbox / "linustart" / "msmtp-password"
    assert secret.read_text() == "s3cret pass\n"
    assert stat.S_IMODE(rc.stat().st_mode) == 0o600 and stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert result["transport"] == "msmtp" and result["relayhost"] == "mail.example.com:587"
    assert result["credentials_set"] and result["service_active"] is None
    assert 'Unattended-Upgrade::Mail "ops@example.com";' in (sandbox / "50unattended-upgrades").read_text()
    # a later save without a password keeps the stored one
    apply_msmtp(password=None, port=465, security="ssl")
    assert secret.read_text() == "s3cret pass\n"


def test_msmtp_needs_a_real_report_address(sandbox):
    with pytest.raises(ValueError):
        apply_msmtp(report_to="root")


def test_msmtp_must_be_installed(sandbox, monkeypatch):
    monkeypatch.setattr(mail.shutil, "which", lambda cmd: None)
    with pytest.raises(RuntimeError):
        apply_msmtp()
