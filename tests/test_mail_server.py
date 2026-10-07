"""Living alongside a mail server: detection, guards and a shared msmtprc."""

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import mail  # noqa: E402
from linustart.util import CmdResult  # noqa: E402

MAILCOW_PS = """mailcowdockerized-postfix-mailcow-1 ghcr.io/mailcow/postfix:1.80
mailcowdockerized-dovecot-mailcow-1 ghcr.io/mailcow/dovecot:2.3
mailcowdockerized-nginx-mailcow-1 ghcr.io/mailcow/nginx:1.03
"""
SS_DOCKER = 'LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* users:(("docker-proxy",pid=1712,fd=4))\n'

USER_MSMTPRC = """# my own setup
defaults
logfile /var/log/msmtp.log
aliases /etc/aliases

account personal
host smtp.example.org
port 465
tls on
tls_starttls off
user me@example.org
passwordeval "cat /root/.personal"

account default : personal
"""


def test_parsers():
    assert mail.parse_docker_ps(MAILCOW_PS)[0] == (
        "mailcowdockerized-postfix-mailcow-1", "ghcr.io/mailcow/postfix:1.80"
    )
    assert mail.parse_docker_ps("\njunk\n") == []
    assert mail.parse_listener_processes(SS_DOCKER) == ["docker-proxy"]
    assert mail.parse_listener_processes(
        'LISTEN 0 100 127.0.0.1:25 0.0.0.0:* users:(("master",pid=9,fd=13))'
    ) == ["master"]


def test_classify_mail_server():
    mailcow = mail.classify_mail_server(mail.parse_docker_ps(MAILCOW_PS), ["docker-proxy"], [])
    assert mailcow["detected"] and mailcow["kind"] == "mailcow"
    other = mail.classify_mail_server([("mailserver", "docker.io/mailserver/docker-mailserver:14")], [], [])
    assert other["kind"] == "docker"
    assert mail.classify_mail_server([], ["docker-proxy"], [])["kind"] == "docker"
    assert mail.classify_mail_server([], ["master"], ["dovecot"])["kind"] == "host"
    # a web app in Docker and the panel's own loopback Postfix are not mail servers
    plain = mail.classify_mail_server([("web", "nginx:1.27")], ["master"], [])
    assert plain == {"detected": False, "kind": "", "detail": ""}


def test_refusal_and_install_command():
    server = {"detected": True, "kind": "mailcow", "detail": "mailcow containers: x"}
    assert "mail server" in mail.mail_server_refusal(server, "Installing Postfix")
    assert mail.mail_server_refusal({"detected": False}, "Installing Postfix") is None
    assert "--no-remove" in mail.install_command("msmtp", mail_server=True)
    assert "--no-remove" not in mail.install_command("msmtp")
    assert mail.install_command("msmtp", mail_server=True)[-1] == "msmtp-mta"


def test_status_detects_mailcow_without_failing(monkeypatch):
    async def fake_run(argv, **kwargs):
        if argv[0] == "docker":
            return CmdResult(argv, 0, MAILCOW_PS, "")
        return CmdResult(argv, 0, SS_DOCKER, "")

    monkeypatch.setattr(mail, "run", fake_run)
    monkeypatch.setattr(mail.shutil, "which", lambda cmd: "/usr/bin/docker")
    assert asyncio.run(mail.mail_server_status())["kind"] == "mailcow"

    async def broken_run(argv, **kwargs):
        raise RuntimeError("no such command")

    monkeypatch.setattr(mail, "run", broken_run)
    monkeypatch.setattr(mail, "ROOT", pathlib.Path("/nonexistent-root"))
    assert asyncio.run(mail.mail_server_status())["detected"] is False


BLOCK = mail.build_msmtprc("mail.example.com", 587, "starttls", "linustart@example.com", "linustart@example.com")


def test_merge_keeps_the_administrators_msmtprc():
    merged = mail.merge_msmtprc(USER_MSMTPRC, BLOCK)
    assert merged.startswith(USER_MSMTPRC.split("account default")[0].rstrip("\n"))
    assert "logfile /var/log/msmtp.log" in merged and "account personal" in merged
    assert "# disabled by LinuStart, its account is the default: account default : personal" in merged
    assert merged.endswith(BLOCK)
    # the panel's account is what sendmail uses now, the other one still parses
    assert mail.parse_msmtprc(merged)["host"] == "mail.example.com"
    assert mail.parse_msmtprc(merged, "personal")["host"] == "smtp.example.org"
    # saving again replaces the block instead of stacking another one
    again = mail.merge_msmtprc(merged, BLOCK.replace("587", "465"))
    assert again.count(mail.MSMTP_BEGIN) == 1 and "port           465" in again
    assert "logfile /var/log/msmtp.log" in again


def test_merge_takes_over_empty_and_old_panel_files():
    assert mail.merge_msmtprc("", BLOCK) == BLOCK
    old = "# Managed by LinuStart - changes made here are overwritten from the Email page.\ndefaults\n"
    assert mail.merge_msmtprc(old, BLOCK) == BLOCK


def test_merge_refuses_a_foreign_account_with_the_panels_name():
    for line in ("account linustart", "account linustart : personal"):
        with pytest.raises(ValueError):
            mail.merge_msmtprc(USER_MSMTPRC + f"\n{line}\nhost x\n", BLOCK)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(util, "ROOT", tmp_path)
    for name, rel in [("MSMTPRC", "msmtprc"), ("MSMTP_PASSWORD_FILE", "linustart/msmtp-password"),
                      ("MAIL_STATE_FILE", "linustart/mail.json"), ("UNATTENDED_FILE", "50unattended-upgrades"),
                      ("POSTFIX_MAIN_CF", "etc/postfix/main.cf"),
                      ("POSTFIX_SASL_PASSWD", "etc/postfix/sasl_passwd"),
                      ("POSTFIX_SENDER_CANONICAL", "etc/postfix/sender_canonical")]:
        monkeypatch.setattr(mail, name, tmp_path / rel)
    monkeypatch.setattr(mail.shutil, "which", lambda cmd: f"/usr/bin/{cmd}" if cmd == "msmtp" else None)

    async def fake_run(argv, **kwargs):
        return CmdResult(argv, 1, "", "")

    monkeypatch.setattr(mail, "run", fake_run)
    return tmp_path


def test_saving_msmtp_backs_up_and_keeps_the_existing_file(sandbox):
    rc = sandbox / "msmtprc"
    rc.write_text(USER_MSMTPRC, encoding="utf-8")
    asyncio.run(mail.apply(host="mail.example.com", port=587, security="starttls",
                           username="linustart@example.com", from_address="linustart@example.com",
                           password="pw", report_to="ops@example.com", transport="msmtp"))
    text = rc.read_text(encoding="utf-8")
    assert "account personal" in text and mail.MSMTP_BEGIN in text
    backups = list((sandbox / "backups").iterdir())
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == USER_MSMTPRC
