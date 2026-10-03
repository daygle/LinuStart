"""Mail delivery: Postfix configured as an SMTP relay (smarthost) that sends
through your own mail server, from an address hosted there.

Managed pieces:
  * /etc/postfix/main.cf          - relayhost, TLS, SASL, myorigin (key = value)
  * /etc/postfix/sasl_passwd      - "[mail.example.com]:587 user@domain:password"
  * /etc/linustart/mail.json      - panel state (never the password)
  * unattended-upgrades Mail      - notification recipient

Pure helpers operate on strings/dicts so they can be tested without root.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from typing import Dict, Optional

from ..paths import (
    MAIL_STATE_FILE,
    POSTFIX_MAIN_CF,
    POSTFIX_SASL_DB,
    POSTFIX_SASL_PASSWD,
    UNATTENDED_FILE,
)
from ..util import read_text, run, write_text

from .hostname import valid_hostname

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAIN_CF_LINE_RE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.*)$")

SECURITIES = ("starttls", "ssl", "none")
REPORT_MODES = ("always", "only-on-error", "on-change")

SASL_PASSWD_MODE = 0o600


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def valid_email(address: str) -> bool:
    return bool(EMAIL_RE.match(address.strip()))


def valid_host(host: str) -> bool:
    """RFC 1123 name or IPv4 literal - rejects empty labels like 'mail..example'."""
    return valid_hostname(host)


def valid_port(port: int) -> bool:
    return isinstance(port, int) and 1 <= port <= 65535


# --------------------------------------------------------------------------
# Postfix main.cf (key = value format)
# --------------------------------------------------------------------------

def parse_main_cf(text: str) -> Dict[str, str]:
    """Parse main.cf settings (comments and continuation lines ignored)."""
    settings: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():  # continuation of the previous key
            continue
        match = MAIN_CF_LINE_RE.match(line)
        if match:
            settings[match.group("key")] = match.group("value").strip()
    return settings


def upsert_main_cf(text: str, key: str, value: str) -> str:
    """Replace or append `key = value`, preserving comments."""
    new_line = f"{key} = {value}"
    lines = text.splitlines()
    pattern = re.compile(rf"^{re.escape(key)}\s*=")
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = new_line
            return "\n".join(lines) + ("\n" if text.endswith("\n") or lines else "")
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(new_line)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# SASL password map
# --------------------------------------------------------------------------

def format_relayhost(host: str, port: int) -> str:
    """`mail.example.com` + 587 -> `[mail.example.com]:587`."""
    return f"[{host.strip()}]:{int(port)}"


def sasl_line(location: str, username: str, password: str) -> str:
    """One sasl_passwd entry: `location user:password`."""
    return f"{location} {username}:{password}"


def parse_sasl_line(line: str) -> Dict[str, str]:
    """Extract location and username (never the password) from an entry."""
    parts = line.strip().split(None, 1)
    if len(parts) < 2:
        return {"location": parts[0] if parts else "", "username": ""}
    location, credentials = parts[0], parts[1]
    username = credentials.split(":", 1)[0]
    return {"location": location, "username": username}


def merge_sasl_line(
    existing_text: str, location: str, username: str, password: Optional[str]
) -> str:
    """Build the new sasl_passwd content.

    An empty *password* keeps the previously stored password for the same
    location, so the UI can leave the field blank to change nothing.
    """
    if not password:
        for line in existing_text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            stored = parse_sasl_line(line)
            if stored["location"] == location:
                credentials = line.strip().split(None, 1)[1]
                password = credentials.split(":", 1)[1] if ":" in credentials else ""
                break
    if not password:
        raise ValueError("a password is required for a new SMTP account")
    return sasl_line(location, username, password) + "\n"


# --------------------------------------------------------------------------
# Relay settings
# --------------------------------------------------------------------------

def relay_settings(host: str, port: int, security: str, from_address: str) -> Dict[str, str]:
    """The main.cf keys that turn Postfix into an authenticated smarthost."""
    if security not in SECURITIES:
        raise ValueError(f"security must be one of {SECURITIES}")
    domain = from_address.rsplit("@", 1)[1] if "@" in from_address else from_address
    return {
        "relayhost": format_relayhost(host, port),
        "myorigin": domain,
        "inet_interfaces": "loopback-only",
        "smtp_sasl_auth_enable": "yes",
        "smtp_sasl_password_maps": "hash:/etc/postfix/sasl_passwd",
        "smtp_sasl_security_options": "noanonymous",
        "smtp_sasl_tls_security_options": "noanonymous",
        "smtp_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
        "smtp_tls_security_level": "may" if security == "none" else "encrypt",
        "smtp_tls_wrappermode": "yes" if security == "ssl" else "no",
    }


# --------------------------------------------------------------------------
# IO helpers
# --------------------------------------------------------------------------

def installed() -> bool:
    """Is Postfix available? (Not installed by default on minimal servers.)"""
    return shutil.which("postmap") is not None or POSTFIX_MAIN_CF.exists()


async def service_active() -> bool:
    result = await run(["systemctl", "is-active", "--quiet", "postfix"])
    return result.ok


def _read_state() -> Dict[str, object]:
    try:
        data = json.loads(MAIL_STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


async def status() -> Dict[str, object]:
    state = _read_state()
    main_cf = parse_main_cf(read_text(POSTFIX_MAIN_CF))
    sasl_exists = bool(read_text(POSTFIX_SASL_PASSWD).strip())
    return {
        "installed": installed(),
        "service_active": await service_active(),
        "host": state.get("host", ""),
        "port": state.get("port", 587),
        "security": state.get("security", "starttls"),
        "username": state.get("username", ""),
        "from_address": state.get("from_address", ""),
        "report_to": state.get("report_to", ""),
        "report_mode": state.get("report_mode", "only-on-error"),
        "credentials_set": sasl_exists,
        "relayhost": main_cf.get("relayhost", ""),
        "myorigin": main_cf.get("myorigin", ""),
        "securities": list(SECURITIES),
        "report_modes": list(REPORT_MODES),
    }


async def apply(
    host: str,
    port: int,
    security: str,
    username: str,
    from_address: str,
    password: Optional[str] = None,
    report_to: str = "",
    report_mode: str = "only-on-error",
) -> Dict[str, object]:
    """Write the relay configuration and reload Postfix."""
    host = host.strip()
    username = username.strip()
    from_address = from_address.strip()
    report_to = report_to.strip()
    if not valid_host(host):
        raise ValueError(f"invalid SMTP server: {host!r}")
    if not valid_port(port):
        raise ValueError(f"invalid port: {port!r}")
    if not username:
        raise ValueError("an SMTP username is required")
    if not valid_email(from_address):
        raise ValueError(f"invalid from address: {from_address!r}")
    if report_to and not valid_email(report_to):
        raise ValueError(f"invalid report recipient: {report_to!r}")
    if report_mode not in REPORT_MODES:
        raise ValueError(f"report_mode must be one of {REPORT_MODES}")
    if not installed():
        raise RuntimeError("postfix is not installed")

    location = format_relayhost(host, port)
    existing = read_text(POSTFIX_SASL_PASSWD)
    line = merge_sasl_line(existing, location, username, password)
    write_text(POSTFIX_SASL_PASSWD, line)
    os.chmod(POSTFIX_SASL_PASSWD, SASL_PASSWD_MODE)
    await run(["postmap", "hash:/etc/postfix/sasl_passwd"], check=True)

    main_cf = read_text(POSTFIX_MAIN_CF)
    for key, value in relay_settings(host, port, security, from_address).items():
        main_cf = upsert_main_cf(main_cf, key, value)
    write_text(POSTFIX_MAIN_CF, main_cf)

    state = {
        "host": host,
        "port": port,
        "security": security,
        "username": username,
        "from_address": from_address,
        "report_to": report_to,
        "report_mode": report_mode,
    }
    write_text(MAIL_STATE_FILE, json.dumps(state, indent=2) + "\n")

    # Wire unattended-upgrades notifications to the same mailbox.
    unattended = read_text(UNATTENDED_FILE)
    if unattended:
        from . import unattended as unattended_mod

        unattended = unattended_mod.upsert_setting(
            unattended, "Unattended-Upgrade::Mail", report_to
        )
        unattended = unattended_mod.upsert_setting(
            unattended, "Unattended-Upgrade::MailReport", report_mode
        )
        write_text(UNATTENDED_FILE, unattended)

    await run(["systemctl", "reload", "postfix"], check=True)
    return await status()


def test_command(from_address: str, recipient: str) -> list:
    """Queue a test message through the whole local Postfix pipeline."""
    argv = ["sendmail", "-i"]
    if from_address:
        argv += ["-f", from_address]
    argv.append(recipient)
    return argv


def test_message(recipient: str) -> str:
    return (
        "From: LinuStart\n"
        f"To: {recipient}\n"
        "Subject: LinuStart test email\n"
        "\n"
        "This is a test message sent by LinuStart through your SMTP relay.\n"
        "If you can read this, the server can deliver mail.\n"
    )


async def preseed_postfix() -> None:
    """Answer debconf so `apt-get install postfix` stays non-interactive."""
    await run(
        ["debconf-set-selections"],
        input_text=(
            "postfix postfix/main_mailer_type select Satellite system\n"
            "postfix postfix/mailname string localhost\n"
            "postfix postfix/destinations string\n"
        ),
        check=True,
    )
