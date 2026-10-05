"""Mail delivery: Postfix configured as an SMTP relay (smarthost) that sends
through your own mail server, from an address hosted there.

Managed pieces:
  * /etc/postfix/main.cf          - relayhost, TLS, SASL, myorigin (key = value)
  * /etc/postfix/sasl_passwd      - "[mail.example.com]:587 user@domain:password"
  * /etc/postfix/sender_canonical - "@domain relay@domain": envelope sender only
  * /etc/linustart/mail.json      - panel state (never the password)
  * unattended-upgrades Mail      - notification recipient

Pure helpers operate on strings/dicts so they can be tested without root.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import PurePosixPath
from typing import Dict, List, Mapping, Optional, Sequence

from ..paths import (
    MAIL_STATE_FILE,
    MSMTP_PASSWORD_FILE,
    MSMTPRC,
    POSTFIX_MAIN_CF,
    POSTFIX_SASL_PASSWD,
    POSTFIX_SENDER_CANONICAL,
    ROOT,
    UNATTENDED_FILE,
)
from ..util import read_text, run, write_text

from .hostname import valid_hostname

# The local part may not start with '-': recipients are passed to sendmail
# as arguments, and a leading dash would be read as an option.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
# Local mailbox names ("root", "postmaster") are valid unattended-upgrades
# recipients - the report is delivered on the box itself.
LOCAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}$")
MAIN_CF_LINE_RE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.*)$")

SECURITIES = ("starttls", "ssl", "none")
# Postfix: a local relay daemon with a queue. msmtp: a sendmail replacement
# that hands each message straight to the relay (no queue, no daemon).
TRANSPORTS = ("postfix", "msmtp")
TRANSPORT_PACKAGE = {"postfix": "postfix", "msmtp": "msmtp-mta"}
MSMTP_PASSWORD_MODE = 0o600
MSMTPRC_MODE = 0o600
REPORT_MODES = ("always", "only-on-error", "on-change")


# --------------------------------------------------------------------------
# Unattended-upgrades report settings
# --------------------------------------------------------------------------

def resolve_report_target(report_to: str, from_address: str = "") -> str:
    """Where unattended-upgrades reports go.

    An empty recipient falls back to the relay's from address so reports work
    out of the box instead of silently being disabled.
    """
    target = (report_to or "").strip()
    if target:
        if not valid_recipient(target):
            raise ValueError(f"invalid report recipient: {target!r}")
        return target
    fallback = (from_address or "").strip()
    if valid_email(fallback):
        return fallback
    raise ValueError("a report recipient is required (set one here or a from address first)")

SASL_PASSWD_MODE = 0o600


# --------------------------------------------------------------------------
# Mail transfer agents: detect conflicting MTAs
# --------------------------------------------------------------------------

# kind "mta" packages provide sendmail and conflict with each other;
# kind "client" packages (plain msmtp, mailx) are harmless and left alone.
MAILER_PACKAGES: Dict[str, Dict[str, object]] = {
    "postfix": {"label": "Postfix", "kind": "mta", "supported": True},
    "msmtp-mta": {"label": "msmtp sendmail compatibility", "kind": "mta", "supported": False},
    "ssmtp": {"label": "sSMTP", "kind": "mta", "supported": False},
    "nullmailer": {"label": "Nullmailer", "kind": "mta", "supported": False},
    "exim4": {"label": "Exim4", "kind": "mta", "supported": False},
    "exim4-base": {"label": "Exim4 base", "kind": "mta", "supported": False},
    "exim4-daemon-heavy": {"label": "Exim4 daemon (heavy)", "kind": "mta", "supported": False},
    "exim4-daemon-light": {"label": "Exim4 daemon (light)", "kind": "mta", "supported": False},
    "sendmail-bin": {"label": "Sendmail", "kind": "mta", "supported": False},
    "dma": {"label": "Dragonfly Mail Agent", "kind": "mta", "supported": False},
    "msmtp": {"label": "msmtp client", "kind": "client", "supported": False},
    "bsd-mailx": {"label": "bsd-mailx", "kind": "client", "supported": False},
    "mailutils": {"label": "GNU mailutils", "kind": "client", "supported": False},
}
SENDMAIL_PROVIDERS = ("postfix", "msmtp", "ssmtp", "nullmailer", "exim", "sendmail", "dma")


def classify_sendmail_target(target: str) -> str:
    """Which package's sendmail is at the end of this path (by symlink target)."""
    lowered = (target or "").lower()
    for provider in SENDMAIL_PROVIDERS:
        if provider in lowered:
            return provider
    return "unknown" if lowered else "none"


def parse_dpkg_status(text: str) -> List[str]:
    """Installed package names from `dpkg-query -W -f='${Package} ${Status}'`."""
    installed: List[str] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[1] == "install ok installed":
            installed.append(parts[0])
    return installed


def known_mailers(installed: Sequence[str]) -> List[str]:
    return sorted(set(installed) & set(MAILER_PACKAGES))


def valid_transport(transport: str) -> str:
    if transport not in TRANSPORTS:
        raise ValueError(f"transport must be one of {TRANSPORTS}")
    return transport


def conflicting_mailers(installed: Sequence[str], transport: str = "postfix") -> List[str]:
    """Installed MTAs that compete with the chosen transport for the sendmail role."""
    own = TRANSPORT_PACKAGE[valid_transport(transport)]
    return [
        name
        for name in known_mailers(installed)
        if MAILER_PACKAGES[name]["kind"] == "mta" and name != own
    ]


def remove_conflicting_command(packages: Sequence[str], transport: str = "postfix") -> List[str]:
    """argv to remove conflicting MTAs (allowlisted names only, configs kept)."""
    own = TRANSPORT_PACKAGE[valid_transport(transport)]
    names = sorted(set(packages))
    if not names:
        raise ValueError("no conflicting mailers to remove")
    for name in names:
        if name not in MAILER_PACKAGES or MAILER_PACKAGES[name]["kind"] != "mta" or name == own:
            raise ValueError(f"refusing to remove {name!r}")
    return ["apt-get", "remove", "-y"] + names


async def installed_mailers() -> List[str]:
    try:
        result = await run(["dpkg-query", "-W", "-f=${Package} ${Status}\\n"])
    except RuntimeError:
        return []
    return known_mailers(parse_dpkg_status(result.stdout))


async def mailer_status(transport: Optional[str] = None) -> Dict[str, object]:
    """What handles sendmail on this system, and what conflicts with the transport."""
    transport = transport or current_transport()
    installed = await installed_mailers()
    sendmail = shutil.which("sendmail")
    return {
        "packages": installed,
        "transport": transport,
        "conflicts": conflicting_mailers(installed, transport),
        "sendmail": sendmail or "",
        "sendmail_provider": classify_sendmail_target(os.path.realpath(sendmail)) if sendmail else "none",
        "msmtp_client": "msmtp" in installed,
    }


# --------------------------------------------------------------------------
# msmtp import (existing setups get adopted, not bulldozed)
# --------------------------------------------------------------------------

MSMTP_KEYS = ("host", "port", "user", "from", "auth", "tls", "tls_starttls", "passwordeval", "password")


def parse_msmtprc(text: str, account: Optional[str] = None) -> Dict[str, str]:
    """Effective settings for one msmtp account (``defaults`` merged in).

    Understands ``defaults``, ``account NAME`` sections and the
    ``account default : NAME`` alias used to pick the default account.
    """
    sections: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    default_name: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "defaults":
            current = "defaults"
            sections.setdefault(current, {})
        elif key == "account":
            words = value.replace(":", " ").split()
            if words and words[0].lower() == "default":
                default_name = words[1] if len(words) > 1 else None
                current = None  # an alias line, not a section
            else:
                current = value or None
                if current:
                    sections.setdefault(current, {})
        elif current is not None:
            sections[current][key] = value.strip().strip('"')
    name = account or default_name
    if name is None:
        candidates = [key for key in sections if key != "defaults"]
        name = candidates[0] if len(candidates) == 1 else "defaults"
    effective = {**sections.get("defaults", {}), **sections.get(name, {})}
    return {key: effective[key] for key in MSMTP_KEYS if key in effective}


def msmtp_import_settings(config: Mapping[str, str]) -> Dict[str, object]:
    """Map msmtp settings onto the panel's relay fields."""
    tls_on = config.get("tls", "off").lower() == "on"
    starttls_on = config.get("tls_starttls", "on").lower() == "on"
    if tls_on and not starttls_on:
        security = "ssl"
    elif tls_on or starttls_on:
        security = "starttls"
    else:
        security = "none"
    try:
        port = int(config.get("port", "587") or "587")
    except ValueError:
        port = 587
    return {
        "host": config.get("host", ""),
        "port": port,
        "security": security,
        "username": config.get("user", ""),
        "from_address": config.get("from", ""),
    }


def msmtp_password_path(config: Mapping[str, str]) -> str:
    """The password file referenced by ``passwordeval "cat /path"`` (or "")."""
    match = re.search(r"cat\s+([^\s\"']+)", config.get("passwordeval", ""))
    if not match:
        return ""
    path = match.group(1)
    return path if path.startswith("/") else ""


def read_msmtp_password() -> str:
    """Read the msmtp password file (root-only; never returned by the API)."""
    config = parse_msmtprc(read_text(MSMTPRC))
    path = msmtp_password_path(config)
    if not path and "password" not in config:
        return ""
    if "password" in config and not path:
        return config["password"]
    rooted = ROOT.joinpath(*PurePosixPath(path).parts[1:])
    try:
        return rooted.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


async def msmtp_status() -> Dict[str, object]:
    """Summarize an existing msmtp setup for the migration banner (no secrets)."""
    text = read_text(MSMTPRC)
    config = parse_msmtprc(text)
    if not config:
        return {"detected": False}
    password_path = msmtp_password_path(config)
    rooted = ROOT.joinpath(*PurePosixPath(password_path).parts[1:]) if password_path else None
    return {
        "detected": True,
        **msmtp_import_settings(config),
        "password_available": bool(
            (rooted is not None and rooted.is_file()) or config.get("password")
        ),
    }


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def valid_email(address: str) -> bool:
    return bool(EMAIL_RE.match(address.strip()))


def valid_recipient(value: str) -> bool:
    """A full email address or a local mailbox name like 'root'."""
    value = (value or "").strip()
    return bool(EMAIL_RE.match(value) or LOCAL_RE.match(value))


def valid_host(host: str) -> bool:
    """RFC 1123 name or IPv4 literal - rejects empty labels like 'mail..example'."""
    return valid_hostname(host)


def valid_port(port: int) -> bool:
    return isinstance(port, int) and 1 <= port <= 65535


def valid_sasl_username(username: str) -> bool:
    """sasl_passwd holds `location user:password` - the user may not contain
    whitespace (it would end the key/value split) or ':' (it would end the
    user), and nothing may contain a line break (it would start a new entry)."""
    return bool(username) and not any(char.isspace() or char == ":" for char in username)


def valid_sasl_password(password: str) -> bool:
    return not any(char in password for char in "\r\n\x00")


# --------------------------------------------------------------------------
# Envelope sender (MAIL FROM)
# --------------------------------------------------------------------------

def address_domain(address: str) -> str:
    """Domain part of an address ('' when there is none)."""
    address = (address or "").strip()
    return address.rsplit("@", 1)[1] if "@" in address else ""


def envelope_sender(username: str, from_address: str) -> str:
    """The MAIL FROM this relay is guaranteed to accept: the relay account.

    A hosted mail server only lets an authenticated mailbox send as itself. A
    MAIL FROM the login does not own is refused at RCPT TO with
    ``553 5.7.1 Sender address rejected: not owned by user ...``, so the
    envelope sender is pinned to the login while the visible ``From:`` header
    keeps the address chosen on the Email page. Usernames without a domain
    (``notifications``) are completed with the from address' domain.
    """
    user = (username or "").strip()
    if not user:
        return (from_address or "").strip()
    if "@" in user:
        return user
    domain = address_domain(from_address)
    return f"{user}@{domain}" if domain else user


def sender_canonical_table(from_address: str, username: str) -> str:
    """The ``/etc/postfix/sender_canonical`` lookup table.

    ``@domain  relay-account`` pins every envelope sender from the sender
    domain to the authenticated account. ``sender_canonical_classes =
    envelope_sender`` (see :func:`relay_settings`) keeps the message headers
    as written, so this only changes the SMTP envelope.
    """
    domain = address_domain(from_address)
    sender = envelope_sender(username, from_address)
    if not domain or not valid_email(sender):
        raise ValueError(
            f"cannot pin the envelope sender to {username or '(empty)'!r}: "
            f"it is not a valid address in {from_address or '(no from address)'!r}"
        )
    return (
        "# LinuStart: hosted mail servers reject a MAIL FROM their login does\n"
        "# not own, so the envelope sender is always the relay account.\n"
        f"@{domain}\t{sender}\n"
    )


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
    if not valid_sasl_username(username):
        raise ValueError("the SMTP username may not contain spaces or ':'")
    if not valid_sasl_password(password):
        raise ValueError("the SMTP password may not contain line breaks")
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
        # Rewrite the SMTP envelope sender to the relay account only; the
        # From:/Sender: headers keep the address the user configured.
        "sender_canonical_maps": "hash:/etc/postfix/sender_canonical",
        "sender_canonical_classes": "envelope_sender",
    }


# --------------------------------------------------------------------------
# IO helpers
# --------------------------------------------------------------------------

def installed(transport: str = "postfix") -> bool:
    """Is the transport available? (Neither is installed on minimal servers.)"""
    if transport == "msmtp":
        return shutil.which("msmtp") is not None
    return shutil.which("postmap") is not None or POSTFIX_MAIN_CF.exists()


def current_transport() -> str:
    transport = str(_read_state().get("transport") or "postfix")
    return transport if transport in TRANSPORTS else "postfix"


def msmtp_tls(security: str) -> Dict[str, str]:
    return {
        "starttls": {"tls": "on", "tls_starttls": "on"},
        "ssl": {"tls": "on", "tls_starttls": "off"},
        "none": {"tls": "off", "tls_starttls": "off"},
    }[security]


def build_msmtprc(host: str, port: int, security: str, username: str, from_address: str) -> str:
    """The /etc/msmtprc the panel manages.

    ``from`` is the envelope sender, pinned to the relay account like the
    Postfix sender_canonical map; the visible From: header stays whatever
    the message (unattended-upgrades' Sender) says. The password lives in a
    separate root-only file read through passwordeval.
    """
    if security not in SECURITIES:
        raise ValueError(f"security must be one of {SECURITIES}")
    tls = msmtp_tls(security)
    lines = [
        "# Managed by LinuStart - changes made here are overwritten from the Email page.",
        "defaults",
        "auth           on",
        f"tls            {tls['tls']}",
        f"tls_starttls   {tls['tls_starttls']}",
        "tls_trust_file /etc/ssl/certs/ca-certificates.crt",
        "syslog         LOG_MAIL",
        "",
        "account        linustart",
        f"host           {host}",
        f"port           {int(port)}",
        f"from           {envelope_sender(username, from_address)}",
        f"user           {username}",
        f'passwordeval   "cat {logical(MSMTP_PASSWORD_FILE)}"',
        "",
        "account default : linustart",
    ]
    return "\n".join(lines) + "\n"


def logical(path) -> str:
    """A path as it appears on the real system (without LINUSTART_ROOT)."""
    try:
        return "/" + path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def stored_password(location: str) -> str:
    """A password already on file for this relay, from any transport."""
    panel = read_text(MSMTP_PASSWORD_FILE).strip()
    if panel:
        return panel
    for line in read_text(POSTFIX_SASL_PASSWD).splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            stored = parse_sasl_line(line)
            credentials = line.strip().split(None, 1)[1] if " " in line.strip() else ""
            if stored["location"] == location and ":" in credentials:
                return credentials.split(":", 1)[1]
    return read_msmtp_password()


async def service_active() -> bool:
    try:
        result = await run(["systemctl", "is-active", "--quiet", "postfix"])
    except RuntimeError:
        return False  # no systemd here; report inactive instead of failing
    return result.ok


def _read_state() -> Dict[str, object]:
    try:
        data = json.loads(MAIL_STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


async def status() -> Dict[str, object]:
    state = _read_state()
    transport = current_transport()
    main_cf = parse_main_cf(read_text(POSTFIX_MAIN_CF))
    if transport == "msmtp":
        msmtp = parse_msmtprc(read_text(MSMTPRC))
        credentials = bool(read_text(MSMTP_PASSWORD_FILE).strip())
        relayhost = f"{msmtp['host']}:{msmtp.get('port', '587')}" if msmtp.get("host") else ""
        active: Optional[bool] = None  # msmtp has no daemon
    else:
        credentials = bool(read_text(POSTFIX_SASL_PASSWD).strip())
        relayhost = main_cf.get("relayhost", "")
        active = await service_active()
    return {
        "transport": transport,
        "transports": list(TRANSPORTS),
        "installed": installed(transport),
        "service_active": active,
        "host": state.get("host", ""),
        "port": state.get("port", 587),
        "security": state.get("security", "starttls"),
        "username": state.get("username", ""),
        "from_address": state.get("from_address", ""),
        "envelope_sender": envelope_sender(
            str(state.get("username", "") or ""), str(state.get("from_address", "") or "")
        ),
        "sender_canonical_set": bool(read_text(POSTFIX_SENDER_CANONICAL).strip()),
        "report_to": state.get("report_to", ""),
        "report_mode": state.get("report_mode", "only-on-error"),
        "credentials_set": credentials,
        "relayhost": relayhost,
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
    transport: str = "postfix",
) -> Dict[str, object]:
    """Write the relay configuration for the chosen transport."""
    valid_transport(transport)
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
    if not valid_sasl_username(username):
        raise ValueError("the SMTP username may not contain spaces or ':'")
    if password and not valid_sasl_password(password):
        raise ValueError("the SMTP password may not contain line breaks")
    if not valid_email(from_address):
        raise ValueError(f"invalid from address: {from_address!r}")
    if report_mode not in REPORT_MODES:
        raise ValueError(f"report_mode must be one of {REPORT_MODES}")
    report_to = resolve_report_target(report_to, from_address)
    if not installed(transport):
        raise RuntimeError(f"{TRANSPORT_PACKAGE[transport]} is not installed")
    if transport == "msmtp":
        return await _apply_msmtp(host, port, security, username, from_address, password,
                                  report_to, report_mode)

    location = format_relayhost(host, port)
    existing = read_text(POSTFIX_SASL_PASSWD)
    try:
        line = merge_sasl_line(existing, location, username, password)
    except ValueError:
        # No stored password for this relay: adopt an existing msmtp password
        # so switching from msmtp-mta setups is a one-click operation.
        password = read_msmtp_password()
        if not password:
            raise
        line = merge_sasl_line(existing, location, username, password)
    # The mode is set before the file is renamed into place, so the password
    # is never readable by anyone but root, not even for a moment.
    write_text(POSTFIX_SASL_PASSWD, line, mode=SASL_PASSWD_MODE)
    await run(["postmap", "hash:/etc/postfix/sasl_passwd"], check=True)

    write_text(POSTFIX_SENDER_CANONICAL, sender_canonical_table(from_address, username))
    await run(["postmap", f"hash:{POSTFIX_SENDER_CANONICAL}"], check=True)

    main_cf = read_text(POSTFIX_MAIN_CF)
    for key, value in relay_settings(host, port, security, from_address).items():
        main_cf = upsert_main_cf(main_cf, key, value)
    write_text(POSTFIX_MAIN_CF, main_cf)

    _save_state("postfix", host, port, security, username, from_address, report_to, report_mode)
    await apply_report_settings(report_to, report_mode, from_address)

    await run(["systemctl", "reload", "postfix"], check=True)
    return await status()


def _save_state(transport: str, host: str, port: int, security: str, username: str,
                from_address: str, report_to: str, report_mode: str) -> None:
    state = {
        "transport": transport,
        "host": host,
        "port": port,
        "security": security,
        "username": username,
        "from_address": from_address,
        "report_to": report_to,
        "report_mode": report_mode,
    }
    write_text(MAIL_STATE_FILE, json.dumps(state, indent=2) + "\n")


async def _apply_msmtp(host: str, port: int, security: str, username: str, from_address: str,
                       password: Optional[str], report_to: str, report_mode: str) -> Dict[str, object]:
    # msmtp delivers nothing locally, so a bare mailbox name like "root"
    # would bounce: reports need a real address here.
    if not valid_email(report_to):
        raise ValueError("with msmtp, reports need a full email address (msmtp has no local delivery)")
    password = password or stored_password(format_relayhost(host, port))
    if not password:
        raise ValueError("a password is required for a new SMTP account")
    if not valid_sasl_password(password):
        raise ValueError("the SMTP password may not contain line breaks")
    write_text(MSMTP_PASSWORD_FILE, password + "\n", mode=MSMTP_PASSWORD_MODE)
    write_text(MSMTPRC, build_msmtprc(host, port, security, username, from_address), mode=MSMTPRC_MODE)
    _save_state("msmtp", host, port, security, username, from_address, report_to, report_mode)
    await apply_report_settings(report_to, report_mode, from_address)
    return await status()


async def apply_report_settings(
    report_to: str = "", report_mode: str = "only-on-error", from_address: str = ""
) -> Dict[str, object]:
    """Wire unattended-upgrades notifications (Mail / MailReport / Sender).

    Creates ``50unattended-upgrades`` when the system has none, so reports
    also work on minimal installs where the package ships no configuration.
    Also sets ``Unattended-Upgrade::Sender`` so reports are sent from the
    relay account's address - hosted mail servers often reject mail whose
    From does not match the authenticated user.
    """
    if report_mode not in REPORT_MODES:
        raise ValueError(f"report_mode must be one of {REPORT_MODES}")
    if not from_address:
        from_address = str(_read_state().get("from_address", "") or "")
    target = resolve_report_target(report_to, from_address)

    from . import unattended as unattended_mod

    unattended = read_text(UNATTENDED_FILE) or unattended_mod.base_config()
    unattended = unattended_mod.upsert_setting(unattended, "Unattended-Upgrade::Mail", target)
    unattended = unattended_mod.upsert_setting(unattended, "Unattended-Upgrade::MailReport", report_mode)
    if valid_email(from_address):
        unattended = unattended_mod.upsert_setting(
            unattended, "Unattended-Upgrade::Sender", from_address
        )
    write_text(UNATTENDED_FILE, unattended)

    state = _read_state()
    state.update({"report_to": target, "report_mode": report_mode})
    write_text(MAIL_STATE_FILE, json.dumps(state, indent=2) + "\n")
    return state


def test_command(from_address: str, recipient: str, transport: str = "postfix") -> list:
    """Send a test message through the configured sendmail.

    msmtp takes the envelope sender from its config (the relay account);
    passing -f would override it with an address the relay may refuse.
    """
    argv = ["sendmail", "-i"]
    if from_address and transport != "msmtp":
        argv += ["-f", from_address]
    argv.append(recipient)
    return argv


def _header_value(value: str) -> str:
    """Flatten a stored value so it can never break out of a header line."""
    return re.sub(r"[\r\n]+", " ", value or "").strip()


def test_message(recipient: str, from_address: str = "") -> str:
    sender = _header_value(from_address)
    return (
        (f"From: LinuStart <{sender}>\n" if sender else "From: LinuStart\n")
        + f"To: {_header_value(recipient)}\n"
        + "Subject: LinuStart test email\n"
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
