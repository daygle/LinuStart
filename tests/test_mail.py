"""Tests for mail relay configuration (pure helpers)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.mail import (  # noqa: E402
    address_domain,
    envelope_sender,
    format_relayhost,
    merge_sasl_line,
    parse_main_cf,
    parse_sasl_line,
    relay_settings,
    sender_canonical_table,
    sasl_line,
    test_command as build_test_command,
    test_message as build_test_message,
    upsert_main_cf,
    valid_email,
    valid_host,
    valid_port,
)

MAIN_CF = """# See /usr/share/postfix/main.cf.dist
smtpd_banner = $myhostname ESMTP
myhostname = server1
"""


def test_valid_email():
    assert valid_email("me@example.com")
    assert valid_email("linustart+alerts@sub.example.co.uk")
    for bad in ["", "me", "me@", "@example.com", "me @example.com", "me@example"]:
        assert not valid_email(bad), bad


def test_valid_host():
    assert valid_host("mail.example.com")
    assert valid_host("10.0.0.5")
    assert valid_host(" mail.example.com ")  # surrounding whitespace is trimmed
    for bad in ["", "mail example com", "-mail.example.com", "mail..example"]:
        assert not valid_host(bad), bad


def test_valid_port():
    assert valid_port(25) and valid_port(587) and valid_port(465) and valid_port(65535)
    assert not valid_port(0) and not valid_port(65536) and not valid_port("587")


def test_format_relayhost():
    assert format_relayhost("mail.example.com", 587) == "[mail.example.com]:587"
    assert format_relayhost("mail.example.com", 25) == "[mail.example.com]:25"


def test_sasl_line_round_trip():
    line = sasl_line("[mail.example.com]:587", "me@example.com", "s3cret")
    assert line == "[mail.example.com]:587 me@example.com:s3cret"
    parsed = parse_sasl_line(line)
    assert parsed == {"location": "[mail.example.com]:587", "username": "me@example.com"}
    # the password must never come back out of the parser
    assert "s3cret" not in str(parsed)


def test_parse_sasl_line_malformed():
    assert parse_sasl_line("")["username"] == ""
    assert parse_sasl_line("[h]:25") == {"location": "[h]:25", "username": ""}


def test_merge_sasl_new_password():
    result = merge_sasl_line("", "[mail.example.com]:587", "me@example.com", "s3cret")
    assert result == "[mail.example.com]:587 me@example.com:s3cret\n"


def test_merge_sasl_keeps_old_password_when_blank():
    existing = "[mail.example.com]:587 me@example.com:oldpass\n"
    result = merge_sasl_line(existing, "[mail.example.com]:587", "me@example.com", "")
    assert result == "[mail.example.com]:587 me@example.com:oldpass\n"


def test_merge_sasl_password_with_colons():
    existing = "[mail.example.com]:587 me@example.com:p:a:ss\n"
    result = merge_sasl_line(existing, "[mail.example.com]:587", "me@example.com", None)
    assert result == "[mail.example.com]:587 me@example.com:p:a:ss\n"


def test_merge_sasl_new_account_needs_password():
    try:
        merge_sasl_line("", "[mail.example.com]:587", "me@example.com", "")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError when no password is available")


def test_parse_main_cf():
    settings = parse_main_cf(MAIN_CF)
    assert settings["smtpd_banner"] == "$myhostname ESMTP"
    assert settings["myhostname"] == "server1"


def test_upsert_main_cf_replaces():
    result = upsert_main_cf(MAIN_CF, "myhostname", "server2")
    settings = parse_main_cf(result)
    assert settings["myhostname"] == "server2"
    assert "myhostname = server2" in result
    assert "myhostname = server1" not in result
    assert "# See /usr/share/postfix/main.cf.dist" in result


def test_upsert_main_cf_appends():
    result = upsert_main_cf(MAIN_CF, "relayhost", "[mail.example.com]:587")
    settings = parse_main_cf(result)
    assert settings["relayhost"] == "[mail.example.com]:587"
    assert settings["myhostname"] == "server1"


def test_relay_settings_starttls():
    settings = relay_settings("mail.example.com", 587, "starttls", "linustart@example.com")
    assert settings["relayhost"] == "[mail.example.com]:587"
    assert settings["myorigin"] == "example.com"
    assert settings["smtp_sasl_auth_enable"] == "yes"
    assert settings["smtp_tls_security_level"] == "encrypt"
    assert settings["smtp_tls_wrappermode"] == "no"
    assert settings["inet_interfaces"] == "loopback-only"


def test_relay_settings_ssl_and_none():
    ssl = relay_settings("mail.example.com", 465, "ssl", "me@example.com")
    assert ssl["smtp_tls_wrappermode"] == "yes"
    assert ssl["smtp_tls_security_level"] == "encrypt"
    plain = relay_settings("mail.example.com", 25, "none", "me@example.com")
    assert plain["smtp_tls_security_level"] == "may"
    assert plain["smtp_tls_wrappermode"] == "no"


def test_relay_settings_rejects_bad_security():
    try:
        relay_settings("mail.example.com", 587, "tls", "me@example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown security mode")


def test_test_command():
    assert build_test_command("me@example.com", "you@example.com") == [
        "sendmail", "-i", "-f", "me@example.com", "you@example.com",
    ]
    assert build_test_command("", "you@example.com") == ["sendmail", "-i", "you@example.com"]


# --- envelope sender (the 553 5.7.1 "not owned by user" bounce) -----------

def test_address_domain():
    assert address_domain("me@example.com") == "example.com"
    assert address_domain(" me@example.com ") == "example.com"
    assert address_domain("me") == ""
    assert address_domain("") == ""


def test_envelope_sender_is_the_relay_account():
    # The bounce: logging in as notifications@ while sending as daygle@ is
    # refused, so the envelope sender must be the login.
    assert envelope_sender("notifications@daygle.net", "daygle@daygle.net") == (
        "notifications@daygle.net"
    )
    assert envelope_sender(" notifications@daygle.net ", "daygle@daygle.net") == (
        "notifications@daygle.net"
    )
    # Same account, nothing to pin - still valid.
    assert envelope_sender("linustart@example.com", "linustart@example.com") == (
        "linustart@example.com"
    )


def test_envelope_sender_completes_a_bare_username():
    assert envelope_sender("notifications", "daygle@daygle.net") == "notifications@daygle.net"
    # Nothing to complete it with, so the login is used as-is.
    assert envelope_sender("notifications", "daygle") == "notifications"
    # No login configured: fall back to the from address.
    assert envelope_sender("", "daygle@daygle.net") == "daygle@daygle.net"


def test_sender_canonical_table_pins_the_from_domain():
    table = sender_canonical_table("daygle@daygle.net", "notifications@daygle.net")
    entries = [line for line in table.splitlines() if line and not line.startswith("#")]
    assert entries == ["@daygle.net\tnotifications@daygle.net"]


def test_sender_canonical_table_rejects_an_unusable_sender():
    for from_address, username in [
        ("", "notifications@daygle.net"),  # no domain to map
        ("daygle@daygle.net", "not a login"),  # login is not an address
    ]:
        try:
            sender_canonical_table(from_address, username)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {from_address!r} {username!r}")


def test_relay_settings_rewrite_the_envelope_sender_only():
    settings = relay_settings("mail.daygle.net", 587, "starttls", "daygle@daygle.net")
    assert settings["sender_canonical_maps"] == "hash:/etc/postfix/sender_canonical"
    # envelope_sender only: the From:/Sender: headers are left as written.
    assert settings["sender_canonical_classes"] == "envelope_sender"


def test_test_message_has_an_addressable_from_header():
    message = build_test_message("daygle@daygle.net", "daygle@daygle.net")
    assert message.startswith("From: LinuStart <daygle@daygle.net>\n")
    assert "To: daygle@daygle.net\n" in message
    assert build_test_message("daygle@daygle.net").startswith("From: LinuStart\n")


def test_test_message_cannot_be_smuggled_headers():
    message = build_test_message(
        "daygle@daygle.net", "me@example.com\r\nBcc: victim@example.com"
    )
    assert message.startswith("From: LinuStart <me@example.com Bcc: victim@example.com>\n")
    assert "\r" not in message
    assert message.count("Subject:") == 1


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all mail tests passed")
