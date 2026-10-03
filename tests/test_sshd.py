"""Tests for sshd_config parsing, diff-friendly editing and validation."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.sshd import (  # noqa: E402
    parse_sshd_config,
    set_sshd_option,
    sshd_config_error,
    typed_values,
    validate_settings,
)

CONFIG = """# SSH configuration - keep this file tidy
#Port 2222
Port 22
PermitRootLogin yes
PasswordAuthentication no

# X11 is discouraged
X11Forwarding yes

Match User bob
    PasswordAuthentication yes
    Port 2223
"""


def test_parse_sshd_config_first_value_wins():
    values = parse_sshd_config(CONFIG)
    assert values["Port"] == "22"  # the commented line is ignored
    assert values["PermitRootLogin"] == "yes"
    assert values["PasswordAuthentication"] == "no"  # Match block must not shadow this
    assert values["X11Forwarding"] == "yes"
    assert "MaxAuthTries" not in values  # absent keywords stay absent


def test_parse_sshd_config_case_insensitive():
    values = parse_sshd_config("port 2222\npasswordauthentication no\n")
    assert values["Port"] == "2222"
    assert values["PasswordAuthentication"] == "no"


def test_parse_sshd_config_quoted_value():
    values = parse_sshd_config('PermitRootLogin "prohibit-password"\n')
    assert values["PermitRootLogin"] == "prohibit-password"


def test_set_sshd_option_replaces_in_place():
    result = set_sshd_option(CONFIG, "Port", "2222")
    values = parse_sshd_config(result)
    assert values["Port"] == "2222"
    assert "# SSH configuration" in result  # comments preserved
    assert "#Port 2222" in result
    assert "Match User bob" in result
    assert "    Port 2223" in result  # Match-scoped line untouched


def test_set_sshd_option_inserts_before_match():
    result = set_sshd_option(CONFIG, "MaxAuthTries", "4")
    assert parse_sshd_config(result)["MaxAuthTries"] == "4"
    assert result.index("MaxAuthTries 4") < result.index("Match User bob")


def test_set_sshd_option_appends_when_missing():
    result = set_sshd_option("Port 22\n", "ClientAliveInterval", "300")
    assert parse_sshd_config(result)["ClientAliveInterval"] == "300"
    assert result.splitlines()[0] == "Port 22"


def test_set_sshd_option_rejects_unknown_keyword():
    try:
        set_sshd_option(CONFIG, "UsePAM", "yes")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an unmanaged keyword")


def test_validate_settings_normalizes():
    values = validate_settings({"Port": "2200", "PasswordAuthentication": False, "PermitRootLogin": "No"})
    assert values == {"Port": "2200", "PasswordAuthentication": "no", "PermitRootLogin": "no"}


def test_validate_settings_rejects_bad_input():
    for bad in [
        {"Port": "0"},
        {"Port": "70000"},
        {"Port": "twentytwo"},
        {"PermitRootLogin": "maybe"},
        {"MaxAuthTries": "0"},
        {"ClientAliveInterval": "-1"},
        {"Unknown": "1"},
    ]:
        try:
            validate_settings(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


def test_typed_values():
    typed = typed_values(parse_sshd_config(CONFIG))
    assert typed["Port"] == 22
    assert typed["PasswordAuthentication"] is False
    assert typed["PermitRootLogin"] == "yes"
    assert typed["MaxAuthTries"] == 6  # default when absent


def test_sshd_config_error_finds_syntax_errors():
    noisy = (
        "Unable to load host key /etc/ssh/ssh_host_rsa_key\n"
        "/etc/ssh/sshd_config: line 12: Missing argument\n"
    )
    assert sshd_config_error(noisy) == "/etc/ssh/sshd_config: line 12: Missing argument"


def test_sshd_config_error_ignores_environment_noise():
    noisy = (
        "Unable to load host key /etc/ssh/ssh_host_rsa_key\n"
        "Could not load host key: /etc/ssh/ssh_host_ecdsa_key\n"
        "Missing privilege separation directory /run/sshd\n"
    )
    assert sshd_config_error(noisy) is None


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all sshd tests passed")
