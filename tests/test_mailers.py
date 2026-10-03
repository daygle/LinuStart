"""Tests for mail transfer agent detection and conflict handling."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.mail import (  # noqa: E402
    classify_sendmail_target,
    conflicting_mailers,
    known_mailers,
    parse_dpkg_status,
    remove_conflicting_command,
)

DPKG = """base-files install ok installed
postfix install ok installed
msmtp deinstall ok config-files
msmtp-mta install ok installed
exim4 install ok installed
msmtp install ok installed
nano install ok installed
"""


def test_parse_dpkg_status():
    installed = parse_dpkg_status(DPKG)
    assert "postfix" in installed
    assert "msmtp-mta" in installed
    assert "msmtp" in installed
    assert "msmtp deinstall" not in installed  # config-files only is not installed
    assert "base-files" in installed


def test_known_mailers_filters_to_mail_packages():
    names = known_mailers(parse_dpkg_status(DPKG))
    assert names == ["exim4", "msmtp", "msmtp-mta", "postfix"]
    assert "nano" not in names


def test_conflicting_mailers_excludes_postfix_and_clients():
    conflicts = conflicting_mailers(parse_dpkg_status(DPKG))
    assert sorted(conflicts) == ["exim4", "msmtp-mta"]  # postfix is ours; msmtp client is harmless


def test_conflicting_mailers_none_when_only_postfix():
    assert conflicting_mailers(["postfix", "msmtp"]) == []


def test_classify_sendmail_target():
    assert classify_sendmail_target("/usr/lib/postfix/sbin/sendmail") == "postfix"
    assert classify_sendmail_target("/usr/bin/msmtp") == "msmtp"
    assert classify_sendmail_target("/usr/sbin/ssmtp") == "ssmtp"
    assert classify_sendmail_target("") == "none"
    assert classify_sendmail_target("/usr/bin/odd-mailer") == "unknown"


def test_remove_conflicting_command():
    argv = remove_conflicting_command(["msmtp-mta", "exim4", "msmtp-mta"])
    assert argv == ["apt-get", "remove", "-y", "exim4", "msmtp-mta"]
    for bad in [[], ["postfix"], ["nano"], ["apt-get remove -y /"]]:
        try:
            remove_conflicting_command(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all mailer tests passed")
