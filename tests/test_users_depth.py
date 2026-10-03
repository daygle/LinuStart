"""Tests for login history parsing and password aging helpers."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.users import (  # noqa: E402
    parse_chage,
    parse_last,
    valid_day_count,
    valid_expiry,
)

LAST = """bob      pts/0        192.168.1.5      Thu Oct  3 10:12:44 2026 +0000   still logged in
alice    pts/2        10.0.0.9         Wed Oct  2 09:00:00 2026 +0000 - Wed Oct  2 09:45:12 2026 +0000  (00:45)
carol    pts/1                         Tue Oct  1 08:00:00 2026 +0000 - Tue Oct  1 08:30:00 2026 +0000  (00:30)
reboot   system boot  5.10.0-21-amd64  Mon Sep 29 07:00:02 2026 +0000   still running
dave     pts/3        10.0.0.7         Sun Sep 28 22:00:00 2026 +0000 - gone - no logout
wtmp begins Mon Sep  1 00:00:00 2026
"""

CHAGE = """Last password change : Oct 03, 2026
Password expires     : never
Password inactive    : never
Account expires      : Jan 01, 2027
Minimum number of days between password change     : 0
Maximum number of days between password change     : 90
Number of days of warning before password expires  : 14
"""


def test_parse_last_rows():
    entries = parse_last(LAST)
    assert len(entries) == 5  # the wtmp notice is skipped
    bob = entries[0]
    assert bob["user"] == "bob" and bob["terminal"] == "pts/0"
    assert bob["source"] == "192.168.1.5"
    assert bob["status"] == "logged in"
    assert bob["login"].startswith("Thu Oct")


def test_parse_last_logout_and_duration():
    entries = parse_last(LAST)
    alice = entries[1]
    assert alice["status"] == "finished"
    assert alice["duration"] == "00:45"
    assert alice["logout"].startswith("Wed Oct")
    carol = entries[2]
    assert carol["source"] == ""  # local session without a source field


def test_parse_last_reboot_and_no_logout():
    entries = parse_last(LAST)
    reboot = entries[3]
    assert reboot["user"] == "reboot" and reboot["terminal"] == "system boot"
    assert reboot["status"] == "logged in"
    dave = entries[4]
    assert dave["status"] == "no logout"


def test_parse_chage():
    fields = parse_chage(CHAGE)
    assert fields["last_change"] == "Oct 03, 2026"
    assert fields["password_expires"] == "never"
    assert fields["account_expires"] == "Jan 01, 2027"
    assert fields["max_days"] == "90"
    assert fields["warn_days"] == "14"


def test_valid_expiry():
    assert valid_expiry("never") is None
    assert valid_expiry("") is None
    assert valid_expiry("2027-01-01") == "2027-01-01"
    for bad in ["tomorrow", "01/01/2027", "2027-13-01"]:
        try:
            valid_expiry(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_valid_day_count():
    assert valid_day_count(90, 99999, "max age") == 90
    for bad in [("many", 99999), (-1, 99999), (100000, 99999), (None, 99999)]:
        try:
            valid_day_count(bad[0], bad[1], "max age")
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all users depth tests passed")
