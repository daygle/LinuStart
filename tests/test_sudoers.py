"""Tests for sudoers drop-in building and parsing."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.sudoers import (  # noqa: E402
    build_sudoers_dropin,
    dropin_path,
    parse_sudoers_dropin,
)


def test_build_sudoers_dropin():
    assert build_sudoers_dropin("deploy") == "deploy ALL=(ALL) ALL\n"
    assert build_sudoers_dropin("deploy", nopasswd=True) == "deploy ALL=(ALL) NOPASSWD: ALL\n"
    try:
        build_sudoers_dropin("bad name")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an invalid user name")


def test_parse_sudoers_dropin_round_trip():
    parsed = parse_sudoers_dropin(build_sudoers_dropin("deploy", nopasswd=True))
    assert parsed == {"user": "deploy", "nopasswd": True}
    parsed = parse_sudoers_dropin("# managed by LinuStart\nbob ALL=(ALL) ALL\n")
    assert parsed == {"user": "bob", "nopasswd": False}


def test_parse_sudoers_dropin_rejects_foreign_content():
    assert parse_sudoers_dropin("") is None
    assert parse_sudoers_dropin("# just a comment\n") is None
    assert parse_sudoers_dropin("root ALL=(ALL:ALL) ALL\n") is None
    assert parse_sudoers_dropin("%sudo ALL=(ALL:ALL) ALL\n") is None


def test_dropin_path():
    assert dropin_path("deploy").name == "linustart-deploy"
    try:
        dropin_path("../evil")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for path traversal in user name")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all sudoers tests passed")
