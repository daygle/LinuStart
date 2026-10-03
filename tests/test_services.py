"""Tests for systemd unit parsing and action validation."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.services import (  # noqa: E402
    action_argv,
    filter_units,
    normalize_unit,
    parse_show,
    parse_unit_files,
    parse_unit_list,
    valid_action,
)

UNITS = """ssh.service                   loaded active   running OpenBSD Secure Shell server
cron.service                  loaded active   running Regular background program processing daemon
postfix.service               loaded active   exited  Postfix Mail Transport Agent
apache2.service               loaded inactive dead    The Apache HTTP Server
bad line without enough columns
"""

UNIT_FILES = """ssh.service                   enabled  enabled
cron.service                  enabled  enabled
apache2.service               disabled enabled
static-thing.service          static   enabled
"""

SHOW = """Id=ssh.service
Description=OpenBSD Secure Shell server
ActiveState=active
SubState=running
UnitFileState=enabled
FragmentPath=/lib/systemd/system/ssh.service
MainPID=424
ExecMainStartTimestamp=Thu 2026-10-03 10:00:00 UTC
"""


def test_parse_unit_list():
    units = parse_unit_list(UNITS)
    assert [u["unit"] for u in units] == ["ssh.service", "cron.service", "postfix.service", "apache2.service"]
    assert units[0]["active"] == "active" and units[0]["sub"] == "running"
    assert units[2]["sub"] == "exited" and units[3]["active"] == "inactive"
    assert units[0]["description"] == "OpenBSD Secure Shell server"  # spaces preserved


def test_parse_unit_files():
    states = parse_unit_files(UNIT_FILES)
    assert states["ssh.service"] == "enabled"
    assert states["apache2.service"] == "disabled"
    assert states["static-thing.service"] == "static"


def test_parse_show():
    props = parse_show(SHOW)
    assert props["MainPID"] == "424"
    assert props["UnitFileState"] == "enabled"


def test_normalize_unit():
    assert normalize_unit("ssh") == "ssh.service"
    assert normalize_unit("ssh.service") == "ssh.service"
    assert normalize_unit("postgresql@13-main") == "postgresql@13-main.service"
    for bad in ["", "  ", "../../etc/passwd", "foo/bar", ".hidden", "a b"]:
        try:
            normalize_unit(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_action_argv():
    assert action_argv("ssh", "restart") == ["systemctl", "restart", "ssh.service"]
    assert action_argv("ssh.service", "STOP") == ["systemctl", "stop", "ssh.service"]
    try:
        action_argv("ssh", "kill")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a non-allowlisted action")


def test_valid_action():
    assert valid_action("start") and valid_action("Restart")
    assert not valid_action("mask") and not valid_action("")


def test_filter_units():
    units = parse_unit_list(UNITS)
    assert [u["unit"] for u in filter_units(units, "post")] == ["postfix.service"]
    assert [u["unit"] for u in filter_units(units, "secure shell")] == ["ssh.service"]
    assert len(filter_units(units, "")) == 4


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all services tests passed")
