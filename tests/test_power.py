"""Tests for reboot/shutdown action validation, argv construction and timers."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.power import (  # noqa: E402
    DEFAULT_DELAY,
    MAX_DELAY,
    cancel_argv,
    describe_delay,
    normalize_action,
    normalize_delay,
    parse_timer,
    timer_unit,
    unit_name,
    action_argv,
)

TIMER_ARMED = """ActiveState=active
NextElapseUSecRealtime=Mon 2026-10-05 11:30:00 UTC
"""

TIMER_INACTIVE = """ActiveState=inactive
NextElapseUSecRealtime=
"""


def test_normalize_action():
    assert normalize_action("reboot") == "reboot"
    assert normalize_action("  Shutdown ") == "shutdown"
    for bad in ["", "reboott", "halt", "poweroff", "reboot; rm -rf /", None]:
        try:
            normalize_action(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_normalize_delay():
    assert normalize_delay(30) == 30
    assert normalize_delay("45") == 45
    assert normalize_delay(" 60 ") == 60
    assert normalize_delay(0) == 0
    # absent/blank means "use the default countdown"
    assert normalize_delay(None) == DEFAULT_DELAY
    assert normalize_delay("") == DEFAULT_DELAY


def test_normalize_delay_rejects_bad_values():
    for bad in ["soon", "5s", 1.5, [5], True, False, -1, MAX_DELAY + 1]:
        try:
            normalize_delay(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_unit_names_are_namespaced():
    assert unit_name("reboot") == "linustart-power-reboot"
    assert unit_name("shutdown") == "linustart-power-shutdown"
    assert timer_unit("reboot") == "linustart-power-reboot.timer"


def test_action_argv_schedules_a_oneshot_timer():
    argv = action_argv("reboot", 5)
    assert argv[0] == "systemd-run"
    assert "--on-active=5" in argv
    assert "--unit=linustart-power-reboot" in argv
    # systemd runs the trailing command once the timer fires
    assert argv[-2:] == ["systemctl", "reboot"]


def test_action_argv_maps_shutdown_to_poweroff():
    assert action_argv("shutdown", 60)[-2:] == ["systemctl", "poweroff"]
    assert "--on-active=60" in action_argv("shutdown", 60)


def test_action_argv_never_injects_a_shell():
    # The action is validated against an allowlist, so an injected value can
    # never reach argv even before the subprocess would reject it.
    try:
        action_argv("reboot; reboot", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an injected action")


def test_cancel_argv_stops_the_matching_timer():
    assert cancel_argv("shutdown") == [
        "systemctl", "stop", "linustart-power-shutdown.timer",
    ]


def test_describe_delay():
    assert describe_delay(0) == "immediately"
    assert describe_delay(5) == "in 5s"
    assert describe_delay(60) == "in 1m"
    assert describe_delay(300) == "in 5m"
    assert describe_delay(90) == "in 1m 30s"


def test_parse_timer():
    armed = parse_timer(TIMER_ARMED)
    assert armed["armed"] is True
    assert armed["next_elapse"] == "Mon 2026-10-05 11:30:00 UTC"

    inactive = parse_timer(TIMER_INACTIVE)
    assert inactive["armed"] is False

    # Active but with no elapse time set is not something we can cancel.
    assert parse_timer("ActiveState=active\nNextElapseUSecRealtime=n/a\n")["armed"] is False


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all power tests passed")
