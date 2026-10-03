"""Tests for ps parsing and kill validation."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.procs import kill_argv, parse_ps, ps_command  # noqa: E402

PS = """    1       0 root            0.0  0.1   8500   100 /sbin/init
  424       1 root            0.0  0.2  12000    60 /usr/sbin/sshd -D
 2048     424 bob             5.5  1.5 102400     5 -bash
20000    2048 bob            99.9 50.0 999999     1 yes
"""


def test_parse_ps():
    procs = parse_ps(PS)
    assert [p["pid"] for p in procs] == [1, 424, 2048, 20000]
    assert procs[2]["user"] == "bob"
    assert procs[2]["cpu"] == 5.5
    assert procs[2]["args"] == "-bash"
    assert procs[3]["rss_kb"] == 999999


def test_ps_command():
    assert ps_command() == ["ps", "-eo", "pid=,ppid=,user=,%cpu=,%mem=,rss=,etimes=,args=", "--sort=-%cpu"]
    assert "--sort=-%mem" in ps_command("mem")
    try:
        ps_command("name")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an unknown sort key")


def test_kill_argv():
    assert kill_argv(42) == ["kill", "-TERM", "42"]
    assert kill_argv("42", "sigkill") == ["kill", "-KILL", "42"]
    for bad in [(1, "TERM"), (0, "TERM"), (-5, "TERM"), ("x", "TERM"), (42, "STOP")]:
        try:
            kill_argv(*bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all procs tests passed")
