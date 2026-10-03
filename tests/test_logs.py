"""Tests for journal queries, log name validation and bounded file tails."""

import atexit
import os
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# tail_file refuses to read anything outside the log directory, so these tests
# need a real root to work inside rather than a bare system temp directory.
# LINUSTART_ROOT is read when linustart.paths is imported, so it has to be set
# before the imports below.
SANDBOX = tempfile.mkdtemp(prefix="linustart-logs-")
os.environ["LINUSTART_ROOT"] = SANDBOX
atexit.register(shutil.rmtree, SANDBOX, ignore_errors=True)

from linustart.modules.logs import (  # noqa: E402
    clamp_lines,
    journal_command,
    tail_file,
    tail_text,
    valid_log_name,
)
from linustart.paths import VAR_LOG_DIR  # noqa: E402
from linustart.util import is_within  # noqa: E402


def _log_dir():
    path = pathlib.Path(VAR_LOG_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_journal_command_basic():
    assert journal_command(100) == ["journalctl", "-n", "100", "--no-pager", "-o", "short-iso"]


def test_journal_command_filters():
    argv = journal_command(50, unit="ssh.service", priority="err")
    assert argv[-4:] == ["-u", "ssh.service", "-p", "err"]
    assert journal_command(50, priority="3")[-1] == "3"


def test_journal_command_rejects_junk():
    for bad in [{"unit": "../etc/passwd"}, {"unit": "a b"}, {"priority": "loud"}]:
        try:
            journal_command(50, **bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


def test_clamp_lines():
    assert clamp_lines(100) == 100
    assert clamp_lines(5) == 10
    assert clamp_lines(99999) == 2000
    assert clamp_lines("nonsense") == 200


def test_valid_log_name():
    assert valid_log_name("syslog") == "syslog"
    assert valid_log_name("apache2-access.log") == "apache2-access.log"
    for bad in ["", "../etc/shadow", "sub/dir.log", "/abs/path", "apache2/error.log", "a..b/../c"]:
        try:
            valid_log_name(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_tail_text():
    assert tail_text("a\nb\nc\nd", 2) == ["c", "d"]


def test_tail_file_reads_bounded_slice():
    log_dir = _log_dir()
    path = log_dir / "app.log"
    path.write_text("\n".join(f"line{i}" for i in range(50)) + "\n", encoding="utf-8")
    lines = tail_file(path, 5)
    assert lines == ["line45", "line46", "line47", "line48", "line49"]
    try:
        tail_file(log_dir / "gone.log", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a missing file")


def test_tail_file_refuses_paths_outside_the_log_dir():
    with tempfile.TemporaryDirectory() as tmp:
        outside = pathlib.Path(tmp) / "app.log"
        outside.write_text("secret\n", encoding="utf-8")
        try:
            tail_file(outside, 5)
        except ValueError:
            pass
        else:
            raise AssertionError("tail_file read a file outside the log directory")
    # A path that climbs back out with .. is refused too.
    escape = pathlib.Path(VAR_LOG_DIR) / ".." / ".." / "etc" / "shadow"
    try:
        tail_file(escape, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("tail_file followed a traversal out of the log directory")


def test_is_within_rejects_siblings_and_parents():
    base = pathlib.Path(VAR_LOG_DIR)
    assert is_within(base, base / "app.log") is True
    assert is_within(base, base) is True
    assert is_within(base, base / "sub" / "deep.log") is True
    assert is_within(base, base.parent) is False
    assert is_within(base, base / ".." / ".." / "etc" / "shadow") is False
    # A sibling whose name merely starts the same way is not inside either.
    assert is_within(base, base.parent / (base.name + "-evil") / "passwd") is False


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all logs tests passed")
