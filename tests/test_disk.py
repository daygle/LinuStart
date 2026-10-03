"""Tests for df/du parsing and scan path validation."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.disk import du_command, parse_df, parse_du, valid_path  # noqa: E402

DF = """Filesystem Mounted on Type 1B-blocks Used Avail Use%
/dev/sda1 / ext4 102400000000 51200000000 51200000000 50%
/dev/sdb1 /data ext4 204800000000 10240000000 194600000000 5%
tmpfs /run tmpfs 1024000000 0 1024000000 0%
"""

DU = """12288\t/var/log
1048576\t/var/cache
4096\t/var/lib
24576\t/var
"""


def test_parse_df():
    filesystems = parse_df(DF)
    assert len(filesystems) == 3  # header row skipped
    root = filesystems[0]
    assert root["target"] == "/"
    assert root["size"] == 102400000000
    assert root["percent"] == 50
    assert filesystems[2]["target"] == "/run"


def test_parse_du_sorts_and_excludes_root():
    entries = parse_du(DU, root="/var")
    assert [e["path"] for e in entries] == ["/var/cache", "/var/log", "/var/lib"]
    assert entries[0]["size"] == 1048576


def test_parse_du_skips_error_lines():
    text = "du: cannot read '/root/secret': Permission denied\n1024\t/tmp/x\n"
    entries = parse_du(text)
    assert entries == [{"path": "/tmp/x", "size": 1024}]


def test_valid_path():
    assert valid_path("/var/log") == "/var/log"
    assert valid_path("/var//log/") == "/var/log"
    for bad in ["", "  ", "relative/path", "/ok/../..", "/var/../etc", "/with\x00byte"]:
        try:
            valid_path(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_du_command():
    assert du_command("/var/log") == ["du", "-x", "-b", "-d", "1", "/var/log"]


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all disk tests passed")
