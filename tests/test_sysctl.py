"""Tests for sysctl configuration parsing, validation and editing."""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import sysctl as sysctl_mod  # noqa: E402
from linustart.modules.sysctl import (  # noqa: E402
    append_entry,
    apply_problems,
    parse_entries,
    remove_entry,
    render_entry,
    render_like,
    replace_entry,
    runtime_value,
    valid_key,
    valid_value,
)

SYSCTL_CONF = """# /etc/sysctl.conf
# Kernel parameter tuning

# Reduce swap tendency on database hosts
vm.swappiness = 10
vm.vfs_cache_pressure=50
net.ipv4.ip_forward=1

# performance - disable risk of SYN flood
# net.ipv4.tcp_syncookies = 0
kernel.pid_max = 4194304
fs.file-max = 2097152
"""

DROPIN = """# managed by ops
vm.dirty_ratio = 20
"""

CLEAN_OUTPUT = """
sysctl: setting key "vm.swappiness"
"""


def test_parse_entries():
    entries = parse_entries(SYSCTL_CONF)
    assert [entry.key for entry in entries] == [
        "vm.swappiness",
        "vm.vfs_cache_pressure",
        "net.ipv4.ip_forward",
        "net.ipv4.tcp_syncookies",  # commented out, see below
        "kernel.pid_max",
        "fs.file-max",
    ]
    assert entries[0].value == "10"
    assert entries[1].value == "50"
    # spacing around the equals sign does not matter
    assert entries[1].raw == "vm.vfs_cache_pressure=50"
    assert [entry.valid for entry in entries] == [True, True, True, False, True, True]


def test_parse_ignores_comments_and_blanks():
    keys = [entry.key for entry in parse_entries(SYSCTL_CONF)]
    assert "# performance" not in keys
    assert not any(key.startswith("#") for key in keys)


def test_parse_commented_setting_is_listed_but_invalid():
    """Prose comments are ignored; a commented-out setting is shown, disabled."""
    entries = parse_entries(SYSCTL_CONF)
    keys = [entry.key for entry in entries]
    # prose never becomes an entry
    assert "performance" not in keys
    assert "Reduce" not in keys
    # a real setting that someone commented out is listed so it can be re-enabled
    syncookies = [entry for entry in entries if entry.key == "net.ipv4.tcp_syncookies"]
    assert len(syncookies) == 1
    assert syncookies[0].valid is False
    assert syncookies[0].value == "0"

    # semicolons work as comment markers too
    text = "; vm.swappiness = 10\n"
    assert parse_entries(text)[0].valid is False


def test_parse_keeps_line_index():
    entries = parse_entries(DROPIN)
    assert entries[0].index == 1  # the comment on line 0 is not an entry


def test_parse_skips_continuation_lines():
    text = "vm.swappiness = \\\n    10\n"
    assert parse_entries(text) == []


def test_valid_key():
    for good in ["vm.swappiness", "fs.file-max", "net.ipv4.conf.all.rp_filter",
                 "kernel.dmesg_restrict", "net.ipv4.ip_forward"]:
        assert valid_key(good), good
    for bad in ["", "vm swappiness", "vm.swappiness=10", "vm.swappiness\nrm -rf /",
                "vm.swappiness;reboot", "vm.swappiness#"]:
        assert not valid_key(bad), bad


def test_valid_value():
    for good in ["10", "0", "4194304", "0x1f", "example.com", "1,2", "/dev/sda", "-1"]:
        assert valid_value(good), good
    for bad in ["", "10\nvm.swappiness=0", 'a"b', "10 # sneaky", "10; reboot", "a\x00b"]:
        assert not valid_value(bad), bad


def test_replace_entry_preserves_everything_else():
    result = replace_entry(SYSCTL_CONF, 4, "vm.swappiness", "20")
    assert result.count("vm.swappiness") == 1
    assert "vm.swappiness = 20" in result
    # comments and neighbours untouched
    assert "# Reduce swap tendency on database hosts" in result
    assert "vm.vfs_cache_pressure=50" in result
    assert "kernel.pid_max = 4194304" in result
    assert result.splitlines()[0] == "# /etc/sysctl.conf"


def test_replace_entry_keeps_equals_spacing():
    assert replace_entry(DROPIN, 1, "vm.dirty_ratio", "30") == (
        "# managed by ops\nvm.dirty_ratio = 30\n"
    )
    tight = "vm.dirty_ratio=20\n"
    assert replace_entry(tight, 0, "vm.dirty_ratio", "30") == "vm.dirty_ratio=30\n"


def test_replace_entry_rejects_injection():
    for key, value in [
        ("vm.swappiness", "10\nvm.swappiness=99"),
        ("vm.swappiness", "10 # sneaky"),
        ("bad key", "10"),
        ("vm.swappiness", ""),
    ]:
        try:
            replace_entry(SYSCTL_CONF, 4, key, value)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {key!r}={value!r}")
    assert "99" not in SYSCTL_CONF


def test_replace_entry_detects_concurrent_edit():
    try:
        replace_entry(SYSCTL_CONF, 4, "vm.swappiness", "20", expected="vm.swappiness = 99")
    except ValueError as exc:
        assert "changed since" in str(exc)
    else:
        raise AssertionError("expected ValueError on a stale line")


def test_replace_entry_rejects_out_of_range_index():
    for index in (-1, 9999):
        try:
            replace_entry(SYSCTL_CONF, index, "vm.swappiness", "20")
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for index {index}")


def test_append_entry():
    result = append_entry(SYSCTL_CONF, "vm.swappiness", "5")
    assert result.count("vm.swappiness") == 2  # the existing one plus the new one
    assert result.rstrip().endswith("vm.swappiness = 5")
    assert append_entry("", "vm.swappiness", "5") == "vm.swappiness = 5\n"


def test_remove_entry():
    result = remove_entry(SYSCTL_CONF, 4)
    assert "vm.swappiness" not in result
    assert "vm.vfs_cache_pressure=50" in result
    assert "# Reduce swap tendency on database hosts" in result


def test_remove_entry_respects_expected():
    try:
        remove_entry(SYSCTL_CONF, 4, expected="vm.swappiness = 99")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on a stale line")


def test_render_entry_and_like():
    assert render_entry("vm.swappiness", "10") == "vm.swappiness = 10"
    assert render_like("vm.swappiness   =   10", "vm.swappiness", "20") == "vm.swappiness   =   20"
    assert render_like("vm.swappiness=10", "vm.swappiness", "20") == "vm.swappiness=20"
    # no recognisable original shape falls back to the standard form
    assert render_like("nonsense", "vm.swappiness", "20") == "vm.swappiness = 20"


def test_apply_problems_detects_procps_messages():
    assert apply_problems(CLEAN_OUTPUT) == []
    assert apply_problems("") == []
    for message in [
        'sysctl: setting key "vm.nope": No such file or directory',
        "sysctl: cannot stat /proc/sys/vm/nope",
        "sysctl: permission denied on key 'kernel.dmesg_restrict'",
        "sysctl: error while setting key 'vm.swappiness'",
    ]:
        assert apply_problems(message), message


def test_runtime_value_of_a_known_key():
    # /proc/sys/vm/overcommit_memory exists on Linux; elsewhere it is None
    value = runtime_value("vm.overcommit_memory")
    assert value is None or value.strip().isdigit()
    assert runtime_value("vm.definitely.not.a.real.key") is None
    # globs have no runtime value
    assert runtime_value("net.ipv4.conf.*.rp_filter") is None


def test_list_files_does_not_echo_exception_text():
    """A file that cannot be listed must not put raw OSError text in the body.

    The listing is served straight to the browser, and OSError messages carry
    paths and permissions the caller has no business seeing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        broken = pathlib.Path(tmp) / "broken"
        broken.mkdir()  # reading a directory raises, which is what we want
        original = sysctl_mod._iter_paths
        sysctl_mod._iter_paths = lambda: [broken]
        try:
            listing = sysctl_mod.list_files()
        finally:
            sysctl_mod._iter_paths = original
    entry = listing["files"][0]
    assert entry["kind"] == "error"
    assert entry["detail"] == sysctl_mod.READ_ERROR
    assert "Errno" not in entry["detail"]


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all sysctl tests passed")
