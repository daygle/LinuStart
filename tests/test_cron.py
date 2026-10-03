"""Tests for cron parsing, validation and editing."""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import cron as cron_mod  # noqa: E402
from linustart.modules.cron import (  # noqa: E402
    append_entry,
    parse_entries,
    remove_entry,
    render_entry,
    render_like,
    replace_entry,
    valid_command,
    valid_field,
    valid_schedule,
)

SYSTEM_CRONTAB = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin
MAILTO=root

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
# 30 4 * * *  root    old-job --legacy
25 6    * * *   root    /usr/local/bin/nightly-backup --verbose
"""

CRON_D = """# managed by ops
SHELL=/bin/bash
*/10 * * * * root /usr/local/bin/collect-metrics
@daily root /usr/local/bin/rotate-logs
# 0 3 * * 0 root weekly-report
"""

USER_CRONTAB = """# my jobs
*/5 * * * * /usr/local/bin/ping-site
@reboot /usr/local/bin/start-agent
# 0 2 * * * old-task
"""


def test_parse_system_crontab():
    entries = parse_entries(SYSTEM_CRONTAB, with_user=True)
    assert [entry.command for entry in entries] == [
        "cd / && run-parts --report /etc/cron.hourly",
        "test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily",
        "old-job --legacy",
        "/usr/local/bin/nightly-backup --verbose",
    ]
    assert entries[0].user == "root"
    assert entries[0].schedule == "17 * * * *"
    assert entries[0].enabled is True
    # a commented-out job is listed so it can be switched back on
    assert entries[2].enabled is False
    assert entries[3].command == "/usr/local/bin/nightly-backup --verbose"


def test_parse_ignores_env_and_prose():
    entries = parse_entries(SYSTEM_CRONTAB, with_user=True)
    raw_commands = " ".join(entry.command for entry in entries)
    assert "PATH=" not in raw_commands
    assert "m h dom mon dow" not in raw_commands  # the header comment


def test_parse_user_crontab_has_no_user_column():
    entries = parse_entries(USER_CRONTAB, with_user=False)
    assert [entry.schedule for entry in entries] == ["*/5 * * * *", "@reboot", "0 2 * * *"]
    assert entries[0].user == ""
    assert entries[0].command == "/usr/local/bin/ping-site"
    assert entries[1].enabled is True
    assert entries[2].enabled is False


def test_parse_special_schedules():
    entries = parse_entries(CRON_D, with_user=True)
    assert entries[1].schedule == "@daily"
    assert entries[1].user == "root"
    assert entries[2].enabled is False  # commented weekly report


def test_parse_rejects_wrong_field_count():
    # five schedule fields and no command is not a job
    assert parse_entries("*/5 * * * *\n", with_user=False) == []
    assert parse_entries("*/5 * * * * root\n", with_user=True) == []


def test_valid_schedule():
    for good in [
        "* * * * *",
        "*/5 * * * *",
        "0 3 * * 1-5",
        "17,23 * 1-15/2 jan,jul sun,sat",
        "0 0 1 jan *",
        "@daily",
        "@reboot",
        "@annually",
        "59 23 31 12 7",
    ]:
        assert valid_schedule(good), good
    for bad in [
        "",
        "* * * *",
        "* * * * * *",
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * * 13 *",
        "* * * * 8",
        "*/0 * * * *",
        "5-1 * * * *",
        "@sometimes",
        "*/5 * * * * rm -rf /",
    ]:
        assert not valid_schedule(bad), bad


def test_valid_field():
    assert valid_field("*", 0, 59)
    assert valid_field("*/15", 0, 59)
    assert valid_field("1-30", 1, 31)
    assert valid_field("1,2,3", 0, 59)
    assert valid_field("jan", 1, 12, {"jan": 1})
    assert not valid_field("1,,2", 0, 59)
    assert not valid_field("5-", 0, 59)
    assert not valid_field("-5", 0, 59)
    assert not valid_field("1-2-3", 0, 59)


def test_valid_command_rejects_injection():
    assert valid_command("/usr/local/bin/job --flag")
    assert not valid_command("")
    assert not valid_command("   ")
    # a newline would smuggle in a second job that cron runs as root
    assert not valid_command("/bin/true\n*/5 * * * * root /bin/evil")
    assert not valid_command("/bin/true\r\n0 3 * * * root /bin/evil")
    assert not valid_command("/bin/true\x00/evil")
    assert not valid_command("x" * 5000)


def test_validate_fields_messages():
    try:
        replace_entry("", 0, "not a schedule", "/bin/true", "root")
    except ValueError as exc:
        assert "schedule" in str(exc)
    else:
        raise AssertionError("expected ValueError for a bad schedule")

    try:
        append_entry("", "*/5 * * * *", "/bin/true\n0 3 * * * root /bin/evil", "root")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a newline in the command")

    # user crontabs must not grow a user column
    try:
        append_entry("", "*/5 * * * *", "/bin/true", "root", with_user=False)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a user column in a user crontab")


def test_replace_entry_preserves_everything_else():
    result = replace_entry(
        SYSTEM_CRONTAB, 8, "30 2 * * *", "/usr/local/bin/nightly-backup --quiet", "root"
    )
    assert "PATH=/usr/local/sbin" in result
    assert "# m h dom mon dow user  command" in result
    assert "run-parts --report /etc/cron.hourly" in result
    # the original column alignment survives an edit
    assert "30 2 * * *   root    /usr/local/bin/nightly-backup --quiet" in result
    entries = parse_entries(result, with_user=True)
    assert entries[3].schedule == "30 2 * * *"
    assert entries[3].command == "/usr/local/bin/nightly-backup --quiet"
    assert entries[2].command == "old-job --legacy"  # untouched neighbour


def test_replace_entry_can_disable_a_job():
    result = replace_entry(SYSTEM_CRONTAB, 8, "30 2 * * *", "/bin/true", "root", False)
    entries = parse_entries(result, with_user=True)
    disabled = [entry for entry in entries if not entry.enabled]
    assert len(disabled) == 2
    assert disabled[1].command == "/bin/true"


def test_replace_entry_detects_concurrent_edit():
    try:
        replace_entry(SYSTEM_CRONTAB, 8, "30 2 * * *", "/bin/true", "root", True,
                      expected="something else entirely")
    except ValueError as exc:
        assert "changed since" in str(exc)
    else:
        raise AssertionError("expected ValueError when the line moved under us")


def test_replace_entry_rejects_out_of_range_index():
    for index in (-1, 9999):
        try:
            replace_entry(SYSTEM_CRONTAB, index, "* * * * *", "/bin/true", "root")
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for index {index}")


def test_append_entry():
    result = append_entry(USER_CRONTAB, "15 3 * * 1", "/usr/local/bin/weekly", with_user=False)
    entries = parse_entries(result, with_user=False)
    assert entries[-1].schedule == "15 3 * * 1"
    assert entries[-1].command == "/usr/local/bin/weekly"
    assert "# my jobs" in result


def test_append_entry_to_empty_file():
    assert append_entry("", "@reboot", "/usr/local/bin/start", with_user=False) == (
        "@reboot /usr/local/bin/start\n"
    )


def test_remove_entry():
    result = remove_entry(SYSTEM_CRONTAB, 8)
    entries = parse_entries(result, with_user=True)
    assert "/usr/local/bin/nightly-backup --verbose" not in [e.command for e in entries]
    assert "PATH=/usr/local/sbin" in result
    assert "run-parts --report /etc/cron.hourly" in result


def test_remove_entry_respects_expected():
    try:
        remove_entry(SYSTEM_CRONTAB, 8, expected="17 * * * * root something-else")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on a stale line")


def test_render_like_keeps_column_alignment():
    original = "25 6    * * *   root    /usr/local/bin/nightly --verbose"
    rendered = render_like(original, "30 2 * * *", "/usr/local/bin/nightly --quiet", "root")
    assert rendered == "30 2 * * *   root    /usr/local/bin/nightly --quiet"
    # a user crontab keeps its single-space shape
    assert render_like("*/5 * * * * /bin/true", "@daily", "/bin/other") == "@daily /bin/other"
    assert render_like("*/5 * * * * /bin/true", "@daily", "/bin/other", enabled=False) == "# @daily /bin/other"


def test_render_entry():
    assert render_entry("*/5 * * * *", "/bin/true", "root") == "*/5 * * * * root /bin/true"
    assert render_entry("*/5 * * * *", "/bin/true") == "*/5 * * * * /bin/true"
    assert render_entry("@daily", "/bin/true", "root", False) == "# @daily root /bin/true"


def test_invalid_schedule_is_still_listed():
    """A broken job should be visible so it can be fixed, not hidden."""
    text = "99 * * * * root /bin/true\n"
    entries = parse_entries(text, with_user=True)
    assert len(entries) == 1
    assert entries[0].valid is False
    assert entries[0].command == "/bin/true"


def test_list_files_does_not_echo_exception_text():
    """A file that cannot be listed must not put raw OSError text in the body.

    The listing is served straight to the browser, and OSError messages carry
    paths and permissions the caller has no business seeing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        broken = pathlib.Path(tmp) / "broken"
        broken.mkdir()  # reading a directory raises, which is what we want
        original = cron_mod._iter_paths
        cron_mod._iter_paths = lambda: [broken]
        try:
            listing = cron_mod.list_files()
        finally:
            cron_mod._iter_paths = original
    entry = listing["files"][0]
    assert entry["kind"] == "error"
    assert entry["detail"] == cron_mod.READ_ERROR
    assert "Errno" not in entry["detail"]


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all cron tests passed")