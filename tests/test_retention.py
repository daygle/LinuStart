"""Audit log rotation and retention of backups and terminal recordings."""

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import audit, terminal, updater, util  # noqa: E402


def test_audit_log_rotates_and_reads_across_files(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_LOG", log)
    monkeypatch.setattr(audit, "MAX_BYTES", 400)
    monkeypatch.setattr(audit, "KEEP", 2)
    for index in range(40):
        audit.record("test", f"entry {index}")
    rotated = sorted(p.name for p in tmp_path.iterdir())
    assert rotated == ["audit.log", "audit.log.1", "audit.log.2"]  # nothing past KEEP
    assert all(p.stat().st_size < 600 for p in tmp_path.iterdir())
    newest = audit.read(10)
    assert [e["detail"] for e in newest[:3]] == ["entry 39", "entry 38", "entry 37"]
    # more than the current file holds: continues into audit.log.1
    current = len(log.read_text().splitlines())
    assert len(audit.read(current + 2)) == current + 2


def test_tail_lines_reads_only_the_end(tmp_path):
    path = tmp_path / "big.log"
    path.write_text("".join(json.dumps({"n": i}) + "\n" for i in range(20000)))
    assert audit.tail_lines(path, 3) == ['{"n": 19997}', '{"n": 19998}', '{"n": 19999}']
    assert audit.tail_lines(tmp_path / "missing", 3) == []


def test_backups_are_pruned_per_file(tmp_path, monkeypatch):
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setattr(util, "BACKUP_DIR", backups)
    flat = "etc__hosts"
    for day in range(1, 26):
        (backups / f"202601{day:02d}T000000-{flat}").write_text("x")
    other = backups / "20260101T000000-etc__ssh__sshd_config"
    lookalike = backups / "20260101T000000-x-etc__hosts"  # ends the same, different file
    other.write_text("x")
    lookalike.write_text("x")
    util.prune_backups(flat, keep=20)
    kept = sorted(p.name for p in backups.iterdir() if p.name.endswith(f"T000000-{flat}"))
    assert len(kept) == 20 and kept[0].startswith("20260106")
    assert other.exists() and lookalike.exists()


def test_backup_prunes_after_copying(tmp_path, monkeypatch):
    backups = tmp_path / "backups"
    monkeypatch.setattr(util, "BACKUP_DIR", backups)
    monkeypatch.setattr(util, "BACKUPS_PER_FILE", 2)
    source = tmp_path / "conf"
    source.write_text("v0\n")
    for version in range(1, 5):  # four rewrites within the same second
        util.write_text(source, f"v{version}\n")
    kept = sorted(backups.iterdir())
    assert len(kept) == 2
    # the two newest previous versions, none lost to a same-second name clash
    assert [p.read_text() for p in kept] == ["v2\n", "v3\n"]


def test_app_backups_keep_the_newest(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "APP_BACKUPS_KEPT", 2)
    app = tmp_path / "app"
    app.mkdir()
    (app / "f").write_text("x")
    store = tmp_path / "store"
    store.mkdir()
    for day in range(1, 5):
        (store / f"linustart-app-202601{day:02d}T000000.tar.gz").write_text("old")
    newest = updater.backup_tree(app, store)
    remaining = sorted(p.name for p in store.iterdir())
    assert len(remaining) == 2 and newest.name in remaining


def test_terminal_logs_are_pruned_and_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(terminal, "TERMINAL_LOG_DIR", tmp_path)
    for index in range(6):
        path = tmp_path / f"s{index}.log"
        path.write_text("x")
        os.utime(path, (1000 + index, 1000 + index))
    terminal.prune_logs(keep=3)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s3.log", "s4.log", "s5.log"]

    monkeypatch.setattr(terminal, "MAX_LOG_BYTES", 100)
    log = tmp_path / "cap.log"
    handle = log.open("a", encoding="utf-8")
    session = terminal.TerminalSession(
        id="cap", user="root", argv=[], cols=80, rows=24, proc=None,  # type: ignore[arg-type]
        master_fd=-1, log_path=str(log), log_handle=handle,
    )
    manager = terminal.TerminalManager()
    for _ in range(10):
        manager._log(session, "y" * 30)
    manager._log(session, "\n# closed\n", force=True)
    handle.close()
    text = log.read_text()
    assert "recording stopped" in text and text.endswith("# closed\n")
    assert text.count("y") <= 100
