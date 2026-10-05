"""Confirm-or-revert sessions survive a panel restart."""

import asyncio
import json
import pathlib
import stat
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import audit, sessions as sessions_mod, util  # noqa: E402
from linustart.sessions import SessionManager  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", tmp_path / "audit.log")
    # restoring a snapshot backs the current file up first; keep that in the
    # sandbox (the real /var/lib/linustart is not writable for CI's user)
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    reapplied = []

    async def fake(spec):
        reapplied.append(dict(spec))

    monkeypatch.setitem(sessions_mod.REAPPLIERS, "network", fake)
    monkeypatch.setitem(sessions_mod.REAPPLIERS, "ssh", fake)
    target = tmp_path / "etc" / "conf"
    target.parent.mkdir(parents=True)
    target.write_text("new\n")
    return {
        "state": tmp_path / "state" / "pending-reverts.json",
        "target": target,
        "reapplied": reapplied,
    }


def test_pending_session_is_written_root_only_and_cleared_on_confirm(env):
    async def scenario():
        manager = SessionManager(env["state"])
        session = manager.create("ssh", "sshd", {str(env["target"]): "old\n"}, 90, {"kind": "ssh"})
        saved = json.loads(env["state"].read_text())
        assert saved[0]["id"] == session.id and saved[0]["snapshots"] == {str(env["target"]): "old\n"}
        assert stat.S_IMODE(env["state"].stat().st_mode) == 0o600
        await manager.confirm(session.id)
        assert not env["state"].exists()
        assert env["target"].read_text() == "new\n"

    asyncio.run(scenario())


def test_restart_resumes_and_reverts_on_schedule(env):
    async def scenario():
        first = SessionManager(env["state"])
        first.create("network", "eth0", {str(env["target"]): "old\n"}, 1,
                     {"kind": "network", "backend": "ifupdown", "name": "eth0"})
        for session in first.sessions.values():
            session.task.cancel()  # the panel "dies" before the deadline
        second = SessionManager(env["state"])
        assert second.resume() == 1
        await asyncio.sleep(1.3)
        return second

    second = asyncio.run(scenario())
    assert env["target"].read_text() == "old\n"
    assert env["reapplied"] == [{"kind": "network", "backend": "ifupdown", "name": "eth0"}]
    assert not env["state"].exists()
    assert all(s.done for s in second.sessions.values())


def test_overdue_revert_runs_immediately_after_restart(env):
    env["state"].parent.mkdir(parents=True)
    env["state"].write_text(json.dumps([{
        "id": "abc", "kind": "ssh", "label": "sshd",
        "snapshots": {str(env["target"]): "old\n"},
        "reapply": {"kind": "ssh"}, "expires_at": time.time() - 30,
    }]))

    async def scenario():
        manager = SessionManager(env["state"])
        manager.resume()
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
    assert env["target"].read_text() == "old\n"
    assert env["reapplied"] == [{"kind": "ssh"}]


def test_corrupt_state_file_is_ignored(env):
    env["state"].parent.mkdir(parents=True)
    env["state"].write_text("{not json")

    async def scenario():
        return SessionManager(env["state"]).resume()

    assert asyncio.run(scenario()) == 0


def test_unknown_reapply_kind_is_refused(env):
    async def scenario():
        with pytest.raises(ValueError):
            SessionManager(env["state"]).create("x", "x", {}, 90, {"kind": "nope"})

    asyncio.run(scenario())
