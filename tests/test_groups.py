"""Group listing, protection rules and the commands that change groups."""

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules import groups as groups_mod  # noqa: E402
from linustart.util import CmdResult  # noqa: E402

PASSWD = """root:x:0:0:root:/root:/bin/bash
bob:x:1000:1000:Bob:/home/bob:/bin/bash
alice:x:1001:1001:Alice:/home/alice:/bin/bash
"""
GROUP = """root:x:0:
sudo:x:27:bob
bob:x:1000:
alice:x:1001:
devs:x:1002:bob,alice
nogroup:x:65534:
"""


@pytest.fixture
def system(tmp_path, monkeypatch):
    (tmp_path / "passwd").write_text(PASSWD)
    (tmp_path / "group").write_text(GROUP)
    monkeypatch.setattr(groups_mod, "PASSWD_FILE", tmp_path / "passwd")
    monkeypatch.setattr(groups_mod, "GROUP_FILE", tmp_path / "group")
    ran = []

    async def fake_run(argv, **kwargs):
        ran.append(list(argv))
        return CmdResult(argv, 0, "", "")

    monkeypatch.setattr(groups_mod, "run", fake_run)
    return ran


def test_groups_are_described_with_protection_flags(system):
    data = asyncio.run(groups_mod.list_groups())
    by_name = {g["name"]: g for g in data["groups"]}
    assert by_name["devs"]["deletable"] and by_name["devs"]["members"] == ["bob", "alice"]
    assert not by_name["bob"]["deletable"] and by_name["bob"]["primary_of"] == ["bob"]
    assert by_name["sudo"]["system"] and not by_name["sudo"]["deletable"]
    assert by_name["nogroup"]["system"]
    assert data["users"] == ["alice", "bob", "root"]
    # regular groups first
    assert not data["groups"][0]["system"]


def test_create_validates_and_runs_groupadd(system):
    asyncio.run(groups_mod.create_group("web", system=True))
    assert system == [["groupadd", "--system", "web"]]
    for bad in ["", "Web", "-x", "a b", "devs"]:
        with pytest.raises(ValueError):
            asyncio.run(groups_mod.create_group(bad))


def test_delete_refuses_system_and_primary_groups(system):
    for name in ["sudo", "bob", "missing"]:
        with pytest.raises(ValueError):
            asyncio.run(groups_mod.delete_group(name))
    asyncio.run(groups_mod.delete_group("devs"))
    assert system == [["groupdel", "devs"]]


def test_members_are_added_and_removed_with_gpasswd(system):
    asyncio.run(groups_mod.add_member("sudo", "alice"))
    asyncio.run(groups_mod.add_member("sudo", "bob"))  # already a member: no command
    asyncio.run(groups_mod.remove_member("devs", "alice"))
    assert system == [["gpasswd", "-a", "alice", "sudo"], ["gpasswd", "-d", "alice", "devs"]]
    with pytest.raises(ValueError):
        asyncio.run(groups_mod.add_member("sudo", "nobody-here"))
    with pytest.raises(ValueError):
        asyncio.run(groups_mod.remove_member("devs", "root"))
