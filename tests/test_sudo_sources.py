"""sudo granted by groups, the panel's rule and other tools' rules."""

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.modules import sudoers, users  # noqa: E402
from linustart.util import CmdResult  # noqa: E402

SUDOERS = """Defaults env_reset
# User privilege specification
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
@includedir /etc/sudoers.d
"""


def test_grants_from_every_source():
    files = {"/etc/sudoers": SUDOERS,
             "/etc/sudoers.d/90-cloud-init-users": "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n",
             "/etc/sudoers.d/linustart-ubuntu": "ubuntu ALL=(ALL) ALL\n"}
    grants = users.sudo_grants("ubuntu", ["ubuntu", "sudo", "admin"], files)
    assert grants == [
        {"file": "/etc/sudoers", "via": "group sudo"},
        {"file": "/etc/sudoers", "via": "group admin"},
        {"file": "/etc/sudoers.d/90-cloud-init-users", "via": "user"},
        {"file": "/etc/sudoers.d/linustart-ubuntu", "via": "user"},
    ]
    assert users.sudo_grants("alice", ["alice"], files) == []
    # Defaults lines and comments are not rules
    assert users.sudo_grants("env_reset", [], {"x": "Defaults env_reset\n# alice ALL=(ALL) ALL\n"}) == []


def _machine(monkeypatch, tmp_path):
    etc = tmp_path / "etc"
    (etc / "sudoers.d").mkdir(parents=True)
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n")
    (etc / "group").write_text("sudo:x:27:ubuntu\nadmin:x:116:ubuntu\nubuntu:x:1000:\n")
    (etc / "sudoers").write_text(SUDOERS)
    (etc / "sudoers.d" / "90-cloud-init-users").write_text("ubuntu ALL=(ALL) NOPASSWD:ALL\n")
    (etc / "sudoers.d" / "linustart-ubuntu").write_text("ubuntu ALL=(ALL) ALL\n")
    (etc / "sudoers.d" / "README.dpkg-old").write_text("ubuntu ALL=(ALL) ALL\n")  # sudo skips names with '.'
    for module in (users, sudoers):
        monkeypatch.setattr(module, "SUDOERS_D", etc / "sudoers.d")
    monkeypatch.setattr(users, "SUDOERS_FILE", etc / "sudoers")
    monkeypatch.setattr(users, "PASSWD_FILE", etc / "passwd")
    monkeypatch.setattr(users, "GROUP_FILE", etc / "group")
    monkeypatch.setattr(users, "SHADOW_FILE", etc / "shadow")
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "gpasswd":  # emulate the removal in /etc/group
            group_file = etc / "group"
            lines = [line.replace(":ubuntu", ":") if line.startswith(f"{argv[3]}:") else line
                     for line in group_file.read_text().splitlines()]
            group_file.write_text("\n".join(lines) + "\n")
        return CmdResult(argv, 0, "", "")

    monkeypatch.setattr(users, "run", fake_run)
    return etc, calls


def test_turning_sudo_off_clears_what_the_panel_can(monkeypatch, tmp_path):
    etc, calls = _machine(monkeypatch, tmp_path)
    listed = asyncio.run(users.list_users())["users"]
    ubuntu = next(u for u in listed if u["name"] == "ubuntu")
    assert ubuntu["sudo"] and len(ubuntu["sudo_via"]) == 4
    remaining = asyncio.run(users.revoke_sudo("ubuntu"))
    assert ["gpasswd", "-d", "ubuntu", "admin"] in calls and ["gpasswd", "-d", "ubuntu", "sudo"] in calls
    assert not (etc / "sudoers.d" / "linustart-ubuntu").exists()
    # cloud-init's rule is reported back, not edited
    assert remaining == [{"file": str(etc / "sudoers.d" / "90-cloud-init-users"), "via": "user"}]
    assert (etc / "sudoers.d" / "90-cloud-init-users").exists()


def test_deleting_a_user_removes_the_panel_rule(monkeypatch, tmp_path):
    etc, calls = _machine(monkeypatch, tmp_path)
    asyncio.run(users.delete_user("ubuntu"))
    assert ["userdel", "ubuntu"] in calls
    assert not (etc / "sudoers.d" / "linustart-ubuntu").exists()
