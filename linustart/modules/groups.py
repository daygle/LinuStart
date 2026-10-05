"""Group management: create and delete groups and maintain their members.

Groups are read straight from /etc/group (pure helpers, testable without
root) and changed with the shadow-utils commands (groupadd, groupdel,
gpasswd), which keep /etc/gshadow in step. System groups (GID below 1000)
and any user's primary group are never deleted from the panel.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..paths import GROUP_FILE, PASSWD_FILE
from ..util import read_text, run
from .users import parse_group, parse_passwd, valid_username

FIRST_REGULAR_GID = 1000
NOGROUP_GID = 65534


def valid_group_name(name: str) -> bool:
    # same rules as user names (useradd/groupadd NAME_REGEX on Debian)
    return valid_username(name)


def describe_groups(
    groups: Sequence[Dict[str, object]], users: Sequence[Dict[str, object]]
) -> List[Dict[str, object]]:
    """Groups with members, whose primary group they are, and protection flags."""
    primary: Dict[int, List[str]] = {}
    for user in users:
        primary.setdefault(int(user["gid"]), []).append(str(user["name"]))  # type: ignore[arg-type]
    described = []
    for group in groups:
        gid = int(group["gid"])  # type: ignore[arg-type]
        system = gid < FIRST_REGULAR_GID or gid == NOGROUP_GID
        primary_of = sorted(primary.get(gid, []))
        described.append({
            "name": group["name"],
            "gid": gid,
            "members": list(group["members"]),  # type: ignore[arg-type]
            "primary_of": primary_of,
            "system": system,
            "deletable": not system and not primary_of,
        })
    described.sort(key=lambda g: (bool(g["system"]), str(g["name"])))
    return described


def _load() -> List[Dict[str, object]]:
    return describe_groups(parse_group(read_text(GROUP_FILE)), parse_passwd(read_text(PASSWD_FILE)))


def _group(name: str) -> Dict[str, object]:
    for group in _load():
        if group["name"] == name:
            return group
    raise ValueError(f"no such group: {name}")


def _user_exists(name: str) -> bool:
    return any(user["name"] == name for user in parse_passwd(read_text(PASSWD_FILE)))


async def list_groups() -> Dict[str, object]:
    users = sorted(str(u["name"]) for u in parse_passwd(read_text(PASSWD_FILE)))
    return {"groups": _load(), "users": users}


async def create_group(name: str, system: bool = False) -> Dict[str, object]:
    name = (name or "").strip()
    if not valid_group_name(name):
        raise ValueError(
            "group names must start with a lowercase letter or '_', contain only "
            "lowercase letters, digits, '-', '_' and be at most 32 characters"
        )
    if any(group["name"] == name for group in _load()):
        raise ValueError(f"group already exists: {name}")
    await run(["groupadd"] + (["--system"] if system else []) + [name], check=True)
    return await list_groups()


async def delete_group(name: str) -> Dict[str, object]:
    group = _group(name)
    if group["system"]:
        raise ValueError(f"refusing to delete system group {name}")
    if group["primary_of"]:
        raise ValueError(f"{name} is the primary group of {', '.join(group['primary_of'])}")  # type: ignore[arg-type]
    await run(["groupdel", name], check=True)
    return await list_groups()


async def add_member(name: str, user: str) -> Dict[str, object]:
    group = _group(name)
    if not _user_exists(user):
        raise ValueError(f"no such user: {user}")
    if user in group["members"]:  # type: ignore[operator]
        return await list_groups()
    await run(["gpasswd", "-a", user, name], check=True)
    return await list_groups()


async def remove_member(name: str, user: str) -> Dict[str, object]:
    group = _group(name)
    if user not in group["members"]:  # type: ignore[operator]
        raise ValueError(f"{user} is not a member of {name}")
    await run(["gpasswd", "-d", user, name], check=True)
    return await list_groups()
