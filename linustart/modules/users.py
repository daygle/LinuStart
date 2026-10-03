"""User account management: create, maintain and remove accounts and their
SSH keys, using the standard shadow-utils commands plus direct parsing of
/etc/passwd, /etc/shadow and /etc/group.

Pure helpers operate on file contents so they can be tested without root.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..paths import GROUP_FILE, PASSWD_FILE, SHADOW_FILE, SHELLS_FILE
from ..util import read_text, run, write_text

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
KEY_RE = re.compile(
    r"^(?P<type>ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r"\s+(?P<data>[A-Za-z0-9+/=]+)(?:\s+(?P<comment>.*))?$"
)

MIN_PASSWORD_LENGTH = 8
DEFAULT_SHELLS = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/sbin/nologin"]
SUDO_GROUP = "sudo"
ROOT_USER = "root"


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name.strip()))


def valid_password(password: str) -> bool:
    """Panel policy: length, and chpasswd-safe (no ':' or newlines)."""
    return (
        isinstance(password, str)
        and len(password) >= MIN_PASSWORD_LENGTH
        and ":" not in password
        and "\n" not in password
        and "\r" not in password
    )


def valid_authorized_key(line: str) -> bool:
    """Accept only lines whose key material decodes as a plausible key blob."""
    match = KEY_RE.match(line.strip())
    if not match:
        return False
    data = match.group("data")
    try:
        blob = base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(blob) >= 8


# --------------------------------------------------------------------------
# /etc/passwd, /etc/shadow, /etc/group parsing
# --------------------------------------------------------------------------

def parse_passwd(text: str) -> List[Dict[str, object]]:
    users: List[Dict[str, object]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue
        users.append(
            {
                "name": parts[0],
                "uid": uid,
                "gid": gid,
                "full_name": parts[4].split(",")[0],
                "home": parts[5],
                "shell": parts[6],
            }
        )
    return users


def visible_users(users: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    """Human accounts: root plus normal (uid >= 1000) users, minus nobody."""
    return [
        user
        for user in users
        if user["uid"] == 0 or (isinstance(user["uid"], int) and user["uid"] >= 1000 and user["uid"] != 65534)
    ]


def parse_shadow(text: str) -> Dict[str, Dict[str, bool]]:
    """name -> {locked, password_set}."""
    status: Dict[str, Dict[str, bool]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        name, _, rest = line.partition(":")
        password = rest.split(":", 1)[0]
        locked = password.startswith("!") or password.startswith("*")
        password_set = password not in ("", "!", "!!", "*", "!*") and not password.startswith("*")
        status[name] = {"locked": locked, "password_set": password_set}
    return status


def parse_group(text: str) -> List[Dict[str, object]]:
    groups: List[Dict[str, object]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        try:
            gid = int(parts[2])
        except ValueError:
            continue
        members = [m for m in parts[3].split(",") if m]
        groups.append({"name": parts[0], "gid": gid, "members": members})
    return groups


def memberships(groups: Sequence[Dict[str, object]], username: str, primary_gid: int) -> List[str]:
    names = [
        str(group["name"])
        for group in groups
        if username in group["members"] or group["gid"] == primary_gid
    ]
    return sorted(set(names))


# --------------------------------------------------------------------------
# authorized_keys
# --------------------------------------------------------------------------

def parse_authorized_keys(text: str) -> List[Dict[str, object]]:
    """Significant entries with their line index (comments/blank lines skipped)."""
    keys: List[Dict[str, object]] = []
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = KEY_RE.match(stripped)
        keys.append(
            {
                "index": index,
                "type": match.group("type") if match else "unknown",
                "comment": (match.group("comment") or "").strip() if match else "",
                "valid": valid_authorized_key(stripped),
                "raw": stripped,
            }
        )
    return keys


def add_authorized_key(content: str, key_line: str) -> str:
    """Append a key unless the same key material is already present."""
    stripped = key_line.strip()
    if not valid_authorized_key(stripped):
        raise ValueError("that does not look like an OpenSSH public key")
    data = KEY_RE.match(stripped).group("data")  # type: ignore[union-attr]
    for existing in parse_authorized_keys(content):
        match = KEY_RE.match(str(existing["raw"]))
        if match and match.group("data") == data:
            return content  # already there, keep as is
    if content and not content.endswith("\n"):
        content += "\n"
    return content + stripped + "\n"


def remove_authorized_key(content: str, index: int) -> str:
    lines = content.splitlines()
    if index < 0 or index >= len(lines):
        raise ValueError(f"no key at position {index}")
    del lines[index]
    return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------
# Async account operations
# --------------------------------------------------------------------------

def _passwd_entry(name: str) -> Dict[str, object]:
    for user in parse_passwd(read_text(PASSWD_FILE)):
        if user["name"] == name:
            return user
    raise ValueError(f"no such user: {name}")


def _shells() -> List[str]:
    shells = [
        line.strip()
        for line in read_text(SHELLS_FILE).splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return shells or list(DEFAULT_SHELLS)


def _keys_path(name: str) -> Path:
    entry = _passwd_entry(name)
    return Path(str(entry["home"])) / ".ssh" / "authorized_keys"


async def list_users() -> Dict[str, object]:
    passwd = parse_passwd(read_text(PASSWD_FILE))
    shadow = parse_shadow(read_text(SHADOW_FILE))
    groups = parse_group(read_text(GROUP_FILE))
    users = []
    for user in visible_users(passwd):
        state = shadow.get(str(user["name"]), {"locked": False, "password_set": False})
        groups_of = memberships(groups, str(user["name"]), int(user["gid"]))
        users.append(
            {
                **user,
                "locked": state["locked"],
                "password_set": state["password_set"],
                "groups": groups_of,
                "sudo": SUDO_GROUP in groups_of,
            }
        )
    users.sort(key=lambda u: (int(u["uid"]) != 0, int(u["uid"])))
    return {
        "users": users,
        "shells": _shells(),
        "groups": sorted(str(g["name"]) for g in groups),
    }


async def user_detail(name: str) -> Dict[str, object]:
    data = await list_users()
    for user in data["users"]:  # type: ignore[index]
        if user["name"] == name:
            return {"user": user, "keys": list_keys(name)}
    raise ValueError(f"no such user: {name}")


def list_keys(name: str) -> List[Dict[str, object]]:
    path = _keys_path(name)
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return parse_authorized_keys(content)


async def create_user(
    name: str,
    password: str,
    full_name: str = "",
    shell: str = "/bin/bash",
    sudo: bool = False,
    ssh_key: str = "",
) -> Dict[str, object]:
    name = name.strip()
    if not valid_username(name):
        raise ValueError(
            "usernames must start with a lowercase letter or '_', contain only "
            "lowercase letters, digits, '-', '_' and be at most 32 characters"
        )
    if any(user["name"] == name for user in parse_passwd(read_text(PASSWD_FILE))):
        raise ValueError(f"user already exists: {name}")
    if not valid_password(password):
        raise ValueError(f"passwords must be at least {MIN_PASSWORD_LENGTH} characters and free of ':'")
    if shell not in _shells():
        raise ValueError(f"not a valid login shell: {shell}")
    await run(
        ["useradd", "-m", "-s", shell, "-c", full_name.strip() or name, name],
        check=True,
    )
    await set_password(name, password)
    if sudo:
        await run(["usermod", "-aG", SUDO_GROUP, name], check=True)
    if ssh_key.strip():
        await add_key(name, ssh_key.strip())
    return await user_detail(name)


async def set_password(name: str, password: str) -> None:
    _passwd_entry(name)
    if not valid_password(password):
        raise ValueError(f"passwords must be at least {MIN_PASSWORD_LENGTH} characters and free of ':'")
    await run(["chpasswd"], input_text=f"{name}:{password}\n", check=True)


async def update_user(
    name: str,
    *,
    password: Optional[str] = None,
    full_name: Optional[str] = None,
    shell: Optional[str] = None,
    sudo: Optional[bool] = None,
    locked: Optional[bool] = None,
) -> Dict[str, object]:
    entry = _passwd_entry(name)
    if full_name is not None:
        await run(["usermod", "-c", full_name.strip() or name, name], check=True)
    if shell is not None:
        if shell not in _shells():
            raise ValueError(f"not a valid login shell: {shell}")
        await run(["usermod", "-s", shell, name], check=True)
    if password is not None:
        await set_password(name, password)
    if sudo is not None:
        if sudo:
            await run(["usermod", "-aG", SUDO_GROUP, name], check=True)
        else:
            result = await run(["gpasswd", "-d", name, SUDO_GROUP])
            if not result.ok and "not a member" not in (result.stdout + result.stderr):
                raise RuntimeError(f"removing {name} from {SUDO_GROUP} failed: {result.stderr.strip()}")
    if locked is not None:
        await run(["usermod", "-L" if locked else "-U", name], check=True)
    return await user_detail(name)


async def delete_user(name: str, remove_home: bool = False) -> None:
    _passwd_entry(name)
    if name == ROOT_USER:
        raise ValueError("refusing to delete root")
    argv = ["userdel"] + (["-r"] if remove_home else []) + [name]
    await run(argv, check=True)


async def add_key(name: str, key_line: str) -> List[Dict[str, object]]:
    entry = _passwd_entry(name)
    path = _keys_path(name)
    content = read_text(path)
    updated = add_authorized_key(content, key_line)
    if updated != content:
        write_text(path, updated)
        _secure_key_file(path, entry)
    return list_keys(name)


async def remove_key(name: str, index: int) -> List[Dict[str, object]]:
    entry = _passwd_entry(name)
    path = _keys_path(name)
    content = read_text(path)
    updated = remove_authorized_key(content, index)
    if updated == "":
        try:
            path.unlink()
        except OSError:
            pass
    else:
        write_text(path, updated)
        _secure_key_file(path, entry)
    return list_keys(name)


def _secure_key_file(path: Path, entry: Dict[str, object]) -> None:
    """Lock down ~/.ssh the way sshd requires."""
    ssh_dir = path.parent
    try:
        os.chmod(ssh_dir, 0o700)
        os.chmod(path, 0o600)
        os.chown(ssh_dir, int(entry["uid"]), int(entry["gid"]))  # type: ignore[arg-type]
        os.chown(path, int(entry["uid"]), int(entry["gid"]))  # type: ignore[arg-type]
    except (OSError, ValueError):
        # Non-root dev sandboxes can't chown; permissions still applied.
        pass
