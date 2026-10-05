"""Tests for user account parsing and authorized_keys handling."""

import base64
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.users import (  # noqa: E402
    MAX_KEY_LENGTH,
    add_authorized_key,
    memberships,
    parse_authorized_keys,
    parse_group,
    parse_passwd,
    parse_shadow,
    remove_authorized_key,
    update_authorized_key,
    valid_authorized_key,
    valid_password,
    valid_username,
    visible_users,
)

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bob:x:1000:1000:Bob Builder,Room 1,,:/home/bob:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""

SHADOW = """root:*:19000:0:99999:7:::
bob:$6$xyz$fakehash:19000:0:99999:7:::
lockeduser:!$6$abc$fakehash:19000:0:99999:7:::
expired:!:19000:0:99999:7:::
"""

GROUP = """sudo:x:27:bob,alice
users:x:100:bob
bob:x:1000:
"""

# Fake but valid base64 key material (real keys always decode cleanly).
BLOB1 = base64.b64encode(b"fake-key-material-for-tests-0123456789").decode()
BLOB2 = base64.b64encode(b"another-fake-key-material-for-tests").decode()
BLOB3 = base64.b64encode(b"brand-new-key-material-for-tests").decode()

KEYS = f"""# managed by hand
ssh-ed25519 {BLOB1} bob@laptop

ssh-rsa {BLOB2} alice@desktop second comment
"""


def test_valid_username():
    assert valid_username("bob")
    assert valid_username("deploy_user")
    assert valid_username("_svc")
    assert valid_username("a" * 32)
    for bad in ["", "Bob", "1stuser", "has space", "a" * 33, "bad/name", "-dash"]:
        assert not valid_username(bad), bad


def test_valid_password():
    assert valid_password("longenough")
    assert valid_password("p@ss:w0rd".replace(":", "!"))
    for bad in ["", "short", "has:colon1", "has\nnewline1", 12345678, "seven77"]:
        assert not valid_password(bad), repr(bad)


def test_parse_passwd():
    users = parse_passwd(PASSWD)
    assert [u["name"] for u in users] == ["root", "daemon", "bob", "nobody"]
    bob = users[2]
    assert bob["uid"] == 1000
    assert bob["home"] == "/home/bob"
    assert bob["shell"] == "/bin/bash"
    assert bob["full_name"] == "Bob Builder"  # gecos fields after the first are dropped


def test_visible_users():
    users = parse_passwd(PASSWD)
    names = [u["name"] for u in visible_users(users)]
    assert names == ["root", "bob"]  # daemon and nobody are system accounts


def test_parse_shadow():
    status = parse_shadow(SHADOW)
    assert status["root"]["locked"] is True
    assert status["root"]["password_set"] is False
    assert status["bob"]["locked"] is False
    assert status["bob"]["password_set"] is True
    assert status["lockeduser"]["locked"] is True
    assert status["expired"]["password_set"] is False


def test_parse_group_and_memberships():
    groups = parse_group(GROUP)
    assert groups[0]["members"] == ["bob", "alice"]
    assert memberships(groups, "bob", 1000) == ["bob", "sudo", "users"]
    assert memberships(groups, "alice", 1001) == ["sudo"]
    assert memberships(groups, "carol", 1002) == []


def test_valid_authorized_key():
    assert valid_authorized_key(f"ssh-ed25519 {BLOB1} bob@laptop")
    assert valid_authorized_key(f"ssh-rsa {BLOB2}")
    assert valid_authorized_key(f"ecdsa-sha2-nistp256 {BLOB1}")
    for bad in ["", "not a key", "ssh-ed25519", "ssh-ed25519 not-a-key!!", f"ssh-unknown-type {BLOB1}"]:
        assert not valid_authorized_key(bad), bad


def test_parse_authorized_keys():
    keys = parse_authorized_keys(KEYS)
    assert len(keys) == 2
    assert keys[0]["type"] == "ssh-ed25519"
    assert keys[0]["comment"] == "bob@laptop"
    assert keys[0]["index"] == 1  # line 0 is the comment
    assert keys[1]["comment"] == "alice@desktop second comment"


def test_add_authorized_key_appends():
    result = add_authorized_key(KEYS, f"ssh-ed25519 {BLOB3} carol@desktop")
    keys = parse_authorized_keys(result)
    assert len(keys) == 3
    assert keys[2]["comment"] == "carol@desktop"


def test_add_authorized_key_dedupes():
    result = add_authorized_key(KEYS, f"ssh-ed25519 {BLOB1} someone@else")
    assert result == KEYS


def test_add_authorized_key_rejects_garbage():
    try:
        add_authorized_key(KEYS, "rm -rf /")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a non-key line")


def test_valid_authorized_key_refuses_oversized_line():
    # A real key line is a few hundred bytes; the cap is checked before the
    # pattern runs so untrusted input cannot make us do unbounded work.
    oversized = "ssh-ed25519 " + ("A" * (MAX_KEY_LENGTH + 1))
    assert not valid_authorized_key(oversized)
    # Padding it out with a comment does not get it under the cap either.
    sneaky = "ssh-ed25519 " + BLOB1 + " " + ("c" * MAX_KEY_LENGTH)
    assert not valid_authorized_key(sneaky)


def test_valid_authorized_key_still_accepts_real_lines():
    # The hardening must not narrow what a genuine key looks like.
    assert valid_authorized_key(f"  ssh-ed25519 {BLOB1} bob@laptop  ")
    assert valid_authorized_key(f"ssh-rsa {BLOB2}")
    assert valid_authorized_key(f"ecdsa-sha2-nistp521 {BLOB1} a comment")
    assert valid_authorized_key(f"ssh-ed25519 {BLOB1} comment with spaces")
    # A comment may contain spaces once it has started.
    assert valid_authorized_key(f"ssh-ed25519 {BLOB1} two words here")


def test_valid_authorized_key_anchors_the_comment_on_a_word():
    # The comment is anchored on a non-space character, so any run of spaces
    # or tabs between the key and the comment is consumed by the separator
    # alone. Letting the comment match whitespace too is what let one tab run
    # be split between the two quantifiers in a growing number of ways, which
    # CodeQL flagged as polynomial backtracking.
    for gap in (" ", "\t", "  ", "\t\t", " \t "):
        line = f"ssh-ed25519 {BLOB1}{gap}bob@laptop"
        assert valid_authorized_key(line), repr(line)
        keys = parse_authorized_keys(line + "\n")
        assert keys[0]["comment"] == "bob@laptop", repr(gap)
    # A line that is only key material and separators is still a valid key.
    assert valid_authorized_key(f"ssh-ed25519 {BLOB1} ")
    assert valid_authorized_key(f"ssh-ed25519 {BLOB1}")


def test_valid_authorized_key_refuses_a_second_line():
    # A newline would let one submitted line install two keys.
    assert not valid_authorized_key(f"ssh-ed25519 {BLOB1}\nssh-rsa {BLOB2}")
    try:
        add_authorized_key(KEYS, f"ssh-ed25519 {BLOB3}\nssh-rsa {BLOB2}")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an embedded newline")


def test_valid_authorized_key_is_not_quadratic_on_whitespace():
    # Separator and comment must not both be able to match the same tab run,
    # or one long run of whitespace can be split between them in a growing
    # number of ways. The bound is loose so it cannot flake on a slow machine;
    # it only fails if the pattern goes back to exploring splits.
    import time

    for filler in (" ", "\t", " \t " * 3):
        crafted = "ssh-ed25519 " + (filler * 20000) + "!"
        started = time.perf_counter()
        assert not valid_authorized_key(crafted)
        assert time.perf_counter() - started < 2.0, f"blowing up on {filler!r}"


def test_remove_authorized_key():
    result = remove_authorized_key(KEYS, 1)
    keys = parse_authorized_keys(result)
    assert len(keys) == 1
    assert keys[0]["comment"] == "alice@desktop second comment"
    try:
        remove_authorized_key(result, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an out-of-range index")


def test_update_authorized_key_replaces_in_place():
    # index 1 is bob's key; the surrounding comment and blank line survive.
    result = update_authorized_key(KEYS, 1, f"ssh-ed25519 {BLOB3} carol@desktop")
    assert result.startswith("# managed by hand\n")
    assert parse_authorized_keys(result)[0]["comment"] == "carol@desktop"
    # alice's key is still there, still on the same line
    assert parse_authorized_keys(result)[1]["comment"] == "alice@desktop second comment"
    assert parse_authorized_keys(result)[1]["index"] == 3


def test_update_authorized_key_allows_its_own_material():
    # Re-saving a key unchanged must not trip the duplicate check.
    same = f"ssh-ed25519 {BLOB1} bob@laptop"
    assert update_authorized_key(KEYS, 1, same) == KEYS


def test_update_authorized_key_refuses_a_duplicate_elsewhere():
    try:
        update_authorized_key(KEYS, 1, f"ssh-rsa {BLOB2} alice@desktop")
    except ValueError as exc:
        assert "already installed" in str(exc)
    else:
        raise AssertionError("expected ValueError when the key already exists")


def test_update_authorized_key_refuses_a_comment_line():
    # list_keys only hands out real key indices; replacing the header comment
    # would silently drop it, so it is an error rather than a quiet deletion.
    try:
        update_authorized_key(KEYS, 0, f"ssh-ed25519 {BLOB3} carol@desktop")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError when the line is a comment")


def test_update_authorized_key_validates_and_bounds_checks():
    for bad_index in [-1, 99]:
        try:
            update_authorized_key(KEYS, bad_index, f"ssh-ed25519 {BLOB3} carol@desktop")
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for index {bad_index}")
    try:
        update_authorized_key(KEYS, 1, "rm -rf /")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a non-key replacement")


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all users tests passed")
