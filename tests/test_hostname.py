"""Tests for hostname validation and /etc/hosts editing."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.hostname import update_hosts_content, valid_hostname  # noqa: E402


def test_valid_hostnames():
    assert valid_hostname("server1")
    assert valid_hostname("my-server.example.com")
    assert valid_hostname("a")
    assert valid_hostname("db-01")


def test_invalid_hostnames():
    assert not valid_hostname("")
    assert not valid_hostname("-leading")
    assert not valid_hostname("trailing-")
    assert not valid_hostname("has space")
    assert not valid_hostname("under_score")
    assert not valid_hostname("a" * 64)
    assert not valid_hostname("double..dot")


def test_update_hosts_replaces_existing_entry():
    content = "127.0.0.1\tlocalhost\n127.0.1.1\toldhost\n# comment\n"
    result = update_hosts_content(content, "newhost")
    assert "127.0.1.1\tnewhost" in result
    assert "oldhost" not in result
    assert "127.0.0.1\tlocalhost" in result
    assert "# comment" in result
    assert result.endswith("\n")


def test_update_hosts_keeps_aliases():
    content = "127.0.1.1\toldhost\talias1 alias2\n"
    result = update_hosts_content(content, "newhost")
    assert result == "127.0.1.1\tnewhost\talias1\talias2\n"


def test_update_hosts_adds_missing_entry():
    content = "127.0.0.1\tlocalhost\n"
    result = update_hosts_content(content, "newhost")
    assert "127.0.1.1\tnewhost" in result
    assert result.splitlines()[0] == "127.0.0.1\tlocalhost"


def test_update_hosts_empty_file():
    result = update_hosts_content("", "newhost")
    assert result == "127.0.1.1\tnewhost\n"


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all hostname tests passed")
