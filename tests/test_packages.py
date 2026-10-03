"""Tests for apt output parsing and package name validation."""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart.modules.packages import (  # noqa: E402
    autoclean_command,
    autoremove_command,
    cache_stats,
    clean_command,
    install_command,
    parse_autoremove_simulation,
    parse_dpkg_query,
    parse_search_output,
    parse_upgrade_simulation,
    remove_command,
    validate_names,
)

SEARCH = """nginx - small, powerful, scalable web/proxy server
nginx-common - common files for nginx
curl - command line tool for transferring data with URL syntax
"""

DPKG = "curl\t7.88.1-10+deb12u8\tinstall ok installed\n\
removed-package\t1.0\tdeinstall ok config-files\n\
nginx\t1.22.1-9\tinstall ok installed\n"

SIM = """NOTE: This is only a simulation!
Inst libnginx-mod-http-geoip2 [1.22.1-9] (1.22.1-9+deb12u1 Debian:12.4/stable [amd64])
Inst nginx [1.22.1-9] (1.22.1-9+deb12u1 Debian:12.4/stable [amd64])
Conf nginx (1.22.1-9+deb12u1 Debian:12.4/stable [amd64])
"""


def test_parse_search():
    results = parse_search_output(SEARCH)
    assert [r["name"] for r in results] == ["nginx", "nginx-common", "curl"]
    assert results[0]["description"] == "small, powerful, scalable web/proxy server"


def test_parse_dpkg_query_skips_removed():
    packages = parse_dpkg_query(DPKG)
    assert [p["name"] for p in packages] == ["curl", "nginx"]
    assert packages[0]["version"] == "7.88.1-10+deb12u8"


def test_parse_upgrade_simulation():
    upgrades = parse_upgrade_simulation(SIM)
    assert [u["name"] for u in upgrades] == ["libnginx-mod-http-geoip2", "nginx"]
    assert upgrades[1]["old"] == "1.22.1-9"
    assert upgrades[1]["new"] == "1.22.1-9+deb12u1"


def test_validate_names_accepts_real_packages():
    assert validate_names(["nginx", "libssl3", "python3.11", "g++", "fonts-dejavu-core"]) == [
        "nginx",
        "libssl3",
        "python3.11",
        "g++",
        "fonts-dejavu-core",
    ]
    assert validate_names(["  curl  "]) == ["curl"]


def test_validate_names_rejects_injection():
    for bad in ["", "  ", "foo; rm -rf /", "foo && bar", "-rf", "../etc", "FOO", "$(x)"]:
        try:
            validate_names([bad])
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


AUTOREMOVE_SIM = """NOTE: This is only a simulation!
Remv libobsolete [2.0-1] (2.0-1 Debian:12/stable [amd64])
Remv old-dependency [1.0-3] (1.0-3 Debian:12/stable [amd64])
"""


def test_parse_autoremove_simulation():
    assert parse_autoremove_simulation(AUTOREMOVE_SIM) == ["libobsolete", "old-dependency"]
    assert parse_autoremove_simulation("NOTE: This is only a simulation!\n") == []


def test_cache_stats():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "a.deb").write_bytes(b"123")
        (root / "b.deb").write_bytes(b"12345")
        (root / "not-a-package.txt").write_bytes(b"1234567890")
        stats = cache_stats(root)
        assert stats["files"] == 2
        assert stats["size_bytes"] == 8


def test_cache_stats_missing_dir():
    stats = cache_stats(pathlib.Path("/nonexistent-cache-dir"))
    assert stats == {"size_bytes": 0, "files": 0}


def test_maintenance_commands():
    assert autoremove_command()[0] == "apt-get" and "autoremove" in autoremove_command()
    assert autoclean_command() == ["apt-get", "autoclean"]
    assert clean_command() == ["apt-get", "clean"]


def test_install_and_remove_commands():
    assert install_command(["curl"]) == ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef",
                                         "-o", "Dpkg::Options::=--force-confold", "install", "curl"]
    assert "remove" in remove_command(["curl"])


if __name__ == "__main__":
    for name, func in sorted(list(globals().items())):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok: {name}")
    print("all packages tests passed")
