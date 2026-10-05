"""Regression tests for the hardening and bug fixes from the code audit."""

import asyncio
import io
import os
import pathlib
import stat
import sys
import tarfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import util  # noqa: E402
from linustart.jobs import MAX_FINISHED_JOBS, STATUS_SUCCEEDED, Job, JobManager  # noqa: E402
from linustart.modules import users as users_mod  # noqa: E402
from linustart.modules.logs import journal_command  # noqa: E402
from linustart.modules.mail import (  # noqa: E402
    sasl_line,
    valid_email,
    valid_recipient,
    valid_sasl_username,
)
from linustart.modules.network import (  # noqa: E402
    update_ifupdown_interface,
    update_netplan_interface,
    validate_dns,
    validate_interface_name,
)
from linustart.modules.unattended import (  # noqa: E402
    BLACKLIST_KEY,
    ORIGINS_PATTERN_KEY,
    parse_block_list,
    upsert_block_list,
)
from linustart.updater import extract_tree, validate_member_types  # noqa: E402


@pytest.fixture
def backups(tmp_path, monkeypatch):
    target = tmp_path / "backups"
    monkeypatch.setattr(util, "BACKUP_DIR", target)
    return target


# --------------------------------------------------------------------------
# write_text keeps permissions
# --------------------------------------------------------------------------

def test_write_text_preserves_mode_of_replaced_file(tmp_path, backups):
    path = tmp_path / "hosts"
    path.write_text("old\n")
    os.chmod(path, 0o644)
    util.write_text(path, "new\n")
    assert path.read_text() == "new\n"
    # mkstemp creates 0600 files; /etc/hosts must not become root-only
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_write_text_new_file_is_world_readable_by_default(tmp_path, backups):
    path = tmp_path / "fresh.conf"
    util.write_text(path, "x\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_write_text_explicit_mode_wins(tmp_path, backups):
    path = tmp_path / "sasl_passwd"
    path.write_text("old\n")
    os.chmod(path, 0o644)
    util.write_text(path, "secret\n", mode=0o600)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # unchanged content still tightens the mode
    os.chmod(path, 0o644)
    util.write_text(path, "secret\n", mode=0o600)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --------------------------------------------------------------------------
# Input validation that guards config files and argv
# --------------------------------------------------------------------------

def test_interface_names_are_validated():
    assert validate_interface_name("eth0") == "eth0"
    assert validate_interface_name("enp0s31f6") == "enp0s31f6"
    assert validate_interface_name("eth0.100") == "eth0.100"
    for bad in ["", "-x", "eth0\n    pre-up /bin/sh", "a b", "a/b", "x" * 16]:
        with pytest.raises(ValueError):
            validate_interface_name(bad)


def test_ifupdown_refuses_injected_name_and_dns():
    with pytest.raises(ValueError):
        update_ifupdown_interface("", "eth0\n    up rm -rf /", "dhcp")
    with pytest.raises(ValueError):
        update_ifupdown_interface("", "eth0", "dhcp", dns=["1.1.1.1\n    up evil"])


def test_dns_servers_must_be_addresses():
    assert validate_dns(["1.1.1.1", " ", "2606:4700::1111"]) == ["1.1.1.1", "2606:4700::1111"]
    with pytest.raises(ValueError):
        validate_dns(["dns.example.com"])


def test_netplan_validates_dns():
    pytest.importorskip("yaml")
    with pytest.raises(ValueError):
        update_netplan_interface({}, "eth0", "dhcp", dns=["not-an-ip"])


def test_sasl_credentials_cannot_break_the_map():
    assert valid_sasl_username("me@example.com")
    for bad in ["", "a b", "a:b", "a\nb"]:
        assert not valid_sasl_username(bad)
    with pytest.raises(ValueError):
        sasl_line("[h]:587", "me@example.com", "pw\n[evil]:25 x:y")
    assert sasl_line("[h]:587", "me@example.com", "pass with spaces") == "[h]:587 me@example.com:pass with spaces"


def test_recipients_cannot_look_like_sendmail_options():
    assert valid_email("ops@example.com")
    assert not valid_email("-oQ@example.com")
    assert not valid_recipient("-bt@example.com")


def test_full_name_cannot_split_passwd_records():
    assert users_mod.valid_full_name("Bob Builder, Room 1")
    assert not users_mod.valid_full_name("evil:0:0")
    assert not users_mod.valid_full_name("a\nroot2::0:0::/:/bin/sh")


def test_journal_accepts_template_units():
    assert journal_command(50, unit="getty@tty1.service")[-2:] == ["-u", "getty@tty1.service"]
    with pytest.raises(ValueError):
        journal_command(50, unit="-x")


# --------------------------------------------------------------------------
# ~/.ssh symlink redirection
# --------------------------------------------------------------------------

def _fake_user(monkeypatch, home):
    entry = {"name": "eve", "uid": 1001, "gid": 1001, "home": str(home), "shell": "/bin/bash", "full_name": ""}
    monkeypatch.setattr(users_mod, "_passwd_entry", lambda name: entry)
    return entry


def test_keys_path_refuses_symlinked_ssh_dir(tmp_path, monkeypatch):
    home = tmp_path / "home" / "eve"
    home.mkdir(parents=True)
    victim = tmp_path / "root" / ".ssh"
    victim.mkdir(parents=True)
    (home / ".ssh").symlink_to(victim)
    _fake_user(monkeypatch, home)
    with pytest.raises(ValueError):
        users_mod._keys_path("eve")
    # listing never reads through the link
    assert users_mod.list_keys("eve") == []


def test_keys_path_refuses_symlinked_authorized_keys(tmp_path, monkeypatch):
    home = tmp_path / "home" / "eve"
    (home / ".ssh").mkdir(parents=True)
    secret = tmp_path / "shadow"
    secret.write_text("root:$6$hash:::\n")
    (home / ".ssh" / "authorized_keys").symlink_to(secret)
    _fake_user(monkeypatch, home)
    with pytest.raises(ValueError):
        users_mod._keys_path("eve")


def test_keys_path_accepts_a_normal_home(tmp_path, monkeypatch):
    home = tmp_path / "home" / "eve"
    home.mkdir(parents=True)
    _fake_user(monkeypatch, home)
    assert users_mod._keys_path("eve") == home / ".ssh" / "authorized_keys"


# --------------------------------------------------------------------------
# unattended-upgrades comment handling
# --------------------------------------------------------------------------

DEBIAN_STOCK = """Unattended-Upgrade::Origins-Pattern {
        // Codename based matching:
//      "origin=Debian,codename=${distro_codename}-updates";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "site=http://deb.example.org//debian";
};
Unattended-Upgrade::Package-Blacklist {
    // The following matches all packages starting with linux-
//  "linux-";
    // the $, "libc6" would match all of them.
//  "libc6$";
};
"""


def test_commented_entries_are_not_active():
    assert parse_block_list(DEBIAN_STOCK, BLACKLIST_KEY) == []
    assert parse_block_list(DEBIAN_STOCK, ORIGINS_PATTERN_KEY) == [
        "origin=Debian,codename=${distro_codename},label=Debian-Security",
        "site=http://deb.example.org//debian",
    ]


def test_saving_does_not_enable_commented_entries():
    text = upsert_block_list(DEBIAN_STOCK, BLACKLIST_KEY, parse_block_list(DEBIAN_STOCK, BLACKLIST_KEY))
    assert parse_block_list(text, BLACKLIST_KEY) == []
    assert '"linux-";' not in text.replace('//  "linux-";', "")


# --------------------------------------------------------------------------
# Updater archive safety
# --------------------------------------------------------------------------

def _tar_with(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    buffer.seek(0)
    return buffer


def test_archive_symlink_leaving_tree_is_refused(tmp_path):
    link = tarfile.TarInfo("pkg/etc")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc"
    with pytest.raises(ValueError):
        validate_member_types([link])
    link.linkname = "../../etc"
    with pytest.raises(ValueError):
        validate_member_types([link])


def test_archive_device_nodes_are_refused():
    node = tarfile.TarInfo("pkg/null")
    node.type = tarfile.CHRTYPE
    with pytest.raises(ValueError):
        validate_member_types([node])


def test_extract_tree_still_extracts_plain_archives(tmp_path):
    info = tarfile.TarInfo("pkg/file.txt")
    data = b"hello"
    info.size = len(data)
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(_tar_with([(info, data)]).getvalue())
    top = extract_tree(archive, tmp_path / "out")
    assert (top / "file.txt").read_bytes() == b"hello"


# --------------------------------------------------------------------------
# Job history is bounded
# --------------------------------------------------------------------------

def test_finished_jobs_are_pruned():
    manager = JobManager()
    for index in range(MAX_FINISHED_JOBS + 20):
        job = Job(id=f"j{index}", kind="k", description="d", argv=["true"], status=STATUS_SUCCEEDED)
        manager.jobs[job.id] = job
        manager._order.append(job.id)
    running = Job(id="live", kind="k", description="d", argv=["sleep"])
    manager.jobs["live"] = running
    manager._order.append("live")
    manager._prune()
    assert "live" in manager.jobs
    assert len(manager.jobs) == MAX_FINISHED_JOBS + 1
    assert "j0" not in manager.jobs and f"j{MAX_FINISHED_JOBS + 19}" in manager.jobs
    assert len(manager._order) == len(manager.jobs)


def test_job_survives_an_overlong_output_line():
    async def scenario():
        manager = JobManager()
        job = await manager.start("t", "long line", [sys.executable, "-c", "print('x' * 1500000); print('done')"])
        for _ in range(200):
            if job.status != "running":
                break
            await asyncio.sleep(0.05)
        return job

    job = asyncio.run(scenario())
    assert job.status == STATUS_SUCCEEDED
    assert job.lines[-1] == "done"


# --------------------------------------------------------------------------
# API authentication and the terminal WebSocket
# --------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from linustart import audit
    from linustart.app import create_app
    from linustart.settings import Settings

    monkeypatch.setattr(audit, "AUDIT_LOG", tmp_path / "audit.log")
    app = create_app(Settings(token="s3cret-token"))
    with TestClient(app) as test_client:
        yield test_client


def test_api_requires_the_bearer_token(client):
    assert client.get("/api/audit").status_code == 401
    assert client.get("/api/audit", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/audit", headers={"Authorization": "Basic s3cret-token"}).status_code == 401
    assert client.get("/api/audit", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
    assert client.get("/api/health").status_code == 200  # public liveness probe


def test_terminal_ws_rejects_a_foreign_origin(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            "/api/terminal/ws", headers={"origin": "https://evil.example"}
        ) as ws:
            ws.receive_json()
    assert excinfo.value.code == 4403


def test_terminal_ws_requires_the_token_message(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/terminal/ws") as ws:
            ws.send_json({"type": "auth", "token": "wrong"})
            ws.receive_json()
    assert excinfo.value.code == 4401


def test_no_auth_flag_overrides_the_public_bind_refusal(monkeypatch, tmp_path):
    from linustart import __main__ as cli

    started = []
    monkeypatch.setitem(sys.modules, "uvicorn", type("U", (), {"run": staticmethod(lambda *a, **k: started.append(k))}))
    monkeypatch.setattr(cli, "create_app", lambda settings: object())
    missing = str(tmp_path / "none.json")
    assert cli.main(["--config", missing, "--host", "0.0.0.0"]) == 2
    assert not started
    assert cli.main(["--config", missing, "--host", "0.0.0.0", "--no-auth"]) == 0
    assert started and started[0]["host"] == "0.0.0.0"


def test_terminal_ws_origin_check_allows_reverse_proxies(client):
    from starlette.websockets import WebSocketDisconnect

    # passes the origin check, then fails auth - proving the origin was accepted
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            "/api/terminal/ws",
            headers={"origin": "https://panel.example.com", "x-forwarded-host": "panel.example.com"},
        ) as ws:
            ws.send_json({"type": "auth", "token": "wrong"})
            ws.receive_json()
    assert excinfo.value.code == 4401


# --------------------------------------------------------------------------
# ifupdown: files pulled in with source / source-directory
# --------------------------------------------------------------------------

from linustart.modules import network as network_mod  # noqa: E402
from linustart.modules import timezone as timezone_mod  # noqa: E402

MAIN = "auto lo\niface lo inet loopback\n\nsource /etc/network/interfaces.d/*\n"
DROPIN_DHCP = "auto eth0\niface eth0 inet dhcp\n"


def test_parse_source_directives():
    text = MAIN + "source-directory interfaces.d\n# source /nope\n"
    assert network_mod.parse_source_directives(text) == [
        ("source", "/etc/network/interfaces.d/*"),
        ("source-directory", "interfaces.d"),
    ]


def test_interface_defined_in_a_dropin_is_edited_there():
    docs = {"/main": MAIN, "/d/eth0": DROPIN_DHCP}
    updated, changed = network_mod.apply_ifupdown_across(
        docs, "/main", "eth0", "static", "10.0.0.5/24", "10.0.0.1", ["1.1.1.1"]
    )
    assert changed == ["/d/eth0"]  # the main file is left alone
    assert "iface eth0 inet static" in updated["/d/eth0"]
    assert updated["/d/eth0"].count("auto eth0") == 1
    assert "eth0" not in updated["/main"]


def test_duplicate_stanzas_in_other_files_are_removed():
    main = MAIN + "\nauto eth0\niface eth0 inet static\n    address 10.0.0.9\n    netmask 255.255.255.0\n"
    docs = {"/main": main, "/d/eth0": DROPIN_DHCP}
    updated, changed = network_mod.apply_ifupdown_across(
        docs, "/main", "eth0", "static", "10.0.0.5/24", None, []
    )
    assert sorted(changed) == ["/d/eth0", "/main"]
    assert "address 10.0.0.5" in updated["/main"]
    # the leftover DHCP stanza is gone; the drop-in's auto line may stay
    assert "inet dhcp" not in updated["/d/eth0"]
    assert network_mod.stanza_counts("".join(updated.values())).get("eth0 inet") == 1


def test_new_interface_goes_to_the_main_file_without_a_second_auto():
    docs = {"/main": MAIN, "/d/hotplug": "auto eth1\n"}
    updated, changed = network_mod.apply_ifupdown_across(docs, "/main", "eth1", "dhcp")
    assert changed == ["/main"]
    assert "iface eth1 inet dhcp" in updated["/main"]
    assert "auto eth1" not in updated["/main"]  # already brought up elsewhere


def test_ifupdown_files_follow_source_lines(tmp_path, monkeypatch):
    netdir = tmp_path / "etc" / "network"
    (netdir / "interfaces.d").mkdir(parents=True)
    (netdir / "extra").mkdir()
    main = netdir / "interfaces"
    main.write_text(MAIN + "source-directory extra\n")
    (netdir / "interfaces.d" / "eth0").write_text(DROPIN_DHCP)  # no .cfg suffix
    (netdir / "interfaces.d" / "eth1.cfg").write_text("iface eth1 inet dhcp\n")
    (netdir / "extra" / "eth2").write_text("iface eth2 inet dhcp\n")
    (netdir / "extra" / "eth2.dpkg-old").write_text("iface eth2 inet static\n")  # run-parts skips
    monkeypatch.setattr(network_mod, "ROOT", tmp_path)
    monkeypatch.setattr(network_mod, "INTERFACES_FILE", main)
    names = [p.relative_to(netdir).as_posix() for p in network_mod.ifupdown_files()]
    assert names == ["interfaces", "interfaces.d/eth0", "interfaces.d/eth1.cfg", "extra/eth2"]
    assert network_mod.managed_config_files("ifupdown") == network_mod.ifupdown_files()

    config = asyncio.run(network_mod.get_config("ifupdown"))
    by_name = {iface["name"]: iface for iface in config["interfaces"]}
    assert set(by_name) == {"eth0", "eth1", "eth2"}
    assert by_name["eth0"]["source"].endswith("interfaces.d/eth0")


def test_source_lines_cannot_escape_the_root():
    assert network_mod._rooted_relative("../../etc/shadow") is None
    assert network_mod._rooted_relative("/etc/network/interfaces.d/*") == "etc/network/interfaces.d/*"
    assert network_mod._rooted_relative("interfaces.d/*") == "etc/network/interfaces.d/*"


# --------------------------------------------------------------------------
# timezone cache sees zones added in subdirectories
# --------------------------------------------------------------------------

def test_timezone_cache_picks_up_a_new_zone_in_a_subdirectory(tmp_path, monkeypatch):
    base = tmp_path / "zoneinfo"
    (base / "America").mkdir(parents=True)
    (base / "America" / "New_York").write_bytes(b"TZif")
    (base / "UTC").write_bytes(b"TZif")
    monkeypatch.setattr(timezone_mod, "ZONEINFO_DIR", base)
    assert timezone_mod.list_timezones() == ["America/New_York", "UTC"]

    # what a tzdata upgrade does: a new file in a subdirectory only
    top_mtime = base.stat().st_mtime
    (base / "America" / "Ciudad_Juarez").write_bytes(b"TZif")
    os.utime(base / "America", (top_mtime + 5, top_mtime + 5))
    os.utime(base, (top_mtime, top_mtime))
    assert "America/Ciudad_Juarez" in timezone_mod.list_timezones()
