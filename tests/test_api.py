"""HTTP API tests: every route is guarded, and endpoints behave end to end.

System-changing module functions are replaced with fakes, so these tests
exercise routing, validation, audit logging and the confirm-or-revert flow
without touching the machine.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from linustart import audit, metrics, routes, sessions, updater, util  # noqa: E402
from linustart.app import create_app  # noqa: E402
from linustart.settings import Settings  # noqa: E402

TOKEN = "api-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(sessions, "PENDING_REVERTS_FILE", tmp_path / "pending.json")
    monkeypatch.setattr(metrics, "METRICS_FILE", tmp_path / "metrics.json")
    monkeypatch.setattr(metrics, "ALERTS_FILE", tmp_path / "alerts.json")
    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    calls = []

    async def reapply(spec):
        calls.append(("reapply", dict(spec)))

    for kind in ("network", "ssh", "firewall", "dhcpcd"):
        monkeypatch.setitem(sessions.REAPPLIERS, kind, reapply)
    app = create_app(Settings(token=TOKEN))
    with TestClient(app) as client:
        yield client, tmp_path, calls, monkeypatch


def audit_text(tmp_path):
    path = tmp_path / "audit.log"
    return path.read_text() if path.exists() else ""


# --------------------------------------------------------------------------
# every route requires the token
# --------------------------------------------------------------------------

PUBLIC = {"/api/health", "/api/terminal/ws", "/api/docs", "/api/openapi.json", "/api/docs/oauth2-redirect"}


def test_every_api_route_rejects_requests_without_a_token(env):
    client, *_ = env
    # the OpenAPI schema lists every HTTP endpoint, however routers are nested
    schema = client.app.openapi()
    checked = 0
    for path, operations in schema["paths"].items():
        if path in PUBLIC:
            continue
        concrete = path.replace("{", "").replace("}", "")  # /api/users/{name} -> /api/users/name
        for method in operations:
            response = client.request(method.upper(), concrete, json={})
            assert response.status_code == 401, f"{method.upper()} {path} answered {response.status_code}"
            checked += 1
    assert checked > 60  # the whole API, not a handful


# --------------------------------------------------------------------------
# system
# --------------------------------------------------------------------------

def test_hostname_validation_and_audit(env):
    client, tmp_path, _, monkeypatch = env

    async def fake_set(name):
        return name

    monkeypatch.setattr(routes.hostname_mod, "set_hostname", fake_set)
    assert client.post("/api/hostname", json={"hostname": "web-01"}, headers=AUTH).json() == {"hostname": "web-01"}
    assert "hostname set to web-01" in audit_text(tmp_path)

    async def refuse(name):
        raise ValueError("invalid hostname")

    monkeypatch.setattr(routes.hostname_mod, "set_hostname", refuse)
    assert client.post("/api/hostname", json={"hostname": "bad name"}, headers=AUTH).status_code == 400


def test_audit_endpoint_returns_newest_first(env):
    client, *_ = env
    audit.record("test.one", "first")
    audit.record("test.two", "second")
    entries = client.get("/api/audit?limit=2", headers=AUTH).json()["entries"]
    assert [e["action"] for e in entries] == ["test.two", "test.one"]


# --------------------------------------------------------------------------
# network: apply, confirm, revert, roll back on failure
# --------------------------------------------------------------------------

def _fake_network(monkeypatch, tmp_path, *, fail_apply=False):
    conf = tmp_path / "interfaces"
    conf.write_text("old\n")

    async def backend():
        return "ifupdown"

    async def write(backend, name, method, address, gateway, dns, ipv6=None):
        conf.write_text("new\n")

    async def apply(backend, name=None):
        if fail_apply:
            raise RuntimeError("ifup failed")
        return [f"ifup {name}"]

    monkeypatch.setattr(routes.network_mod, "detect_backend", backend)
    monkeypatch.setattr(routes.network_mod, "managed_config_files", lambda b: [conf])
    monkeypatch.setattr(routes.network_mod, "write_interface_config", write)
    monkeypatch.setattr(routes.network_mod, "apply_backend", apply)
    return conf


def test_network_change_opens_a_session_that_can_be_confirmed(env):
    client, tmp_path, _, monkeypatch = env
    conf = _fake_network(monkeypatch, tmp_path)
    result = client.post("/api/network/interfaces/eth0", headers=AUTH,
                         json={"method": "static", "address": "10.0.0.5/24"}).json()
    assert result["session"]["seconds_left"] > 80 and conf.read_text() == "new\n"
    pending = client.get("/api/sessions", headers=AUTH).json()["sessions"]
    assert [s["id"] for s in pending] == [result["session"]["id"]]
    assert client.post(f"/api/sessions/{result['session']['id']}/confirm", headers=AUTH).json()["confirmed"]
    assert client.get("/api/sessions", headers=AUTH).json()["sessions"] == []
    assert conf.read_text() == "new\n"


def test_network_change_can_be_reverted(env):
    client, tmp_path, calls, monkeypatch = env
    conf = _fake_network(monkeypatch, tmp_path)
    session = client.post("/api/network/interfaces/eth0", headers=AUTH,
                          json={"method": "dhcp"}).json()["session"]
    client.post(f"/api/sessions/{session['id']}/revert", headers=AUTH)
    assert conf.read_text() == "old\n"
    assert calls == [("reapply", {"kind": "network", "backend": "ifupdown", "name": "eth0"})]


def test_failed_network_apply_restores_files(env):
    client, tmp_path, _, monkeypatch = env
    conf = _fake_network(monkeypatch, tmp_path, fail_apply=True)
    response = client.post("/api/network/interfaces/eth0", headers=AUTH, json={"method": "dhcp"})
    assert response.status_code == 500 and conf.read_text() == "old\n"
    assert client.get("/api/sessions", headers=AUTH).json()["sessions"] == []


def test_network_rejects_bad_input(env):
    client, tmp_path, _, monkeypatch = env
    _fake_network(monkeypatch, tmp_path)
    assert client.post("/api/network/interfaces/eth0", headers=AUTH, json={"method": "bogus"}).status_code == 422
    assert client.post("/api/network/interfaces/eth0", headers=AUTH,
                       json={"method": "dhcp", "ipv6_method": "static"}).status_code == 400


def test_unknown_session_is_404(env):
    client, *_ = env
    assert client.post("/api/sessions/nope/confirm", headers=AUTH).status_code == 404


# --------------------------------------------------------------------------
# validation on the other write endpoints
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/packages/install", {"names": ["bad name; rm -rf /"]}),
    ("post", "/api/users", {"username": "Bad", "password": "longenough1"}),
    ("post", "/api/processes/kill", {"pid": 1}),
    ("post", "/api/disk/scan", {"path": "relative/path"}),
    ("post", "/api/services/-x/action/start", None),
    ("post", "/api/services/sshd/action/mask", None),
    ("post", "/api/ssh", {}),
    ("post", "/api/groups", {"name": "Bad Group"}),
    ("post", "/api/metrics/alerts", {"cpu": 500}),
    ("post", "/api/update/install", {"tag": "v1; rm -rf /"}),
    ("get", "/api/logs/journal?after_cursor=$(id)", None),
    ("get", "/api/logs/files/..%2Fshadow", None),
])
def test_write_endpoints_validate_input(env, method, path, body):
    client, *_ = env
    response = getattr(client, method)(path, headers=AUTH, **({"json": body} if body is not None else {}))
    assert response.status_code in (400, 404, 422), f"{path} -> {response.status_code}"


def test_package_install_starts_a_job(env):
    client, tmp_path, _, monkeypatch = env
    monkeypatch.setattr(routes.packages_mod, "install_command", lambda names: ["true"])
    job = client.post("/api/packages/install", headers=AUTH, json={"names": ["htop"]}).json()
    assert job["kind"] == "packages.install"
    assert client.get(f"/api/jobs/{job['id']}", headers=AUTH).status_code == 200
    assert client.get("/api/jobs/missing", headers=AUTH).status_code == 404
    assert "htop" in audit_text(tmp_path)


# --------------------------------------------------------------------------
# metrics, updates
# --------------------------------------------------------------------------

def test_metrics_and_alert_settings(env):
    client, *_ = env
    data = client.get("/api/metrics", headers=AUTH).json()
    assert {"samples", "interval", "cpus", "alerts"} <= set(data)
    saved = client.post("/api/metrics/alerts", headers=AUTH,
                        json={"enabled": True, "disk": 80, "recipient": "ops@example.com"}).json()
    assert saved["config"]["disk"] == 80 and saved["thresholds"]["disk"] == 80
    assert client.get("/api/metrics", headers=AUTH).json()["alerts"]["config"]["enabled"] is True


def test_update_check_without_releases(env):
    client, _, _, monkeypatch = env

    def none(repo):
        raise updater.NoReleases("none")

    monkeypatch.setattr(routes.updater_mod, "latest_release", none)
    data = client.get("/api/update/check", headers=AUTH).json()
    assert data["no_releases"] is True and data["newer_available"] is False


def test_update_check_reports_checksums(env):
    client, _, _, monkeypatch = env
    release = updater.parse_release({
        "tag_name": "v99.0.0", "tarball_url": "https://api.github.com/x",
        "assets": [{"name": "linustart-v99.0.0.tar.gz", "browser_download_url": "https://github.com/a"},
                   {"name": "SHA256SUMS", "browser_download_url": "https://github.com/b"}],
    })
    monkeypatch.setattr(routes.updater_mod, "latest_release", lambda repo: release)
    data = client.get("/api/update/check", headers=AUTH).json()
    assert data["newer_available"] and data["checksum_published"]


def _fake_resolver(monkeypatch, backend, **summary):
    async def detect():
        return backend

    async def status(_backend=None):
        return {"dns_setting_applies": False, "has_resolvconf": False, **summary}

    monkeypatch.setattr(routes.network_mod, "detect_backend", detect)
    monkeypatch.setattr(routes.network_mod, "resolver_status", status)


def test_resolvconf_install_starts_a_job_where_dns_does_not_apply(env):
    client, tmp_path, _, monkeypatch = env
    _fake_resolver(monkeypatch, "ifupdown")
    monkeypatch.setattr(routes.resolvconf_mod, "command", lambda: ["true"])
    job = client.post("/api/network/resolvconf", headers=AUTH).json()
    assert job["kind"] == "network.resolvconf"
    assert "resolvconf" in audit_text(tmp_path)


@pytest.mark.parametrize("backend,summary", [
    ("netplan", {}),
    ("ifupdown", {"has_resolvconf": True}),
    ("ifupdown", {"dns_setting_applies": True}),
])
def test_resolvconf_install_is_refused_where_it_is_not_needed(env, backend, summary):
    client, _, _, monkeypatch = env
    _fake_resolver(monkeypatch, backend, **summary)
    monkeypatch.setattr(routes.resolvconf_mod, "command", lambda: ["false"])
    assert client.post("/api/network/resolvconf", headers=AUTH).status_code == 400


MAILCOW = {"detected": True, "kind": "mailcow", "detail": "mailcow containers: postfix-mailcow"}


def _fake_mail_server(monkeypatch, server):
    async def status():
        return server

    monkeypatch.setattr(routes.mail_mod, "mail_server_status", status)


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/mail/install?transport=postfix", None),
    ("post", "/api/mail/remove-conflicts", None),
    ("post", "/api/mail", {"host": "mail.example.com", "port": 587, "security": "starttls",
                           "username": "u@example.com", "from_address": "u@example.com",
                           "password": "pw", "report_to": "ops@example.com", "transport": "postfix"}),
])
def test_a_mail_server_is_never_touched(env, method, path, body):
    client, tmp_path, _, monkeypatch = env
    _fake_mail_server(monkeypatch, MAILCOW)

    async def must_not_run(*args, **kwargs):
        raise AssertionError("reached the mail server")

    monkeypatch.setattr(routes.mail_mod, "preseed_postfix", must_not_run)
    monkeypatch.setattr(routes.mail_mod, "apply", must_not_run)
    response = getattr(client, method)(path, headers=AUTH, **({"json": body} if body else {}))
    assert response.status_code == 409
    assert "mail server" in response.json()["detail"]
    assert "mail.refused" in audit_text(tmp_path)


def test_msmtp_install_on_a_mail_server_never_removes_packages(env):
    client, _, _, monkeypatch = env
    _fake_mail_server(monkeypatch, MAILCOW)
    seen = []

    def install_command(transport, mail_server=False):
        seen.append((transport, mail_server))
        return ["true"]

    monkeypatch.setattr(routes.mail_mod, "install_command", install_command)
    job = client.post("/api/mail/install?transport=msmtp", headers=AUTH).json()
    assert job["kind"] == "mail.install"
    assert seen == [("msmtp", True)]


def test_mail_page_reports_the_mail_server(env):
    client, _, _, monkeypatch = env
    _fake_mail_server(monkeypatch, MAILCOW)
    assert client.get("/api/mail", headers=AUTH).json()["mail_server"]["kind"] == "mailcow"


def _fake_findings(monkeypatch, found):
    async def backend():
        return "ifupdown"

    async def config(_backend=None):
        return {"interfaces": []}

    async def findings(_backend, _config):
        return found

    monkeypatch.setattr(routes.network_mod, "detect_backend", backend)
    monkeypatch.setattr(routes.network_mod, "get_config", config)
    monkeypatch.setattr(routes.nethealth_mod, "findings", findings)


def test_network_fix_needs_a_current_finding(env):
    client, _, _, monkeypatch = env
    _fake_findings(monkeypatch, [{"id": "nm-unmanaged", "fix": None}])
    assert client.post("/api/network/fix/cloud-init", headers=AUTH).status_code == 400
    assert client.post("/api/network/fix/nm-unmanaged", headers=AUTH).status_code == 400


def test_network_fix_cloud_init(env):
    client, tmp_path, _, monkeypatch = env
    _fake_findings(monkeypatch, [{"id": "cloud-init", "fix": {"label": "x"}}])
    target = tmp_path / "99-disable-network-config.cfg"
    monkeypatch.setattr(routes.nethealth_mod, "CLOUD_DISABLE_FILE", target)
    assert client.post("/api/network/fix/cloud-init", headers=AUTH).json()["ok"]
    assert "config: disabled" in target.read_text()
    assert "cloud-init" in audit_text(tmp_path)


def test_network_fix_dhcpcd_opens_a_revert_session(env):
    client, tmp_path, calls, monkeypatch = env
    _fake_findings(monkeypatch, [{"id": "dhcpcd", "fix": {"label": "x"}}])
    conf = tmp_path / "dhcpcd.conf"
    conf.write_text("hostname\n")
    monkeypatch.setattr(routes.network_mod, "DHCPCD_CONF", conf)
    monkeypatch.setattr(routes.nethealth_mod, "DHCPCD_CONF", conf)

    async def conflicts():
        return ["ens18"]

    async def apply(names):
        return [f"ifup {n}" for n in names]

    monkeypatch.setattr(routes.nethealth_mod, "dhcpcd_conflicts", conflicts)
    monkeypatch.setattr(routes.nethealth_mod, "apply_dhcpcd_fix", apply)
    result = client.post("/api/network/fix/dhcpcd", headers=AUTH).json()
    assert "denyinterfaces ens18" in conf.read_text()
    session = result["session"]
    # reverting puts the old dhcpcd.conf back and re-applies through the dhcpcd re-applier
    client.post(f"/api/network/sessions/{session['id']}/revert", headers=AUTH)
    assert conf.read_text() == "hostname\n"
    assert ("reapply", {"kind": "dhcpcd", "names": "ens18"}) in calls
