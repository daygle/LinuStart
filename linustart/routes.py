"""HTTP API routes for LinuStart."""

from __future__ import annotations

import asyncio
import functools
import hmac
from typing import Awaitable, Callable, Dict, List, Optional, Union
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from . import audit
from . import metrics as metrics_mod
from . import updater as updater_mod
from .jobs import JobManager
from .modules import disk as disk_mod
from .modules import firewall as firewall_mod
from .modules import groups as groups_mod
from .modules import hostname as hostname_mod
from .modules import logs as logs_mod
from .modules import mail as mail_mod
from .modules import network as network_mod
from .modules import nethealth as nethealth_mod
from .modules import packages as packages_mod
from .modules import power as power_mod
from .modules import procs as procs_mod
from .modules import resolvconf as resolvconf_mod
from .modules import services as services_mod
from .modules import sshd as sshd_mod
from .modules import cron as cron_mod
from .modules import sudoers as sudoers_mod
from .modules import sysctl as sysctl_mod
from .modules import sysinfo as sysinfo_mod
from .modules import timezone as timezone_mod
from .modules import unattended as unattended_mod
from .modules import users as users_mod
from .ratelimit import AuthThrottle, client_key
from .sessions import SessionManager
from .settings import Settings
from .terminal import TerminalManager
from .util import restore_files, snapshot_files


# --------------------------------------------------------------------------
# Request bodies
# --------------------------------------------------------------------------

class HostnameBody(BaseModel):
    hostname: str


class TimezoneBody(BaseModel):
    timezone: str


class NtpBody(BaseModel):
    enabled: bool


class PowerBody(BaseModel):
    action: str = Field(pattern="^(reboot|shutdown)$")
    delay: Optional[Union[int, str]] = None
    # The UI must opt in explicitly; without it a stray POST cannot take the
    # machine down.
    confirm: bool = False


class InterfaceBody(BaseModel):
    method: str = Field(pattern="^(static|dhcp|manual)$")
    address: Optional[str] = None
    gateway: Optional[str] = None
    dns: List[str] = Field(default_factory=list)
    # None leaves IPv6 exactly as it is
    ipv6_method: Optional[str] = Field(default=None, pattern="^(none|auto|dhcp|static)$")
    ipv6_address: Optional[str] = None
    ipv6_gateway: Optional[str] = None


class UpdatesBody(BaseModel):
    enabled: Optional[bool] = None
    update_frequency_days: Optional[str] = None
    download_upgradeable_packages: Optional[bool] = None
    autoclean_interval: Optional[str] = None
    auto_reboot: Optional[bool] = None
    auto_reboot_time: Optional[str] = None
    auto_reboot_withusers: Optional[bool] = None
    auto_fix_interrupted_dpkg: Optional[bool] = None
    remove_unused: Optional[bool] = None
    remove_new_unused_dependencies: Optional[bool] = None
    remove_unused_dependencies: Optional[bool] = None
    origins: Optional[List[str]] = None
    origins_style: Optional[str] = Field(default=None, pattern="^(pattern|allowed)$")
    package_blacklist: Optional[List[str]] = None
    report_to: Optional[str] = None
    report_mode: Optional[str] = Field(default=None, pattern="^(always|only-on-error|on-change)$")


class MailBody(BaseModel):
    host: str
    port: int = Field(default=587, ge=1, le=65535)
    security: str = Field(default="starttls", pattern="^(starttls|ssl|none)$")
    username: str = ""
    password: Optional[str] = None
    from_address: str = ""
    report_to: Optional[str] = ""
    report_mode: Optional[str] = Field(default="only-on-error", pattern="^(always|only-on-error|on-change)$")
    transport: str = Field(default="postfix", pattern="^(postfix|msmtp)$")


class MailTestBody(BaseModel):
    recipient: str = ""


class PackagesBody(BaseModel):
    names: List[str]


class UpgradeBody(BaseModel):
    full: bool = False


class UserCreateBody(BaseModel):
    username: str
    password: str
    full_name: str = ""
    shell: str = "/bin/bash"
    sudo: bool = False
    ssh_key: str = ""


class UserUpdateBody(BaseModel):
    password: Optional[str] = None
    full_name: Optional[str] = None
    shell: Optional[str] = None
    sudo: Optional[bool] = None
    locked: Optional[bool] = None


class GroupBody(BaseModel):
    name: str
    system: bool = False


class MemberBody(BaseModel):
    user: str


class KeyBody(BaseModel):
    key: str


class SshBody(BaseModel):
    port: Optional[int] = None
    permit_root_login: Optional[str] = None
    password_authentication: Optional[bool] = None
    pubkey_authentication: Optional[bool] = None
    x11_forwarding: Optional[bool] = None
    max_auth_tries: Optional[int] = None
    client_alive_interval: Optional[int] = None
    client_alive_count_max: Optional[int] = None


class FirewallPolicyBody(BaseModel):
    enabled: Optional[bool] = None
    default_incoming: Optional[str] = Field(default=None, pattern="^(allow|deny)$")
    default_outgoing: Optional[str] = Field(default=None, pattern="^(allow|deny)$")


class FirewallRuleBody(BaseModel):
    action: str
    direction: str
    protocol: str = "any"
    port: str = ""
    address: str = "any"


class OverrideBody(BaseModel):
    content: str = ""


class AlertsBody(BaseModel):
    enabled: bool = False
    cpu: float = 90
    mem: float = 90
    disk: float = 90
    load_per_cpu: float = 2.0
    sustain_minutes: float = 5
    cooldown_minutes: float = 360
    recipient: str = ""


class DiskScanBody(BaseModel):
    path: str


class KillBody(BaseModel):
    pid: int
    signal: str = Field(default="TERM", pattern="^(TERM|KILL|HUP|INT|SIGTERM|SIGKILL|SIGHUP|SIGINT)$")


class AgingBody(BaseModel):
    max_days: Optional[int] = None
    warn_days: Optional[int] = None
    expiry: Optional[str] = None


class CronBody(BaseModel):
    path: str
    schedule: str = ""
    command: str = ""
    user: str = ""
    enabled: bool = True
    index: int = -1  # -1 appends a new job
    expected: str = ""  # the raw line as loaded; refuses stale edits


class CronDeleteBody(BaseModel):
    path: str
    index: int
    expected: str = ""


class CronFileBody(BaseModel):
    path: str


class SysctlBody(BaseModel):
    path: str
    key: str = ""
    value: str = ""
    index: int = -1  # -1 appends a new setting
    expected: str = ""  # the raw line as loaded; refuses stale edits


class SysctlDeleteBody(BaseModel):
    path: str
    index: int
    expected: str = ""


class SysctlFileBody(BaseModel):
    path: str


class SudoersBody(BaseModel):
    nopasswd: bool = False


class UpdateInstallBody(BaseModel):
    tag: str = ""


# --------------------------------------------------------------------------
# Router factory
# --------------------------------------------------------------------------

def build_router(
    settings: Settings,
    jobs: JobManager,
    sessions: SessionManager,
    terminals: TerminalManager,
    recorder: Optional[metrics_mod.MetricsRecorder] = None,
) -> APIRouter:
    router = APIRouter()

    def token_ok(candidate: Optional[str]) -> bool:
        """Constant-time token comparison, so response timing leaks nothing."""
        if not settings.auth_enabled:
            return True
        return hmac.compare_digest(
            (candidate or "").encode("utf-8"), str(settings.token).encode("utf-8")
        )

    throttle = AuthThrottle()

    def locked_out(key: str) -> int:
        return throttle.retry_after(key)

    def note_failure(key: str) -> None:
        if throttle.failure(key):
            audit.record(
                "auth.lockout",
                f"{key} locked out for {throttle.lockout // 60} minutes after "
                f"{throttle.max_failures} wrong tokens",
                ok=False,
            )

    async def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> None:
        if not settings.auth_enabled:
            return
        key = client_key(request.client.host if request.client else None)
        wait = locked_out(key)
        if wait:
            raise HTTPException(
                status_code=429,
                detail=f"too many wrong tokens; try again in {wait} seconds",
                headers={"Retry-After": str(wait)},
            )
        scheme, _, token = (authorization or "").partition(" ")
        if scheme == "Bearer" and token_ok(token):
            throttle.success(key)
            return
        if authorization:  # a missing header is not a guess
            note_failure(key)
        raise HTTPException(status_code=401, detail="invalid or missing token")

    guard = [Depends(require_auth)]

    async def restore_and_reapply(
        snapshots: Dict[str, str], reapply: Callable[[], Awaitable[object]], kind: str
    ) -> None:
        """Undo a failed apply: restore the files, then load them again.

        Restoring files alone is not enough when the failure came after the
        live state was already changed (a firewall command or an interface
        restart); the restored files have to be applied for the old state to
        actually come back.
        """
        restore_files(snapshots)
        try:
            await reapply()
        except Exception as exc:  # noqa: BLE001 - the original error is what the caller reports
            audit.record(f"{kind}.revert", f"re-applying the previous configuration failed: {exc}", ok=False)

    # ---- system ----------------------------------------------------------
    @router.get("/system/overview", dependencies=guard)
    async def overview() -> Dict[str, object]:
        data = sysinfo_mod.overview()
        data["hostname"] = await hostname_mod.current()
        return data

    @router.get("/hostname", dependencies=guard)
    async def get_hostname() -> Dict[str, object]:
        return {"hostname": await hostname_mod.current(), "cloud_init": hostname_mod.cloud_init_status()}

    @router.post("/hostname", dependencies=guard)
    async def set_hostname(body: HostnameBody) -> Dict[str, object]:
        cloud = hostname_mod.cloud_init_status()
        try:
            name = await hostname_mod.set_hostname(body.hostname)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("hostname.set", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("hostname.set", f"hostname set to {name}"
                     + (f"; cloud-init told to keep it ({hostname_mod.CLOUD_HOSTNAME_FILE})" if cloud["managed"] else ""))
        return {"hostname": name, "cloud_init_preserved": bool(cloud["managed"])}

    @router.get("/timezone", dependencies=guard)
    async def get_timezone() -> Dict[str, object]:
        status = await timezone_mod.status()
        status["zones"] = timezone_mod.list_timezones()
        return status

    @router.post("/timezone", dependencies=guard)
    async def set_timezone(body: TimezoneBody) -> Dict[str, object]:
        try:
            await timezone_mod.set_timezone(body.timezone)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("timezone.set", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("timezone.set", f"timezone set to {body.timezone}")
        return await timezone_mod.status()

    @router.get("/power", dependencies=guard)
    async def power_status() -> Dict[str, object]:
        return await power_mod.status()

    @router.post("/power", dependencies=guard)
    async def power_schedule(body: PowerBody) -> Dict[str, object]:
        if not body.confirm:
            raise HTTPException(
                status_code=400,
                detail="confirm must be true to schedule a reboot or shutdown",
            )
        try:
            result = await power_mod.schedule(body.action, body.delay)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("power.schedule", f"{body.action} failed: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record(
            "power.schedule",
            f"{result['action']} scheduled {result['when']} (unit {result['unit']})",
        )
        return result

    @router.post("/power/cancel", dependencies=guard)
    async def power_cancel(body: PowerBody) -> Dict[str, object]:
        try:
            result = await power_mod.cancel(body.action)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("power.cancel", f"{body.action} failed: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        if result["cancelled"]:
            audit.record("power.cancel", f"cancelled pending {result['action']}")
        return result

    @router.post("/ntp", dependencies=guard)
    async def set_ntp(body: NtpBody) -> Dict[str, object]:
        try:
            await timezone_mod.set_ntp(body.enabled)
        except RuntimeError as exc:
            audit.record("ntp.set", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("ntp.set", f"ntp {'enabled' if body.enabled else 'disabled'}")
        return await timezone_mod.status()

    # ---- network ---------------------------------------------------------
    @router.get("/network", dependencies=guard)
    async def network() -> Dict[str, object]:
        backend = await network_mod.detect_backend()
        resolver = await network_mod.resolver_status(backend)
        resolver["can_install_resolvconf"] = resolvconf_mod.setup_offered(backend, resolver)
        config = await network_mod.get_config(backend)
        return {
            "backend": backend,
            "config": config,
            "runtime": await network_mod.runtime_status(),
            "resolver": resolver,
            "findings": await nethealth_mod.findings(backend, config),
            "sessions": [s.to_dict() for s in sessions.pending()],
        }

    @router.post("/network/fix/{finding_id}", dependencies=guard)
    async def network_fix(finding_id: str) -> Dict[str, object]:
        backend = await network_mod.detect_backend()
        config = await network_mod.get_config(backend)
        current = {f["id"]: f for f in await nethealth_mod.findings(backend, config)}
        if finding_id not in current or not current[finding_id].get("fix"):
            raise HTTPException(status_code=400, detail=f"nothing to fix for {finding_id!r} on this machine")
        if finding_id == "cloud-init":
            done = nethealth_mod.fix_cloud_init()
            audit.record("network.fix", f"cloud-init: {done}")
            return {"ok": True, "done": [done]}
        if finding_id == "ifupdown-leftover":
            names = nethealth_mod.ifupdown_leftover_names()
            changed = nethealth_mod.fix_ifupdown_leftovers(names)
            audit.record("network.fix", f"removed ifupdown entries for {', '.join(names)} from {', '.join(changed)}")
            return {"ok": True, "done": changed}
        if finding_id == "dhcpcd":
            names = await nethealth_mod.dhcpcd_conflicts()
            files = [network_mod.DHCPCD_CONF]
            snapshots = snapshot_files(files)
            nethealth_mod.write_dhcpcd_deny(names)
            try:
                ran = await nethealth_mod.apply_dhcpcd_fix(names)
            except RuntimeError as exc:
                audit.record("network.fix", f"dhcpcd: {exc}", ok=False)
                await restore_and_reapply(
                    snapshots, functools.partial(nethealth_mod.apply_dhcpcd_fix, names), "network"
                )
                raise HTTPException(status_code=500, detail=str(exc))
            session = sessions.create(
                "network", f"dhcpcd leaves {', '.join(names)} to ifupdown", snapshots,
                timeout=90, reapply={"kind": "dhcpcd", "names": ",".join(names)},
            )
            audit.record("network.fix", f"dhcpcd: denyinterfaces {' '.join(names)}")
            return {"ok": True, "done": ran, "session": session.to_dict()}
        raise HTTPException(status_code=400, detail=f"no fix for {finding_id!r}")

    @router.post("/network/resolvconf", dependencies=guard)
    async def network_install_resolvconf() -> Dict[str, object]:
        backend = await network_mod.detect_backend()
        resolver = await network_mod.resolver_status(backend)
        if not resolvconf_mod.setup_offered(backend, resolver):
            raise HTTPException(
                status_code=400,
                detail="resolvconf is only needed on ifupdown systems where the panel's DNS does not apply",
            )
        job = await jobs.start(
            "network.resolvconf", "Install resolvconf so the panel's DNS applies", resolvconf_mod.command()
        )
        audit.record("network.resolvconf", "install resolvconf")
        return job.to_dict()

    @router.post("/network/interfaces/{name}", dependencies=guard)
    async def configure_interface(name: str, body: InterfaceBody) -> Dict[str, object]:
        try:
            network_mod.validate_interface_name(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # NetworkManager machines can still have interfaces ifupdown owns
        backend = await network_mod.backend_for(name)
        files = network_mod.managed_config_files(backend)
        snapshots = snapshot_files(files)
        try:
            ipv6 = network_mod.validate_ipv6(body.ipv6_method, body.ipv6_address, body.ipv6_gateway)
            await network_mod.write_interface_config(
                backend, name, body.method, body.address, body.gateway, body.dns, ipv6
            )
            commands = await network_mod.apply_backend(backend, name)
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("network.configure", f"{name}: {exc}", ok=False)
            # The apply may have half-happened (ifdown ran, ifup failed): put
            # the old files back *and* bring the interface up on them again.
            await restore_and_reapply(
                snapshots, functools.partial(network_mod.apply_backend, backend, name), "network"
            )
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(
            "network",
            f"{name} ({backend})",
            snapshots,
            timeout=90,
            reapply={"kind": "network", "backend": backend, "name": name},
        )
        audit.record(
            "network.configure",
            f"{name}: {body.method} {body.address or ''} via {body.gateway or '-'}".strip()
            + (f"; ipv6 {body.ipv6_method} {body.ipv6_address or ''}".rstrip() if body.ipv6_method else ""),
        )
        return {"ok": True, "session": session.to_dict(), "applied": commands}

    @router.post("/network/sessions/{session_id}/confirm", dependencies=guard)
    async def confirm_session(session_id: str) -> Dict[str, object]:
        return (await sessions.confirm(session_id)).to_dict()

    @router.post("/network/sessions/{session_id}/revert", dependencies=guard)
    async def revert_session(session_id: str) -> Dict[str, object]:
        return (await sessions.revert(session_id)).to_dict()

    # ---- unattended updates ---------------------------------------------
    @router.get("/updates", dependencies=guard)
    async def updates_status() -> Dict[str, object]:
        return unattended_mod.status()

    @router.post("/updates", dependencies=guard)
    async def updates_apply(body: UpdatesBody) -> Dict[str, object]:
        if body.auto_reboot_time is not None and body.auto_reboot_time != "":
            if not timezone_mod.valid_time(body.auto_reboot_time):
                raise HTTPException(status_code=400, detail="auto_reboot_time must look like HH:MM")
        try:
            unattended_mod.apply_settings(
                enabled=body.enabled,
                update_frequency_days=body.update_frequency_days,
                download_upgradeable_packages=body.download_upgradeable_packages,
                autoclean_interval=body.autoclean_interval,
                auto_reboot=body.auto_reboot,
                auto_reboot_time=body.auto_reboot_time or None,
                auto_reboot_withusers=body.auto_reboot_withusers,
                auto_fix_interrupted_dpkg=body.auto_fix_interrupted_dpkg,
                remove_unused=body.remove_unused,
                remove_new_unused_dependencies=body.remove_new_unused_dependencies,
                remove_unused_dependencies=body.remove_unused_dependencies,
                origins=body.origins,
                origins_style=body.origins_style,
                package_blacklist=body.package_blacklist,
            )
        except ValueError as exc:
            audit.record("updates.configure", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except OSError as exc:
            audit.record("updates.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        if body.report_to is not None or body.report_mode is not None:
            state = await mail_mod.status()
            try:
                await mail_mod.apply_report_settings(
                    report_to=body.report_to or "",
                    report_mode=body.report_mode or str(state.get("report_mode") or "only-on-error"),
                    from_address=str(state.get("from_address") or ""),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            audit.record(
                "updates.reports",
                f"reports to {body.report_to or 'the from address'} ({body.report_mode or 'unchanged'})",
            )
        audit.record(
            "updates.configure",
            "unattended-upgrades settings updated"
            + (f" ({'enabled' if body.enabled else 'disabled'})" if body.enabled is not None else ""),
        )
        return unattended_mod.status()

    @router.post("/updates/dry-run", dependencies=guard)
    async def updates_dry_run() -> Dict[str, object]:
        job = await jobs.start("updates.dry-run", "Unattended upgrades dry run", packages_mod.dry_run_command())
        return job.to_dict()

    # ---- mail ------------------------------------------------------------
    @router.get("/mail", dependencies=guard)
    async def mail_status() -> Dict[str, object]:
        data = await mail_mod.status()
        data["mailer"] = await mail_mod.mailer_status(str(data.get("transport") or "postfix"))
        data["msmtp"] = await mail_mod.msmtp_status()
        data["mail_server"] = await mail_mod.mail_server_status()
        return data

    async def refuse_on_mail_server(action: str) -> Dict[str, object]:
        server = await mail_mod.mail_server_status()
        reason = mail_mod.mail_server_refusal(server, action)
        if reason:
            audit.record("mail.refused", reason, ok=False)
            raise HTTPException(status_code=409, detail=reason)
        return server

    @router.post("/mail", dependencies=guard)
    async def mail_apply(body: MailBody) -> Dict[str, object]:
        if body.transport == "postfix":
            await refuse_on_mail_server("Configuring Postfix as a relay")
        try:
            result = await mail_mod.apply(
                host=body.host,
                port=body.port,
                security=body.security,
                username=body.username,
                from_address=body.from_address,
                password=body.password,
                report_to=body.report_to or "",
                report_mode=body.report_mode or "only-on-error",
                transport=body.transport,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("mail.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("mail.configure", f"{body.transport} relay {body.host}:{body.port} as {body.from_address}")
        return result

    @router.post("/mail/test", dependencies=guard)
    async def mail_test(body: MailTestBody) -> Dict[str, object]:
        state = await mail_mod.status()
        recipient = (body.recipient or "").strip() or str(state.get("report_to") or "")
        if not recipient or not mail_mod.valid_recipient(recipient):
            raise HTTPException(status_code=400, detail="a valid test recipient is required")
        from_address = str(state.get("from_address") or "")
        job = await jobs.start(
            "mail.test",
            f"Test email to {recipient}",
            mail_mod.test_command(from_address, recipient, str(state.get("transport") or "postfix")),
            stdin_text=mail_mod.test_message(recipient, from_address),
        )
        audit.record("mail.test", f"test message to {recipient}")
        return job.to_dict()

    @router.post("/mail/remove-conflicts", dependencies=guard)
    async def mail_remove_conflicts() -> Dict[str, object]:
        await refuse_on_mail_server("Removing mail transfer agents")
        state = await mail_mod.mailer_status()
        conflicts = list(state.get("conflicts") or [])
        if not conflicts:
            raise HTTPException(status_code=400, detail="no conflicting mail transfer agents found")
        try:
            argv = mail_mod.remove_conflicting_command(conflicts, str(state.get("transport") or "postfix"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job = await jobs.start(
            "mail.remove-conflicts",
            f"Remove conflicting mailers: {', '.join(conflicts)}",
            argv,
        )
        audit.record("mail.remove-conflicts", ", ".join(conflicts))
        return job.to_dict()

    @router.post("/mail/install", dependencies=guard)
    async def mail_install(transport: str = Query("postfix", pattern="^(postfix|msmtp)$")) -> Dict[str, object]:
        package = mail_mod.TRANSPORT_PACKAGE[transport]
        if transport == "postfix":
            await refuse_on_mail_server("Installing Postfix")
            try:
                await mail_mod.preseed_postfix()
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc))
        server = await mail_mod.mail_server_status()
        job = await jobs.start(
            "mail.install",
            f"Install {package} (SMTP relay)",
            mail_mod.install_command(transport, mail_server=bool(server.get("detected"))),
        )
        audit.record("mail.install", f"{package} install")
        return job.to_dict()

    # ---- packages --------------------------------------------------------
    @router.get("/packages/search", dependencies=guard)
    async def packages_search(q: str = Query("")) -> Dict[str, object]:
        return {"results": await packages_mod.search(q)}

    @router.get("/packages/installed", dependencies=guard)
    async def packages_installed() -> Dict[str, object]:
        return {"packages": await packages_mod.installed()}

    @router.get("/packages/upgradable", dependencies=guard)
    async def packages_upgradable() -> Dict[str, object]:
        return {"packages": await packages_mod.upgradable()}

    @router.post("/packages/install", dependencies=guard)
    async def packages_install(body: PackagesBody) -> Dict[str, object]:
        try:
            argv = packages_mod.install_command(body.names)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job = await jobs.start("packages.install", f"Install {', '.join(body.names)}", argv)
        audit.record("packages.install", ", ".join(body.names))
        return job.to_dict()

    @router.post("/packages/remove", dependencies=guard)
    async def packages_remove(body: PackagesBody) -> Dict[str, object]:
        try:
            argv = packages_mod.remove_command(body.names)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job = await jobs.start("packages.remove", f"Remove {', '.join(body.names)}", argv)
        audit.record("packages.remove", ", ".join(body.names))
        return job.to_dict()

    @router.post("/packages/update", dependencies=guard)
    async def packages_update() -> Dict[str, object]:
        job = await jobs.start("packages.update", "Refresh package lists", packages_mod.update_command())
        audit.record("packages.update", "apt-get update")
        return job.to_dict()

    @router.post("/packages/upgrade", dependencies=guard)
    async def packages_upgrade(body: UpgradeBody) -> Dict[str, object]:
        job = await jobs.start(
            "packages.upgrade",
            "Full system upgrade" if body.full else "System upgrade",
            packages_mod.upgrade_command(body.full),
        )
        audit.record("packages.upgrade", "full-upgrade" if body.full else "upgrade")
        return job.to_dict()

    @router.get("/packages/maintenance", dependencies=guard)
    async def packages_maintenance() -> Dict[str, object]:
        return {
            "autoremove_candidates": await packages_mod.autoremove_candidates(),
            "cache": packages_mod.cache_stats(),
        }

    @router.post("/packages/autoremove", dependencies=guard)
    async def packages_autoremove() -> Dict[str, object]:
        job = await jobs.start(
            "packages.autoremove",
            "Remove unused packages (autoremove)",
            packages_mod.autoremove_command(),
        )
        audit.record("packages.autoremove", "apt-get autoremove")
        return job.to_dict()

    @router.post("/packages/autoclean", dependencies=guard)
    async def packages_autoclean() -> Dict[str, object]:
        job = await jobs.start(
            "packages.autoclean",
            "Remove obsolete cached downloads (autoclean)",
            packages_mod.autoclean_command(),
        )
        audit.record("packages.autoclean", "apt-get autoclean")
        return job.to_dict()

    @router.post("/packages/clean", dependencies=guard)
    async def packages_clean() -> Dict[str, object]:
        job = await jobs.start(
            "packages.clean",
            "Clear package cache (clean)",
            packages_mod.clean_command(),
        )
        audit.record("packages.clean", "apt-get clean")
        return job.to_dict()

    # ---- jobs ------------------------------------------------------------
    @router.get("/jobs", dependencies=guard)
    async def jobs_list() -> Dict[str, object]:
        return {"jobs": [job.to_dict() for job in jobs.list()]}

    @router.get("/jobs/{job_id}", dependencies=guard)
    async def jobs_get(job_id: str, after: int = Query(0, ge=0)) -> Dict[str, object]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such job")
        return {"job": job.to_dict(include_argv=True), "lines": job.log_slice(after)}

    @router.post("/jobs/{job_id}/cancel", dependencies=guard)
    async def jobs_cancel(job_id: str) -> Dict[str, object]:
        job = await jobs.cancel(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such job")
        return job.to_dict()

    # ---- users -----------------------------------------------------------
    @router.get("/users", dependencies=guard)
    async def users_list() -> Dict[str, object]:
        return await users_mod.list_users()

    @router.post("/users", dependencies=guard)
    async def users_create(body: UserCreateBody) -> Dict[str, object]:
        try:
            user = await users_mod.create_user(
                body.username,
                body.password,
                full_name=body.full_name,
                shell=body.shell,
                sudo=body.sudo,
                ssh_key=body.ssh_key,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("user.create", f"{body.username}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("user.create", f"created {body.username} (sudo={body.sudo})")
        return user

    @router.get("/users/{name}", dependencies=guard)
    async def users_detail(name: str) -> Dict[str, object]:
        try:
            return await users_mod.user_detail(name)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @router.post("/users/{name}", dependencies=guard)
    async def users_update(name: str, body: UserUpdateBody) -> Dict[str, object]:
        try:
            user = await users_mod.update_user(
                name,
                password=body.password,
                full_name=body.full_name,
                shell=body.shell,
                sudo=body.sudo,
                locked=body.locked,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("user.update", f"{name}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("user.update", f"updated {name}")
        return user

    @router.delete("/users/{name}", dependencies=guard)
    async def users_delete(name: str, remove_home: bool = False) -> Dict[str, object]:
        try:
            await users_mod.delete_user(name, remove_home=remove_home)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("user.delete", f"{name}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("user.delete", f"deleted {name} (remove_home={remove_home})")
        return {"ok": True}

    @router.get("/users/{name}/keys", dependencies=guard)
    async def users_keys(name: str) -> Dict[str, object]:
        try:
            return {"keys": users_mod.list_keys(name)}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @router.post("/users/{name}/keys", dependencies=guard)
    async def users_add_key(name: str, body: KeyBody) -> Dict[str, object]:
        try:
            keys = await users_mod.add_key(name, body.key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        audit.record("user.key.add", f"added SSH key for {name}")
        return {"keys": keys}

    @router.delete("/users/{name}/keys/{index}", dependencies=guard)
    async def users_remove_key(name: str, index: int) -> Dict[str, object]:
        try:
            keys = await users_mod.remove_key(name, index)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        audit.record("user.key.remove", f"removed SSH key {index} for {name}")
        return {"keys": keys}

    @router.put("/users/{name}/keys/{index}", dependencies=guard)
    async def users_update_key(name: str, index: int, body: KeyBody) -> Dict[str, object]:
        try:
            keys = await users_mod.update_key(name, index, body.key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # The key material itself never reaches the audit log.
        audit.record("user.key.update", f"updated SSH key {index} for {name}")
        return {"keys": keys}

    # ---- groups ------------------------------------------------------------
    async def group_action(action: str, detail: str, call) -> Dict[str, object]:
        try:
            result = await call
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record(action, f"{detail}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record(action, detail)
        return result

    @router.get("/groups", dependencies=guard)
    async def groups_list() -> Dict[str, object]:
        return await groups_mod.list_groups()

    @router.post("/groups", dependencies=guard)
    async def groups_create(body: GroupBody) -> Dict[str, object]:
        return await group_action(
            "group.create", f"created group {body.name}{' (system)' if body.system else ''}",
            groups_mod.create_group(body.name, body.system),
        )

    @router.delete("/groups/{name}", dependencies=guard)
    async def groups_delete(name: str) -> Dict[str, object]:
        return await group_action("group.delete", f"deleted group {name}", groups_mod.delete_group(name))

    @router.post("/groups/{name}/members", dependencies=guard)
    async def groups_add_member(name: str, body: MemberBody) -> Dict[str, object]:
        return await group_action(
            "group.member.add", f"added {body.user} to {name}", groups_mod.add_member(name, body.user)
        )

    @router.delete("/groups/{name}/members/{user}", dependencies=guard)
    async def groups_remove_member(name: str, user: str) -> Dict[str, object]:
        return await group_action(
            "group.member.remove", f"removed {user} from {name}", groups_mod.remove_member(name, user)
        )

    # ---- generic confirm-or-revert sessions ------------------------------
    @router.get("/sessions", dependencies=guard)
    async def sessions_pending() -> Dict[str, object]:
        # Lets a freshly loaded page (or one reloaded after a panel restart)
        # find a change that is still waiting to be confirmed.
        return {"sessions": [s.to_dict() for s in sessions.pending()]}

    @router.post("/sessions/{session_id}/confirm", dependencies=guard)
    async def sessions_confirm(session_id: str) -> Dict[str, object]:
        return (await sessions.confirm(session_id)).to_dict()

    @router.post("/sessions/{session_id}/revert", dependencies=guard)
    async def sessions_revert(session_id: str) -> Dict[str, object]:
        return (await sessions.revert(session_id)).to_dict()

    # ---- ssh hardening ---------------------------------------------------
    @router.get("/ssh", dependencies=guard)
    async def ssh_status() -> Dict[str, object]:
        return await sshd_mod.status()

    @router.post("/ssh", dependencies=guard)
    async def ssh_apply(body: SshBody) -> Dict[str, object]:
        updates: Dict[str, object] = {}
        if body.port is not None:
            updates["Port"] = body.port
        if body.permit_root_login is not None:
            updates["PermitRootLogin"] = body.permit_root_login
        for key, flag in (
            ("PasswordAuthentication", body.password_authentication),
            ("PubkeyAuthentication", body.pubkey_authentication),
            ("X11Forwarding", body.x11_forwarding),
        ):
            if flag is not None:
                updates[key] = "yes" if flag else "no"
        if body.max_auth_tries is not None:
            updates["MaxAuthTries"] = body.max_auth_tries
        if body.client_alive_interval is not None:
            updates["ClientAliveInterval"] = body.client_alive_interval
        if body.client_alive_count_max is not None:
            updates["ClientAliveCountMax"] = body.client_alive_count_max
        if not updates:
            raise HTTPException(status_code=400, detail="nothing to change")
        snapshots = snapshot_files(sshd_mod.config_files())
        try:
            values = await sshd_mod.apply_settings(updates)
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        try:
            await sshd_mod.reload_service()
        except RuntimeError as exc:
            restore_files(snapshots)
            audit.record("ssh.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(
            "ssh", "sshd settings", snapshots, timeout=90, reapply={"kind": "ssh"}
        )
        audit.record("ssh.configure", ", ".join(f"{key}={value}" for key, value in values.items()))
        return {"ok": True, "session": session.to_dict(), "applied": values}

    # ---- firewall --------------------------------------------------------
    def ssh_allow_rule() -> Dict[str, str]:
        return {
            "action": "allow",
            "direction": "in",
            "protocol": "tcp",
            "port": str(firewall_mod.ssh_port()),
            "address": "any",
        }

    def session_kwargs(backend: str, was_running: Optional[bool] = None) -> Dict[str, object]:
        reapply: Dict[str, Optional[str]] = {"kind": "firewall", "backend": backend}
        if was_running is not None:
            # firewalld: reverting also restores whether the daemon ran
            reapply["running"] = "yes" if was_running else "no"
        return {
            "kind": "firewall",
            "label": f"firewall ({backend})",
            "timeout": 90,
            "reapply": reapply,
        }

    def revert_firewall(backend: str, was_running: Optional[bool] = None):
        return functools.partial(
            firewall_mod.reapply, backend, None if was_running is None else ("yes" if was_running else "no")
        )

    @router.get("/firewall", dependencies=guard)
    async def firewall_status() -> Dict[str, object]:
        return await firewall_mod.status()

    @router.post("/firewall/fix/{finding_id}", dependencies=guard)
    async def firewall_fix(finding_id: str) -> Dict[str, object]:
        state = await firewall_mod.status()
        current = {f["id"]: f for f in state.get("findings") or []}
        if finding_id not in current or not current[finding_id].get("fix") \
                or finding_id not in firewall_mod.FIX_COMMANDS:
            raise HTTPException(status_code=400, detail=f"nothing to fix for {finding_id!r} on this machine")
        try:
            done = await firewall_mod.apply_fix(finding_id)
        except RuntimeError as exc:
            audit.record("firewall.fix", f"{finding_id}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("firewall.fix", done)
        return {"ok": True, "done": [done]}

    @router.post("/firewall", dependencies=guard)
    async def firewall_policy(body: FirewallPolicyBody) -> Dict[str, object]:
        backend = await firewall_mod.detect_backend()
        state = await firewall_mod.status()
        enabled = bool(state["enabled"]) if body.enabled is None else body.enabled
        default_incoming = body.default_incoming or str(state["default_incoming"])
        default_outgoing = body.default_outgoing or str(state["default_outgoing"])
        snapshots = snapshot_files(firewall_mod.managed_config_files(backend))
        ssh_added = False
        applied: List[str] = []
        was_running = bool(state["enabled"]) if backend == "firewalld" else None
        try:
            if backend == "firewalld":
                if body.default_outgoing and default_outgoing != "allow":
                    raise ValueError("firewalld zones do not filter outgoing traffic; it stays allowed")
                args: List[str] = []
                if body.default_incoming:
                    args.append(f"--set-target={firewall_mod.FIREWALLD_POLICY_TARGET[default_incoming]}")
                if enabled and default_incoming == "deny" and not any(
                    firewall_mod.rule_covers_port(rule, str(state["ssh_port"])) for rule in state["rules"]
                ):
                    args += firewall_mod.firewalld_add_args(ssh_allow_rule())
                    ssh_added = True
                if body.enabled is not None and bool(body.enabled) != bool(state["enabled"]):
                    if body.enabled:
                        # start it first, so the permanent changes are reloaded into it
                        applied.append(await firewall_mod.firewalld_set_running(True))
                        applied += await firewall_mod.firewalld_apply(args)
                    else:
                        applied += await firewall_mod.firewalld_apply(args)
                        applied.append(await firewall_mod.firewalld_set_running(False))
                else:
                    applied += await firewall_mod.firewalld_apply(args)
            elif backend == "ufw":
                commands: List[List[str]] = []
                if body.default_incoming:
                    commands.append(["ufw", "default", default_incoming, "incoming"])
                if body.default_outgoing:
                    commands.append(["ufw", "default", default_outgoing, "outgoing"])
                if enabled and default_incoming == "deny" and not any(
                    firewall_mod.rule_covers_port(rule, str(state["ssh_port"])) for rule in state["rules"]
                ):
                    commands.append(firewall_mod.ufw_add_argv(ssh_allow_rule()))
                    ssh_added = True
                if body.enabled is not None and bool(body.enabled) != bool(state["enabled"]):
                    commands.append(["ufw", "--force", "enable" if body.enabled else "disable"])
                for argv in commands:
                    await firewall_mod.ufw_apply(argv)
                applied = [" ".join(argv) for argv in commands]
            else:
                rules = list(state["rules"])
                if enabled and default_incoming == "deny" and not any(
                    firewall_mod.rule_covers_port(rule, str(state["ssh_port"])) for rule in rules
                ):
                    rules.insert(0, ssh_allow_rule())
                    ssh_added = True
                await firewall_mod.nftables_apply(
                    enabled=enabled,
                    default_incoming=default_incoming,
                    default_outgoing=default_outgoing,
                    rules=rules,
                )
                applied = ["nftables ruleset updated"]
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("firewall.configure", str(exc), ok=False)
            await restore_and_reapply(snapshots, revert_firewall(backend, was_running), "firewall")
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(snapshots=snapshots, **session_kwargs(backend, was_running))  # type: ignore[arg-type]
        audit.record(
            "firewall.configure",
            f"enabled={enabled} default_incoming={default_incoming} default_outgoing={default_outgoing}",
        )
        return {
            "ok": True,
            "session": session.to_dict(),
            "applied": applied,
            "ssh_rule_added": ssh_added,
        }

    @router.post("/firewall/rules", dependencies=guard)
    async def firewall_add_rule(body: FirewallRuleBody) -> Dict[str, object]:
        try:
            rule = firewall_mod.normalize_rule(
                {
                    "action": body.action,
                    "direction": body.direction,
                    "protocol": body.protocol,
                    "port": body.port,
                    "address": body.address,
                }
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        backend = await firewall_mod.detect_backend()
        state = await firewall_mod.status()
        if backend == "nftables" and not bool(state["enabled"]):
            raise HTTPException(status_code=400, detail="enable the firewall before editing rules")
        snapshots = snapshot_files(firewall_mod.managed_config_files(backend))
        try:
            if backend == "firewalld":
                applied = await firewall_mod.firewalld_apply(firewall_mod.firewalld_add_args(rule))
            elif backend == "ufw":
                argv = firewall_mod.ufw_add_argv(rule)
                await firewall_mod.ufw_apply(argv)
                applied = [" ".join(argv)]
            else:
                await firewall_mod.nftables_apply(
                    enabled=True,
                    default_incoming=str(state["default_incoming"]),
                    default_outgoing=str(state["default_outgoing"]),
                    rules=list(state["rules"]) + [rule],
                )
                applied = [firewall_mod.nft_rule_line(rule)]
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("firewall.rule.add", str(exc), ok=False)
            await restore_and_reapply(snapshots, revert_firewall(backend), "firewall")
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(snapshots=snapshots, **session_kwargs(backend))  # type: ignore[arg-type]
        audit.record("firewall.rule.add", firewall_mod.rule_label(rule))
        return {"ok": True, "session": session.to_dict(), "applied": applied}

    @router.delete("/firewall/rules/{index}", dependencies=guard)
    async def firewall_remove_rule(index: int) -> Dict[str, object]:
        backend = await firewall_mod.detect_backend()
        state = await firewall_mod.status()
        rules = list(state["rules"])
        if index < 0 or index >= len(rules):
            raise HTTPException(status_code=404, detail=f"no rule at position {index}")
        removed = rules.pop(index)
        snapshots = snapshot_files(firewall_mod.managed_config_files(backend))
        try:
            if backend == "firewalld":
                applied = await firewall_mod.firewalld_apply(firewall_mod.firewalld_remove_args(removed))
            elif backend == "ufw":
                argv = firewall_mod.ufw_delete_argv(removed)
                await firewall_mod.ufw_apply(argv)
                applied = [" ".join(argv)]
            else:
                await firewall_mod.nftables_apply(
                    enabled=bool(state["enabled"]),
                    default_incoming=str(state["default_incoming"]),
                    default_outgoing=str(state["default_outgoing"]),
                    rules=rules,
                )
                applied = [f"removed: {firewall_mod.rule_label(removed)}"]
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("firewall.rule.remove", str(exc), ok=False)
            await restore_and_reapply(snapshots, revert_firewall(backend), "firewall")
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(snapshots=snapshots, **session_kwargs(backend))  # type: ignore[arg-type]
        if removed.get("source") in ("service", "port"):
            label = f"{removed['source']} {removed.get('name', '')}"
        elif removed.get("raw"):
            label = str(removed["raw"])
        elif "action" in removed and "protocol" in removed:
            label = firewall_mod.rule_label(removed)
        else:
            label = str(removed.get("to", index))
        audit.record("firewall.rule.remove", label)
        return {"ok": True, "session": session.to_dict(), "applied": applied}

    # ---- services --------------------------------------------------------
    @router.get("/services", dependencies=guard)
    async def services_list(q: str = Query("")) -> Dict[str, object]:
        return await services_mod.list_services(q)

    @router.get("/services/{unit}", dependencies=guard)
    async def services_detail(unit: str) -> Dict[str, object]:
        try:
            return await services_mod.unit_detail(unit)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @router.get("/services/{unit}/override", dependencies=guard)
    async def services_override(unit: str) -> Dict[str, object]:
        try:
            return await services_mod.get_override(unit)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.put("/services/{unit}/override", dependencies=guard)
    async def services_set_override(unit: str, body: OverrideBody) -> Dict[str, object]:
        try:
            result = await services_mod.set_override(unit, body.content)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("services.override", f"{unit}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        action = "updated" if body.content.strip() else "removed"
        audit.record("services.override", f"{action} override for {result['unit']}")
        return result

    @router.post("/services/{unit}/action/{action}", dependencies=guard)
    async def services_action(unit: str, action: str) -> Dict[str, object]:
        try:
            argv = services_mod.action_argv(unit, action)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job = await jobs.start("services.action", f"{action} {argv[-1]}", argv)
        audit.record("services.action", f"{action} {argv[-1]}")
        return job.to_dict()

    # ---- disk usage ------------------------------------------------------
    @router.get("/disk", dependencies=guard)
    async def disk_filesystems() -> Dict[str, object]:
        return await disk_mod.filesystems()

    @router.post("/disk/scan", dependencies=guard)
    async def disk_scan(body: DiskScanBody) -> Dict[str, object]:
        try:
            argv = disk_mod.du_command(body.path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job = await jobs.start("disk.scan", f"Scan directory sizes under {argv[-1]}", argv)
        audit.record("disk.scan", argv[-1])
        return job.to_dict()

    @router.get("/disk/usage/{job_id}", dependencies=guard)
    async def disk_usage(job_id: str) -> Dict[str, object]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such job")
        return {
            "job": job.to_dict(),
            "entries": disk_mod.parse_du("\n".join(job.lines), root=job.argv[-1] if job.argv else None),
        }

    # ---- logs ------------------------------------------------------------
    @router.get("/logs/journal", dependencies=guard)
    async def logs_journal(
        lines: int = Query(200, ge=10, le=2000),
        unit: str = Query(""),
        priority: str = Query(""),
        after_cursor: str = Query(""),
    ) -> Dict[str, object]:
        try:
            return await logs_mod.journal(lines, unit, priority, after_cursor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/logs/files", dependencies=guard)
    async def logs_files() -> Dict[str, object]:
        return logs_mod.list_log_files()

    @router.get("/logs/files/{name}", dependencies=guard)
    async def logs_file(
        name: str,
        lines: int = Query(200, ge=10, le=2000),
        offset: Optional[int] = Query(None, ge=0),
    ) -> Dict[str, object]:
        try:
            return logs_mod.read_log_file(name, lines, offset)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    # ---- processes -------------------------------------------------------
    @router.get("/processes", dependencies=guard)
    async def processes(sort: str = Query("cpu")) -> Dict[str, object]:
        try:
            return await procs_mod.list_processes(sort)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/processes/kill", dependencies=guard)
    async def processes_kill(body: KillBody) -> Dict[str, object]:
        try:
            result = await procs_mod.kill(body.pid, body.signal)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("process.kill", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("process.kill", f"signal {result['signal']} sent to PID {result['pid']}")
        return result

    # ---- cron ---------------------------------------------------------------
    @router.get("/cron", dependencies=guard)
    async def cron_list() -> Dict[str, object]:
        return cron_mod.list_files()

    @router.post("/cron/entry", dependencies=guard)
    async def cron_upsert(body: CronBody) -> Dict[str, object]:
        try:
            if body.index < 0:
                result = await cron_mod.add_entry(
                    body.path, body.schedule, body.command, body.user, body.enabled
                )
                verb = "added"
            else:
                result = await cron_mod.update_entry(
                    body.path,
                    body.index,
                    body.schedule,
                    body.command,
                    body.user,
                    body.enabled,
                    body.expected,
                )
                verb = "updated" if body.enabled else "disabled"
        except ValueError as exc:
            audit.record("cron.update", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("cron.update", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record(
            "cron.update",
            f"job {verb} in {body.path}: {body.schedule} {body.command[:120]}",
        )
        return result

    @router.post("/cron/delete", dependencies=guard)
    async def cron_delete(body: CronDeleteBody) -> Dict[str, object]:
        try:
            result = await cron_mod.delete_entry(body.path, body.index, body.expected)
        except ValueError as exc:
            audit.record("cron.delete", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("cron.delete", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("cron.delete", f"removed line {body.index} from {body.path}")
        return result

    @router.post("/cron/delete-file", dependencies=guard)
    async def cron_delete_file(body: CronFileBody) -> Dict[str, object]:
        try:
            result = await cron_mod.delete_file(body.path)
        except ValueError as exc:
            audit.record("cron.delete", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("cron.delete", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("cron.delete", f"deleted {body.path}")
        return result

    # ---- users: aging, history and sudo rules ----------------------------
    @router.get("/users/{name}/aging", dependencies=guard)
    async def users_aging(name: str) -> Dict[str, object]:
        try:
            return {"aging": await users_mod.aging(name)}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @router.post("/users/{name}/aging", dependencies=guard)
    async def users_set_aging(name: str, body: AgingBody) -> Dict[str, object]:
        try:
            aging = await users_mod.set_aging(
                name, max_days=body.max_days, warn_days=body.warn_days, expiry=body.expiry
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("user.aging", f"{name}: {exc}", ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("user.aging", f"updated password aging for {name}")
        return {"aging": aging}

    @router.get("/users/{name}/history", dependencies=guard)
    async def users_history(name: str, limit: int = Query(30, ge=1, le=200)) -> Dict[str, object]:
        try:
            return {"entries": await users_mod.login_history(name, limit)}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @router.get("/sudoers", dependencies=guard)
    async def sudoers_list() -> Dict[str, object]:
        return sudoers_mod.list_dropins()

    @router.post("/sudoers/{name}", dependencies=guard)
    async def sudoers_set(name: str, body: SudoersBody) -> Dict[str, object]:
        try:
            result = await sudoers_mod.set_rule(name, nopasswd=body.nopasswd)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        audit.record("sudoers.set", f"{name}: {'NOPASSWD' if body.nopasswd else 'password required'}")
        return result

    @router.delete("/sudoers/{name}", dependencies=guard)
    async def sudoers_remove(name: str) -> Dict[str, object]:
        try:
            result = sudoers_mod.remove_rule(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        audit.record("sudoers.remove", f"removed sudo rule for {name}")
        return result

    # ---- sysctl --------------------------------------------------------------
    @router.get("/sysctl", dependencies=guard)
    async def sysctl_list() -> Dict[str, object]:
        return sysctl_mod.list_files()

    @router.post("/sysctl/entry", dependencies=guard)
    async def sysctl_upsert(body: SysctlBody) -> Dict[str, object]:
        try:
            if body.index < 0:
                result = await sysctl_mod.add_entry(body.path, body.key, body.value)
                verb = "added"
            else:
                result = await sysctl_mod.update_entry(
                    body.path, body.index, body.key, body.value, body.expected
                )
                verb = "updated"
        except ValueError as exc:
            audit.record("sysctl.update", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("sysctl.update", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("sysctl.update", f"{verb} {body.key}={body.value} in {body.path}")
        return result

    @router.post("/sysctl/delete", dependencies=guard)
    async def sysctl_delete(body: SysctlDeleteBody) -> Dict[str, object]:
        try:
            result = await sysctl_mod.delete_entry(body.path, body.index, body.expected)
        except ValueError as exc:
            audit.record("sysctl.delete", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("sysctl.delete", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("sysctl.delete", f"removed line {body.index} from {body.path}")
        return result

    @router.post("/sysctl/delete-file", dependencies=guard)
    async def sysctl_delete_file(body: SysctlFileBody) -> Dict[str, object]:
        try:
            result = await sysctl_mod.delete_file(body.path)
        except ValueError as exc:
            audit.record("sysctl.delete", str(exc), ok=False)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("sysctl.delete", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("sysctl.delete", f"deleted {body.path}")
        return result

    @router.post("/sysctl/apply", dependencies=guard)
    async def sysctl_apply() -> Dict[str, object]:
        try:
            output = await sysctl_mod.apply_checked()
        except RuntimeError as exc:
            audit.record("sysctl.apply", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("sysctl.apply", "applied all sysctl settings")
        return {"output": output, **sysctl_mod.list_files()}

    # ---- web terminal -----------------------------------------------------
    @router.get("/terminal/sessions", dependencies=guard)
    async def terminal_sessions() -> Dict[str, object]:
        return {"sessions": terminals.list()}

    def same_origin(websocket: WebSocket) -> bool:
        """Browsers send Origin on every WebSocket handshake but never apply
        the same-origin policy to it, so any page could otherwise open a root
        shell on a panel running without a token (cross-site WebSocket
        hijacking). Non-browser clients send no Origin and are let through.
        X-Forwarded-Host counts too, for reverse proxies that rewrite Host;
        a page cannot set that header on a WebSocket handshake.
        """
        origin = websocket.headers.get("origin")
        if not origin:
            return True
        allowed = {
            value.strip().lower()
            for header in ("host", "x-forwarded-host")
            for value in websocket.headers.get(header, "").split(",")
            if value.strip()
        }
        return urlsplit(origin).netloc.lower() in allowed

    @router.websocket("/terminal/ws")
    async def terminal_ws(
        websocket: WebSocket,
        user: str = Query(""),
        cols: int = Query(100),
        rows: int = Query(30),
    ) -> None:
        if not same_origin(websocket):
            await websocket.close(code=4403)
            return
        await websocket.accept()
        if settings.auth_enabled:
            key = client_key(websocket.client.host if websocket.client else None)
            if locked_out(key):
                await websocket.close(code=4429)
                return
            # The token arrives as the first message rather than in the URL:
            # query strings end up in access logs and browser history.
            try:
                hello = await asyncio.wait_for(websocket.receive_json(), timeout=10)
            except (asyncio.TimeoutError, WebSocketDisconnect, ValueError, RuntimeError):
                hello = {}
            if not isinstance(hello, dict) or hello.get("type") != "auth" or not token_ok(
                str(hello.get("token", ""))
            ):
                if isinstance(hello, dict) and hello.get("token"):
                    note_failure(key)
                await websocket.close(code=4401)
                return
            throttle.success(key)
        try:
            session = await terminals.create(user or None, cols, rows)
        except (ValueError, RuntimeError) as exc:
            await websocket.send_json({"type": "error", "detail": str(exc)})
            await websocket.close()
            return
        audit.record("terminal.open", f"session {session.id} opened as {session.user}")

        async def pump() -> None:
            try:
                while True:
                    chunk = await session.output.get()
                    if chunk is None:
                        break
                    await websocket.send_json({"type": "output", "data": chunk})
                await websocket.send_json({"type": "closed", "detail": "shell exited"})
            except (WebSocketDisconnect, RuntimeError, OSError):
                pass  # the browser went away; the receive loop cleans up

        pump_task = asyncio.create_task(pump())
        idle_limit = settings.terminal_idle_minutes * 60 or None
        close_reason = "closed by panel"
        try:
            while True:
                try:
                    message = await asyncio.wait_for(websocket.receive_json(), timeout=idle_limit)
                except asyncio.TimeoutError:
                    # An abandoned browser tab must not keep a root shell open.
                    close_reason = "idle timeout"
                    pump_task.cancel()
                    try:
                        await websocket.send_json({"type": "closed", "detail": "idle timeout"})
                        await websocket.close()
                    except (RuntimeError, OSError):
                        pass
                    break
                if not isinstance(message, dict):
                    continue
                kind = message.get("type")
                if kind == "input":
                    terminals.write(session.id, str(message.get("data", "")))
                elif kind == "resize":
                    terminals.resize(session.id, message.get("cols"), message.get("rows"))
                elif kind == "close":
                    break
        except (WebSocketDisconnect, RuntimeError, ValueError, OSError):
            pass
        finally:
            pump_task.cancel()

            async def finish() -> None:
                closed = await terminals.close(session.id, close_reason)
                audit.record(
                    "terminal.close",
                    f"session {session.id} closed ({close_reason}; user {closed['user']}, log {closed['log']})",
                )

            # Shielded: when the handler itself is cancelled (the client went
            # away mid-await), the shell must still be hung up and the close
            # still audited - a cancelled cleanup would leave a root shell
            # running with no record of it ending.
            await asyncio.shield(asyncio.ensure_future(finish()))

    # ---- self-update ------------------------------------------------------
    @router.get("/update/check", dependencies=guard)
    async def update_check() -> Dict[str, object]:
        details = updater_mod.version_details()
        try:
            release = await asyncio.to_thread(updater_mod.latest_release, settings.update_repo)
        except updater_mod.NoReleases:
            # A fixed reason, not the exception text: the response body is
            # served to the browser and must not echo raw error detail.
            return {
                "current": details["version"],
                "current_base": details["base"],
                "commit": details["commit"],
                "ahead": details["ahead"],
                "version_source": details["source"],
                "latest": None,
                "tag": "",
                "newer_available": False,
                "no_releases": True,
                "detail": "this repository has no published releases yet",
                "repo": settings.update_repo,
                "update_supported": updater_mod.is_managed_install(),
                "app_dir": str(updater_mod.app_source_dir()),
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return {
            "current": details["version"],
            "current_base": details["base"],
            "commit": details["commit"],
            "ahead": details["ahead"],
            "version_source": details["source"],
            "latest": updater_mod.normalize_version(release["tag"]),
            "tag": release["tag"],
            # Compared against the tag this build descends from, never against
            # '1.0.0-3-g0cdaeb8' - that would rank a checkout below v1.0.0 and
            # offer to "update" a tree that already contains the release.
            "newer_available": updater_mod.is_newer(release["tag"], str(details["base"])),
            "no_releases": False,
            "release_url": release["url"],
            "checksum_published": updater_mod.choose_download(release)[2] is not None,
            "require_checksum": settings.update_require_checksum,
            "published_at": release["published_at"],
            "notes": release["body"],
            "repo": settings.update_repo,
            "update_supported": updater_mod.is_managed_install(),
            "app_dir": str(updater_mod.app_source_dir()),
        }

    @router.post("/update/install", dependencies=guard)
    async def update_install(body: UpdateInstallBody) -> Dict[str, object]:
        try:
            argv = updater_mod.apply_command(
                settings.update_repo, body.tag, settings.update_require_checksum
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not updater_mod.is_managed_install():
            raise HTTPException(
                status_code=400,
                detail=(
                    "this does not look like an install.sh install; use git pull in a source checkout"
                    if updater_mod.is_source_checkout()
                    else "this does not look like an install.sh install"
                ),
            )
        job = await jobs.start(
            "update.install",
            f"LinuStart self-update {body.tag or 'to the latest release'}",
            argv,
        )
        audit.record("update.install", f"install {body.tag or 'latest'} from {settings.update_repo}")
        return job.to_dict()

    @router.post("/update/rollback", dependencies=guard)
    async def update_rollback() -> Dict[str, object]:
        job = await jobs.start(
            "update.rollback",
            "LinuStart rollback to the most recent backup",
            updater_mod.rollback_command(),
        )
        audit.record("update.rollback", "rollback to the most recent application backup")
        return job.to_dict()

    # ---- metrics and alerts ----------------------------------------------
    def alerts_view(config: Dict[str, object]) -> Dict[str, object]:
        active = [k for k, on in recorder.active.items() if on] if recorder else []
        return {"config": config, "active": active,
                "thresholds": recorder.thresholds(config) if recorder else {}}

    @router.get("/metrics", dependencies=guard)
    async def metrics_history() -> Dict[str, object]:
        return {
            "samples": list(recorder.samples) if recorder else [],
            "interval": recorder.interval if recorder else metrics_mod.INTERVAL,
            "cpus": recorder.cpus if recorder else 1,
            "alerts": alerts_view(metrics_mod.load_alert_config()),
            "recipient": await metrics_mod.alert_recipient(metrics_mod.load_alert_config()),
        }

    @router.post("/metrics/alerts", dependencies=guard)
    async def metrics_alerts(body: AlertsBody) -> Dict[str, object]:
        try:
            config = metrics_mod.save_alert_config(body.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        audit.record("alerts.configure", "resource alerts " + ("enabled" if config["enabled"] else "disabled"))
        return alerts_view(config)

    @router.post("/metrics/alerts/test", dependencies=guard)
    async def metrics_alerts_test() -> Dict[str, object]:
        sent = await metrics_mod.send_alert({"kind": "test", "metric": "test"})
        if not sent:
            raise HTTPException(
                status_code=400,
                detail="the test alert could not be sent - set a recipient and check the Email page",
            )
        return {"ok": True}

    # ---- audit -----------------------------------------------------------
    @router.get("/audit", dependencies=guard)
    async def audit_log(limit: int = Query(200, ge=1, le=1000)) -> Dict[str, object]:
        return {"entries": audit.read(limit)}

    return router
