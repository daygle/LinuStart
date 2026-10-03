"""HTTP API routes for LinuStart."""

from __future__ import annotations

import asyncio
import functools
import time
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from . import __version__, audit
from . import updater as updater_mod
from .jobs import JobManager
from .modules import disk as disk_mod
from .modules import firewall as firewall_mod
from .modules import hostname as hostname_mod
from .modules import logs as logs_mod
from .modules import mail as mail_mod
from .modules import network as network_mod
from .modules import packages as packages_mod
from .modules import procs as procs_mod
from .modules import services as services_mod
from .modules import sshd as sshd_mod
from .modules import cron as cron_mod
from .modules import sudoers as sudoers_mod
from .modules import sysctl as sysctl_mod
from .modules import sysinfo as sysinfo_mod
from .modules import timezone as timezone_mod
from .modules import unattended as unattended_mod
from .modules import users as users_mod
from .paths import SSHD_CONFIG
from .settings import Settings
from .terminal import TerminalManager
from .util import now_iso, restore_files, snapshot_files


# --------------------------------------------------------------------------
# Request bodies
# --------------------------------------------------------------------------

class HostnameBody(BaseModel):
    hostname: str


class TimezoneBody(BaseModel):
    timezone: str


class NtpBody(BaseModel):
    enabled: bool


class InterfaceBody(BaseModel):
    method: str = Field(pattern="^(static|dhcp|manual)$")
    address: Optional[str] = None
    gateway: Optional[str] = None
    dns: List[str] = Field(default_factory=list)


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
# Network change sessions (apply + auto-revert unless confirmed)
# --------------------------------------------------------------------------

@dataclass
class RevertSession:
    id: str
    kind: str
    label: str
    snapshots: Dict[str, str]
    reapply: Callable[[], Awaitable[None]]
    created_at: str = field(default_factory=now_iso)
    expires_at: float = 0.0
    confirmed: bool = False
    done: bool = False
    task: Optional[asyncio.Task] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "created_at": self.created_at,
            "confirmed": self.confirmed,
            "done": self.done,
            "seconds_left": max(0, int(self.expires_at - time.monotonic())) if not self.confirmed else 0,
        }


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, RevertSession] = {}

    def create(
        self,
        kind: str,
        label: str,
        snapshots: Dict[str, str],
        timeout: int,
        reapply: Callable[[], Awaitable[None]],
    ) -> RevertSession:
        session = RevertSession(
            id=uuid.uuid4().hex[:12],
            kind=kind,
            label=label,
            snapshots=snapshots,
            reapply=reapply,
            expires_at=time.monotonic() + timeout,
        )
        self.sessions[session.id] = session
        session.task = asyncio.get_running_loop().create_task(self._expire(session, timeout))
        return session

    async def _expire(self, session: RevertSession, timeout: int) -> None:
        await asyncio.sleep(timeout)
        if session.confirmed or session.done:
            return
        session.done = True
        restore_files(session.snapshots)
        try:
            await session.reapply()
            audit.record(
                f"{session.kind}.revert",
                f"changes to {session.label} reverted automatically after {timeout}s",
            )
        except Exception as exc:  # noqa: BLE001 - log and keep running
            audit.record(f"{session.kind}.revert", f"revert of {session.label} failed: {exc}", ok=False)

    async def confirm(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        session.confirmed = True
        session.done = True
        audit.record(f"{session.kind}.confirm", f"changes to {session.label} confirmed")
        return session

    async def revert(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        if not session.done:
            session.done = True
            restore_files(session.snapshots)
            await session.reapply()
            audit.record(f"{session.kind}.revert", f"changes to {session.label} reverted manually")
        return session

    def _get(self, session_id: str) -> RevertSession:
        session = self.sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no such network session")
        return session


# --------------------------------------------------------------------------
# Router factory
# --------------------------------------------------------------------------

def build_router(
    settings: Settings,
    jobs: JobManager,
    sessions: SessionManager,
    terminals: TerminalManager,
) -> APIRouter:
    router = APIRouter()

    async def require_auth(authorization: Optional[str] = Header(None)) -> None:
        if not settings.auth_enabled:
            return
        expected = f"Bearer {settings.token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="invalid or missing token")

    guard = [Depends(require_auth)]

    # ---- system ----------------------------------------------------------
    @router.get("/system/overview", dependencies=guard)
    async def overview() -> Dict[str, object]:
        data = sysinfo_mod.overview()
        data["hostname"] = await hostname_mod.current()
        return data

    @router.get("/hostname", dependencies=guard)
    async def get_hostname() -> Dict[str, str]:
        return {"hostname": await hostname_mod.current()}

    @router.post("/hostname", dependencies=guard)
    async def set_hostname(body: HostnameBody) -> Dict[str, str]:
        try:
            name = await hostname_mod.set_hostname(body.hostname)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("hostname.set", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("hostname.set", f"hostname set to {name}")
        return {"hostname": name}

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
        return {
            "backend": backend,
            "config": await network_mod.get_config(backend),
            "runtime": await network_mod.runtime_status(),
            "sessions": [s.to_dict() for s in sessions.sessions.values() if not s.done],
        }

    @router.post("/network/interfaces/{name}", dependencies=guard)
    async def configure_interface(name: str, body: InterfaceBody) -> Dict[str, object]:
        backend = await network_mod.detect_backend()
        files = network_mod.managed_config_files(backend)
        snapshots = snapshot_files(files)
        try:
            await network_mod.write_interface_config(
                backend, name, body.method, body.address, body.gateway, body.dns
            )
            commands = await network_mod.apply_backend(backend, name)
        except ValueError as exc:
            restore_files(snapshots)
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("network.configure", f"{name}: {exc}", ok=False)
            restore_files(snapshots)
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(
            "network",
            f"{name} ({backend})",
            snapshots,
            timeout=90,
            reapply=functools.partial(network_mod.apply_backend, backend, name),
        )
        audit.record(
            "network.configure",
            f"{name}: {body.method} {body.address or ''} via {body.gateway or '-'}".strip(),
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
        data["mailer"] = await mail_mod.mailer_status()
        data["msmtp"] = await mail_mod.msmtp_status()
        return data

    @router.post("/mail", dependencies=guard)
    async def mail_apply(body: MailBody) -> Dict[str, object]:
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
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            audit.record("mail.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("mail.configure", f"relay {body.host}:{body.port} as {body.from_address}")
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
            mail_mod.test_command(from_address, recipient),
            stdin_text=mail_mod.test_message(recipient),
        )
        audit.record("mail.test", f"test message to {recipient}")
        return job.to_dict()

    @router.post("/mail/remove-conflicts", dependencies=guard)
    async def mail_remove_conflicts() -> Dict[str, object]:
        state = await mail_mod.mailer_status()
        conflicts = list(state.get("conflicts") or [])
        if not conflicts:
            raise HTTPException(status_code=400, detail="no conflicting mail transfer agents found")
        try:
            argv = mail_mod.remove_conflicting_command(conflicts)
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
    async def mail_install() -> Dict[str, object]:
        try:
            await mail_mod.preseed_postfix()
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        job = await jobs.start(
            "mail.install",
            "Install postfix (SMTP relay)",
            packages_mod.install_command(["postfix"]),
        )
        audit.record("mail.install", "postfix install")
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

    # ---- generic confirm-or-revert sessions ------------------------------
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
        snapshots = snapshot_files([SSHD_CONFIG])
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
            "ssh", "sshd settings", snapshots, timeout=90, reapply=sshd_mod.reload_service
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

    def session_kwargs(backend: str) -> Dict[str, object]:
        return {
            "kind": "firewall",
            "label": f"firewall ({backend})",
            "timeout": 90,
            "reapply": functools.partial(firewall_mod.reapply, backend),
        }

    @router.get("/firewall", dependencies=guard)
    async def firewall_status() -> Dict[str, object]:
        return await firewall_mod.status()

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
        try:
            if backend == "ufw":
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
            restore_files(snapshots)
            audit.record("firewall.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(snapshots=snapshots, **session_kwargs(backend))  # type: ignore[arg-type]
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
        if backend != "ufw" and not bool(state["enabled"]):
            raise HTTPException(status_code=400, detail="enable the firewall before editing rules")
        snapshots = snapshot_files(firewall_mod.managed_config_files(backend))
        try:
            if backend == "ufw":
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
            restore_files(snapshots)
            audit.record("firewall.rule.add", str(exc), ok=False)
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
            if backend == "ufw":
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
            restore_files(snapshots)
            audit.record("firewall.rule.remove", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        session = sessions.create(snapshots=snapshots, **session_kwargs(backend))  # type: ignore[arg-type]
        label = firewall_mod.rule_label(removed) if "action" in removed else str(removed.get("to", index))
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
    ) -> Dict[str, object]:
        try:
            return await logs_mod.journal(lines, unit, priority)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/logs/files", dependencies=guard)
    async def logs_files() -> Dict[str, object]:
        return logs_mod.list_log_files()

    @router.get("/logs/files/{name}", dependencies=guard)
    async def logs_file(name: str, lines: int = Query(200, ge=10, le=2000)) -> Dict[str, object]:
        try:
            return logs_mod.read_log_file(name, lines)
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
            output = await sysctl_mod._apply_checked()
        except RuntimeError as exc:
            audit.record("sysctl.apply", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("sysctl.apply", "applied all sysctl settings")
        return {"output": output, **sysctl_mod.list_files()}

    # ---- web terminal -----------------------------------------------------
    @router.get("/terminal/sessions", dependencies=guard)
    async def terminal_sessions() -> Dict[str, object]:
        return {"sessions": terminals.list()}

    @router.websocket("/terminal/ws")
    async def terminal_ws(
        websocket: WebSocket,
        token: str = Query(""),
        user: str = Query(""),
        cols: int = Query(100),
        rows: int = Query(30),
    ) -> None:
        if settings.auth_enabled and token != settings.token:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            session = await terminals.create(user or None, cols, rows)
        except (ValueError, RuntimeError) as exc:
            await websocket.send_json({"type": "error", "detail": str(exc)})
            await websocket.close()
            return
        audit.record("terminal.open", f"session {session.id} opened as {session.user}")

        async def pump() -> None:
            while True:
                chunk = await session.output.get()
                if chunk is None:
                    break
                await websocket.send_json({"type": "output", "data": chunk})
            await websocket.send_json({"type": "closed", "detail": "shell exited"})

        pump_task = asyncio.create_task(pump())
        try:
            while True:
                message = await websocket.receive_json()
                kind = message.get("type")
                if kind == "input":
                    terminals.write(session.id, str(message.get("data", "")))
                elif kind == "resize":
                    terminals.resize(session.id, message.get("cols"), message.get("rows"))
                elif kind == "close":
                    break
        except (WebSocketDisconnect, RuntimeError, ValueError):
            pass
        finally:
            pump_task.cancel()
            closed = await terminals.close(session.id)
            audit.record(
                "terminal.close",
                f"session {session.id} closed (user {closed['user']}, log {closed['log']})",
            )

    # ---- self-update ------------------------------------------------------
    @router.get("/update/check", dependencies=guard)
    async def update_check() -> Dict[str, object]:
        try:
            release = await asyncio.to_thread(updater_mod.latest_release, settings.update_repo)
        except updater_mod.NoReleases:
            # A fixed reason, not the exception text: the response body is
            # served to the browser and must not echo raw error detail.
            return {
                "current": __version__,
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
            "current": __version__,
            "latest": updater_mod.normalize_version(release["tag"]),
            "tag": release["tag"],
            "newer_available": updater_mod.is_newer(release["tag"], __version__),
            "no_releases": False,
            "release_url": release["url"],
            "published_at": release["published_at"],
            "notes": release["body"],
            "repo": settings.update_repo,
            "update_supported": updater_mod.is_managed_install(),
            "app_dir": str(updater_mod.app_source_dir()),
        }

    @router.post("/update/install", dependencies=guard)
    async def update_install(body: UpdateInstallBody) -> Dict[str, object]:
        try:
            argv = updater_mod.apply_command(settings.update_repo, body.tag)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not updater_mod.is_managed_install():
            raise HTTPException(
                status_code=400,
                detail="this does not look like an install.sh install; use git pull in a source checkout",
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

    # ---- audit -----------------------------------------------------------
    @router.get("/audit", dependencies=guard)
    async def audit_log(limit: int = Query(200, ge=1, le=1000)) -> Dict[str, object]:
        return {"entries": audit.read(limit)}

    return router
