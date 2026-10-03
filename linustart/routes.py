"""HTTP API routes for LinuStart."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from . import audit
from .jobs import JobManager
from .modules import hostname as hostname_mod
from .modules import mail as mail_mod
from .modules import network as network_mod
from .modules import packages as packages_mod
from .modules import sysinfo as sysinfo_mod
from .modules import timezone as timezone_mod
from .modules import unattended as unattended_mod
from .modules import users as users_mod
from .settings import Settings
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
    enabled: bool
    update_frequency_days: Optional[str] = None
    auto_reboot: Optional[bool] = None
    auto_reboot_time: Optional[str] = None
    remove_unused: Optional[bool] = None
    remove_unused_dependencies: Optional[bool] = None


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


# --------------------------------------------------------------------------
# Network change sessions (apply + auto-revert unless confirmed)
# --------------------------------------------------------------------------

@dataclass
class RevertSession:
    id: str
    backend: str
    iface: str
    snapshots: Dict[str, str]
    created_at: str = field(default_factory=now_iso)
    expires_at: float = 0.0
    confirmed: bool = False
    done: bool = False
    task: Optional[asyncio.Task] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "backend": self.backend,
            "interface": self.iface,
            "created_at": self.created_at,
            "confirmed": self.confirmed,
            "done": self.done,
            "seconds_left": max(0, int(self.expires_at - time.monotonic())) if not self.confirmed else 0,
        }


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, RevertSession] = {}

    def create(self, backend: str, iface: str, snapshots: Dict[str, str], timeout: int) -> RevertSession:
        session = RevertSession(
            id=uuid.uuid4().hex[:12],
            backend=backend,
            iface=iface,
            snapshots=snapshots,
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
            await network_mod.apply_backend(session.backend, session.iface)
            audit.record("network.revert", f"changes to {session.iface} reverted automatically after {timeout}s")
        except Exception as exc:  # noqa: BLE001 - log and keep running
            audit.record("network.revert", f"revert of {session.iface} failed: {exc}", ok=False)

    async def confirm(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        session.confirmed = True
        session.done = True
        audit.record("network.confirm", f"changes to {session.iface} confirmed")
        return session

    async def revert(self, session_id: str) -> RevertSession:
        session = self._get(session_id)
        if session.task and not session.task.done():
            session.task.cancel()
        if not session.done:
            session.done = True
            restore_files(session.snapshots)
            await network_mod.apply_backend(session.backend, session.iface)
            audit.record("network.revert", f"changes to {session.iface} reverted manually")
        return session

    def _get(self, session_id: str) -> RevertSession:
        session = self.sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no such network session")
        return session


# --------------------------------------------------------------------------
# Router factory
# --------------------------------------------------------------------------

def build_router(settings: Settings, jobs: JobManager, sessions: SessionManager) -> APIRouter:
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
        session = sessions.create(backend, name, snapshots, timeout=90)
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
            result = unattended_mod.apply_settings(
                enabled=body.enabled,
                update_frequency_days=body.update_frequency_days,
                auto_reboot=body.auto_reboot,
                auto_reboot_time=body.auto_reboot_time or None,
                remove_unused=body.remove_unused,
                remove_unused_dependencies=body.remove_unused_dependencies,
            )
        except OSError as exc:
            audit.record("updates.configure", str(exc), ok=False)
            raise HTTPException(status_code=500, detail=str(exc))
        audit.record("updates.configure", f"unattended-upgrades {'enabled' if body.enabled else 'disabled'}")
        return result

    @router.post("/updates/dry-run", dependencies=guard)
    async def updates_dry_run() -> Dict[str, object]:
        job = await jobs.start("updates.dry-run", "Unattended upgrades dry run", packages_mod.dry_run_command())
        return job.to_dict()

    # ---- mail ------------------------------------------------------------
    @router.get("/mail", dependencies=guard)
    async def mail_status() -> Dict[str, object]:
        return await mail_mod.status()

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
        if not recipient or not mail_mod.valid_email(recipient):
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

    # ---- audit -----------------------------------------------------------
    @router.get("/audit", dependencies=guard)
    async def audit_log(limit: int = Query(200, ge=1, le=1000)) -> Dict[str, object]:
        return {"entries": audit.read(limit)}

    return router
