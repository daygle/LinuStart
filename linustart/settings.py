"""Runtime settings: config file plus CLI overrides."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .paths import CONFIG_FILE
from .updater import DEFAULT_REPO


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    token: Optional[str] = None
    config_path: Path = field(default_factory=lambda: CONFIG_FILE)
    update_repo: str = DEFAULT_REPO
    # Refuse self-updates whose release publishes no SHA256SUMS.
    update_require_checksum: bool = False
    # Web terminal sessions with no keyboard input for this long are closed
    # (0 disables the timeout).
    terminal_idle_minutes: int = 30

    @property
    def auth_enabled(self) -> bool:
        return bool(self.token)


def load_settings(
    config_path: Optional[Path] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    token: Optional[str] = None,
    no_auth: bool = False,
) -> Settings:
    path = Path(config_path) if config_path else CONFIG_FILE
    settings = Settings(config_path=path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if isinstance(data, dict):
        if isinstance(data.get("host"), str):
            settings.host = data["host"]
        if isinstance(data.get("port"), int):
            settings.port = data["port"]
        if isinstance(data.get("auth_token"), str) and data["auth_token"]:
            settings.token = data["auth_token"]
        if isinstance(data.get("update_repo"), str) and data["update_repo"]:
            settings.update_repo = data["update_repo"]
        idle = data.get("terminal_idle_minutes")
        if isinstance(idle, int) and not isinstance(idle, bool) and idle >= 0:
            settings.terminal_idle_minutes = idle
        if isinstance(data.get("update_require_checksum"), bool):
            settings.update_require_checksum = data["update_require_checksum"]
    if host is not None:
        settings.host = host
    if port is not None:
        settings.port = port
    if no_auth:
        settings.token = None
    elif token is not None:
        settings.token = token
    return settings
