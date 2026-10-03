"""Unattended upgrades configuration (/etc/apt/apt.conf.d/*)."""

from __future__ import annotations

import re
import shutil
from typing import Dict, List, Optional, Sequence, Tuple

from ..paths import AUTO_UPGRADES_FILE, UNATTENDED_FILE, UNATTENDED_LOG
from ..util import read_text, write_text

SETTING_RE = re.compile(
    r'^\s*(?P<key>[A-Za-z0-9:_-]+)\s+(?P<value>"[^"]*"|[^;]+)\s*;',
    re.M,
)

ORIGINS_KEY = "Unattended-Upgrade::Allowed-Origins"          # old-style block
ORIGINS_PATTERN_KEY = "Unattended-Upgrade::Origins-Pattern"  # new-style block
BLACKLIST_KEY = "Unattended-Upgrade::Package-Blacklist"
ORIGINS_STYLES = ("pattern", "allowed")
STYLE_KEYS = {"pattern": ORIGINS_PATTERN_KEY, "allowed": ORIGINS_KEY}
MAX_BLOCK_ENTRIES = 200


def parse_settings(text: str) -> Dict[str, str]:
    """Parse simple `Key "value";` apt.conf settings (last one wins)."""
    values: Dict[str, str] = {}
    for match in SETTING_RE.finditer(text):
        value = match.group("value").strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        values[match.group("key")] = value
    return values


def upsert_setting(text: str, key: str, value: str) -> str:
    """Replace or append a `Key "value";` line, preserving comments."""
    new_line = f'{key} "{value}";'
    lines = text.splitlines()
    pattern = re.compile(rf'^\s*{re.escape(key)}\s+')
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = new_line
            return "\n".join(lines) + ("\n" if text.endswith("\n") or lines else "")
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(new_line)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Quoted list blocks (`Key { "entry"; ... };`) - origins and blacklist
# --------------------------------------------------------------------------

def valid_block_entry(entry: str) -> bool:
    """Entries are written inside double quotes - keep them free of syntax.

    Braces are fine (origin patterns use "${distro_codename}"), but quotes,
    semicolons, backslashes and line breaks would escape the quoted string.
    """
    if not entry or len(entry) > 200:
        return False
    return not any(char in entry for char in '";\\\n\r')


def _block_lines(lines: Sequence[str], key: str) -> Optional[Tuple[int, int]]:
    """Inclusive line span of a list block, or None.

    Quote-aware on purpose: origin strings contain braces ("${distro_id}"),
    so a naive brace match truncates the block.
    """
    opener = re.compile(rf'^\s*{re.escape(key)}\s*\{{')
    for start, line in enumerate(lines):
        if not opener.match(line):
            continue
        in_quote = False
        for index in range(start, len(lines)):
            for char in lines[index]:
                if char == '"':
                    in_quote = not in_quote
                elif not in_quote and char == "}":
                    return (start, index)
    return None


def parse_block_list(text: str, key: str) -> List[str]:
    """Collect the quoted entries of a list block (empty list when absent)."""
    entries: List[str] = []
    in_block = False
    for line in text.splitlines():
        if not in_block:
            marker = line.find(key)
            if marker == -1:
                continue
            in_block = True
            line = line[marker + len(key):]
        current: List[str] = []
        in_quote = False
        closed = False
        for char in line:
            if char == '"':
                if in_quote:
                    entries.append("".join(current))
                    current = []
                    in_quote = False
                else:
                    in_quote = True
                continue
            if in_quote:
                current.append(char)
            elif char == "}":
                closed = True
                break
        if closed:
            break
    return entries


def parse_allowed_origins(text: str) -> List[str]:
    """The entries of the (old-style) Allowed-Origins block."""
    return parse_block_list(text, ORIGINS_KEY)


def upsert_block_list(text: str, key: str, entries: Sequence[str]) -> str:
    """Replace or append a quoted list block, preserving surrounding comments."""
    cleaned: List[str] = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if not valid_block_entry(entry):
            raise ValueError(f"invalid entry for {key}: {entry!r}")
        if entry not in cleaned:
            cleaned.append(entry)
    if len(cleaned) > MAX_BLOCK_ENTRIES:
        raise ValueError(f"too many entries for {key} (max {MAX_BLOCK_ENTRIES})")
    new_lines = [f"{key} {{"] + [f'\t"{entry}";' for entry in cleaned] + ["};"]
    lines = text.splitlines()
    span = _block_lines(lines, key)
    if span:
        lines[span[0]: span[1] + 1] = new_lines
    else:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(new_lines)
    return "\n".join(lines) + "\n"


def remove_block(text: str, key: str) -> str:
    """Delete a list block entirely (used when switching origins style)."""
    lines = text.splitlines()
    span = _block_lines(lines, key)
    if not span:
        return text
    del lines[span[0]: span[1] + 1]
    return "\n".join(lines) + ("\n" if lines else "")


def origins_state(text: str) -> Tuple[str, List[str]]:
    """Which origins style the file uses and its entries (pattern wins ties)."""
    lines = text.splitlines()
    has_pattern = _block_lines(lines, ORIGINS_PATTERN_KEY) is not None
    has_allowed = _block_lines(lines, ORIGINS_KEY) is not None
    if has_pattern or not has_allowed:
        return "pattern", parse_block_list(text, ORIGINS_PATTERN_KEY)
    return "allowed", parse_block_list(text, ORIGINS_KEY)


def valid_days(value: str) -> bool:
    """A period in days (0 disables) as apt.conf wants it: plain digits."""
    return value.isdigit() and int(value) <= 365


def base_config() -> str:
    """A minimal 50unattended-upgrades for systems that don't have one yet.

    Creating the file is what makes report wiring possible on minimal Debian
    installs, where the package ships no configuration at all.
    """
    return (
        "// Generated by LinuStart\n"
        "// Automatic security upgrades for Debian/Ubuntu\n"
        'Unattended-Upgrade::Allowed-Origins {\n'
        '\t"${distro_id}:${distro_codename}";\n'
        '\t"${distro_id}:${distro_codename}-security";\n'
        "};\n"
    )


def log_tail(limit: int = 200) -> List[str]:
    try:
        lines = UNATTENDED_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []
    return lines[-limit:]


def package_installed() -> bool:
    """Is the unattended-upgrades package present? (Default on Ubuntu, optional on Debian.)"""
    return shutil.which("unattended-upgrade") is not None or UNATTENDED_FILE.exists()


def status() -> Dict[str, object]:
    auto = parse_settings(read_text(AUTO_UPGRADES_FILE))
    conf_text = read_text(UNATTENDED_FILE)
    conf = parse_settings(conf_text)
    style, origins = origins_state(conf_text)
    return {
        "package_installed": package_installed(),
        "enabled": auto.get("APT::Periodic::Unattended-Upgrade", "0") == "1",
        "update_lists": auto.get("APT::Periodic::Update-Package-Lists", "0") == "1",
        "update_frequency_days": auto.get("APT::Periodic::Update-Package-Lists", "1"),
        "download_upgradeable_packages": auto.get("APT::Periodic::Download-Upgradeable-Packages", "1") == "1",
        "autoclean_interval": auto.get("APT::Periodic::AutocleanInterval", "0"),
        "auto_reboot": conf.get("Unattended-Upgrade::Automatic-Reboot", "false") == "true",
        "auto_reboot_time": conf.get("Unattended-Upgrade::Automatic-Reboot-Time", ""),
        "auto_reboot_withusers": conf.get("Unattended-Upgrade::Automatic-Reboot-WithUsers", "true") == "true",
        "auto_fix_interrupted_dpkg": conf.get("Unattended-Upgrade::AutoFixInterruptedDpkg", "true") == "true",
        "remove_unused": conf.get("Unattended-Upgrade::Remove-Unused-Kernel-Packages", "true") == "true",
        "remove_new_unused_dependencies": conf.get("Unattended-Upgrade::Remove-New-Unused-Dependencies", "true") == "true",
        "remove_unused_dependencies": conf.get("Unattended-Upgrade::Remove-Unused-Dependencies", "false") == "true",
        "origins": origins,
        "origins_style": style,
        "allowed_origins": origins,
        "package_blacklist": parse_block_list(conf_text, BLACKLIST_KEY),
        "report_to": conf.get("Unattended-Upgrade::Mail", ""),
        "report_mode": conf.get("Unattended-Upgrade::MailReport", ""),
        "report_sender": conf.get("Unattended-Upgrade::Sender", ""),
        "log": log_tail(),
        "files": {
            "auto_upgrades": str(AUTO_UPGRADES_FILE),
            "unattended": str(UNATTENDED_FILE),
        },
    }


def apply_settings(
    *,
    enabled: Optional[bool] = None,
    update_frequency_days: Optional[str] = None,
    download_upgradeable_packages: Optional[bool] = None,
    autoclean_interval: Optional[str] = None,
    auto_reboot: Optional[bool] = None,
    auto_reboot_time: Optional[str] = None,
    auto_reboot_withusers: Optional[bool] = None,
    auto_fix_interrupted_dpkg: Optional[bool] = None,
    remove_unused: Optional[bool] = None,
    remove_new_unused_dependencies: Optional[bool] = None,
    remove_unused_dependencies: Optional[bool] = None,
    origins: Optional[Sequence[str]] = None,
    origins_style: Optional[str] = None,
    package_blacklist: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Write the unattended-upgrades configuration.

    Any field left as None keeps whatever the files already say, so partial
    updates (origins only, reports only) never clobber other settings.
    """
    auto = parse_settings(read_text(AUTO_UPGRADES_FILE))
    frequency = update_frequency_days or auto.get("APT::Periodic::Update-Package-Lists", "1")
    if not valid_days(str(frequency)):
        raise ValueError(f"update_frequency_days must be 0-365: {frequency!r}")
    if autoclean_interval is not None and not valid_days(autoclean_interval):
        raise ValueError(f"autoclean_interval must be 0-365: {autoclean_interval!r}")

    auto_text = read_text(AUTO_UPGRADES_FILE) or (
        "// Generated by LinuStart\n// Periodic upgrade settings\n"
    )
    if enabled is not None:
        auto_text = upsert_setting(auto_text, "APT::Periodic::Unattended-Upgrade", "1" if enabled else "0")
    auto_text = upsert_setting(auto_text, "APT::Periodic::Update-Package-Lists", str(frequency))
    if download_upgradeable_packages is not None:
        auto_text = upsert_setting(
            auto_text,
            "APT::Periodic::Download-Upgradeable-Packages",
            "1" if download_upgradeable_packages else "0",
        )
    if autoclean_interval is not None:
        auto_text = upsert_setting(auto_text, "APT::Periodic::AutocleanInterval", str(autoclean_interval))
    write_text(AUTO_UPGRADES_FILE, auto_text)

    conf_text = read_text(UNATTENDED_FILE) or base_config()
    booleans = (
        (auto_reboot, "Unattended-Upgrade::Automatic-Reboot"),
        (auto_reboot_withusers, "Unattended-Upgrade::Automatic-Reboot-WithUsers"),
        (auto_fix_interrupted_dpkg, "Unattended-Upgrade::AutoFixInterruptedDpkg"),
        (remove_unused, "Unattended-Upgrade::Remove-Unused-Kernel-Packages"),
        (remove_new_unused_dependencies, "Unattended-Upgrade::Remove-New-Unused-Dependencies"),
        (remove_unused_dependencies, "Unattended-Upgrade::Remove-Unused-Dependencies"),
    )
    for flag, key in booleans:
        if flag is not None:
            conf_text = upsert_setting(conf_text, key, "true" if flag else "false")
    if auto_reboot_time is not None:
        conf_text = upsert_setting(conf_text, "Unattended-Upgrade::Automatic-Reboot-Time", auto_reboot_time)
    if origins is not None:
        style = origins_style or origins_state(conf_text)[0]
        if style not in ORIGINS_STYLES:
            raise ValueError(f"origins_style must be one of {ORIGINS_STYLES}")
        keep_key = STYLE_KEYS[style]
        drop_key = STYLE_KEYS["allowed" if style == "pattern" else "pattern"]
        conf_text = upsert_block_list(remove_block(conf_text, drop_key), keep_key, origins)
    if package_blacklist is not None:
        conf_text = upsert_block_list(conf_text, BLACKLIST_KEY, package_blacklist)
    write_text(UNATTENDED_FILE, conf_text)
    return status()
