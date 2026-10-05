"""Kernel parameters (sysctl): view, add, edit and remove settings.

Settings live in ``/etc/sysctl.conf`` and in drop-ins under
``/etc/sysctl.d/*.conf``. ``sysctl --system`` applies them in a fixed
precedence order - the drop-ins are read first, ``/etc/sysctl.conf`` last -
so this module mirrors that order when listing files.

Writing a file only changes what the *next* apply will do, so every write is
followed by ``sysctl --system``. If the kernel rejects the settings the files
are restored and the runtime values re-applied, which keeps a typo from
leaving a half-configured kernel behind.

Parsing and rendering are pure string functions so they can be tested
without root.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from ..paths import PROC_SYS, ROOT, SYSCTL_CONF, SYSCTL_D
from ..util import backup, read_text, restore_files, run, write_text

DEFAULT_FILE = "99-linustart.conf"
MAX_VALUE = 200
# Shown in place of an exception when one file cannot be listed. The raw
# OSError text can name paths and permissions the API caller has no business
# seeing, so the response carries a fixed reason and the operator looks at the
# path itself.
READ_ERROR = "cannot read this file"

# Kernel parameter names: letters, digits and the separators that appear in
# real keys (vm.swappiness, fs.file-max, net.ipv4.conf.all.rp_filter), plus
# the glob characters sysctl(8) accepts in drop-ins.
KEY_RE = re.compile(r"^[A-Za-z0-9_.*?\[\]/@-]{1,120}$")
# Values are kernel parameters, not shell: quotes and comment characters are
# refused so a value can never start a comment or a second assignment.
VALUE_RE = re.compile(r"^[A-Za-z0-9 ._:/,@*+%~-]{1,200}$")
ENTRY_RE = re.compile(
    r"^(?P<key>[A-Za-z0-9_.*?\[\]/@-]+)(?P<gap1>\s*)=(?P<gap2>\s*)(?P<value>.*?)\s*$"
)


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------

def logical_path(path: Path) -> str:
    try:
        return "/" + path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def rooted_path(value: str) -> Path:
    pure = PurePosixPath(value)
    if not pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"not an absolute sysctl path: {value!r}")
    return ROOT.joinpath(*pure.parts[1:])


def classify(path: Path) -> str:
    """Kind of sysctl file: "main", "dropin" or "" when it is not one."""
    if path == SYSCTL_CONF:
        return "main"
    try:
        relative = path.relative_to(SYSCTL_D)
    except ValueError:
        return ""
    if len(relative.parts) != 1 or not relative.parts[0].endswith(".conf"):
        return ""
    return "dropin"


def load(logical: str) -> Path:
    """Resolve a sysctl file path, refusing anything outside the two places."""
    path = rooted_path(logical)
    if not classify(path):
        raise ValueError(f"not a sysctl configuration file: {logical}")
    return path


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def valid_key(key: str) -> bool:
    return bool(KEY_RE.match((key or "").strip()))


def valid_value(value: str) -> bool:
    return bool(VALUE_RE.match((value or "").strip()))


def validate_fields(key: str, value: str) -> Tuple[str, str]:
    key = (key or "").strip()
    value = (value or "").strip()
    if not valid_key(key):
        raise ValueError(f"invalid parameter name: {key!r} (expected something like vm.swappiness)")
    if not valid_value(value):
        raise ValueError("value must be a single unquoted word, number or path")
    return key, value


def runtime_value(key: str) -> Optional[str]:
    """The value the kernel is actually using right now, from /proc/sys."""
    key = (key or "").strip()
    if not valid_key(key) or any(char in key for char in "*?[]"):
        return None
    try:
        return (PROC_SYS / key.replace(".", "/")).read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@dataclass
class SysctlEntry:
    index: int
    key: str
    value: str
    valid: bool
    runtime: Optional[str]
    raw: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "key": self.key,
            "value": self.value,
            "valid": self.valid,
            "runtime": self.runtime,
            "changed": bool(self.runtime is not None and self.runtime != self.value),
            "raw": self.raw,
        }


def parse_entries(text: str) -> List[SysctlEntry]:
    """Every ``key = value`` line, ignoring comments, blanks and globs.

    Commented-out settings are reported like cron jobs so they can be
    switched back on; a comment only counts when what follows really parses.
    """
    entries: List[SysctlEntry] = []
    for index, raw in enumerate(text.splitlines()):
        stripped = raw.strip()
        if not stripped or stripped.endswith("\\"):
            continue  # continuation of the previous setting
        enabled = True
        line = stripped
        if line.startswith(("#", ";")):
            candidate = line.lstrip("#;").strip()
            match = ENTRY_RE.match(candidate)
            if match is None or not valid_key(match.group("key")):
                continue
            line, enabled = candidate, False
        else:
            match = ENTRY_RE.match(line)
            if match is None:
                continue
        key = match.group("key")
        value = match.group("value").strip()
        if not value:
            continue
        entries.append(
            SysctlEntry(
                index=index,
                key=key,
                value=value,
                valid=valid_key(key) and valid_value(value) and enabled,
                runtime=runtime_value(key),
                raw=raw,
            )
        )
    return entries


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_entry(key: str, value: str) -> str:
    return f"{key} = {value}"


def render_like(original: str, key: str, value: str) -> str:
    """Keep the original spacing around the ``=`` so diffs stay small."""
    stripped = (original or "").strip()
    if stripped.startswith(("#", ";")):
        stripped = stripped.lstrip("#;").strip()
    match = re.match(
        r"^(?P<pre>\s*)(?P<key>[^\s=]+)(?P<gap1>\s*)=(?P<gap2>\s*)(?P<value>.*?)\s*$",
        stripped,
    )
    if match:
        return f"{match.group('pre')}{key}{match.group('gap1')}={match.group('gap2')}{value}"
    return render_entry(key, value)


def replace_entry(
    text: str,
    index: int,
    key: str,
    value: str,
    expected: str = "",
) -> str:
    """Rewrite one line in place, leaving every other line untouched."""
    key, value = validate_fields(key, value)
    lines = text.splitlines()
    if index < 0 or index >= len(lines):
        raise ValueError(f"no line {index} in this file")
    if expected and lines[index] != expected:
        raise ValueError("this file changed since it was loaded; reload and try again")
    lines[index] = render_like(lines[index], key, value)
    return "\n".join(lines) + "\n"


def append_entry(text: str, key: str, value: str) -> str:
    key, value = validate_fields(key, value)
    body = text.rstrip("\n")
    line = render_entry(key, value)
    return f"{body}\n{line}\n" if body else f"{line}\n"


def remove_entry(text: str, index: int, expected: str = "") -> str:
    lines = text.splitlines()
    if index < 0 or index >= len(lines):
        raise ValueError(f"no line {index} in this file")
    if expected and lines[index] != expected:
        raise ValueError("this file changed since it was loaded; reload and try again")
    del lines[index]
    return "\n".join(lines) + "\n" if lines else ""


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

@dataclass
class SysctlFile:
    path: Path
    kind: str

    @property
    def logical(self) -> str:
        return logical_path(self.path)

    def to_dict(self) -> Dict[str, object]:
        text = read_text(self.path)
        entries = parse_entries(text)
        return {
            "path": self.logical,
            "kind": self.kind,
            "entries": [entry.to_dict() for entry in entries],
            "count": len(entries),
            "exists": self.path.is_file(),
        }


def _iter_paths() -> List[Path]:
    """Drop-ins first, then /etc/sysctl.conf - the order sysctl applies them."""
    paths: List[Path] = []
    if SYSCTL_D.is_dir():
        for path in sorted(SYSCTL_D.iterdir()):
            if path.is_file() and not path.name.startswith(".") and path.name.endswith(".conf"):
                paths.append(path)
    if SYSCTL_CONF.is_file() or SYSCTL_CONF.parent.is_dir():
        paths.append(SYSCTL_CONF)
    return paths


def list_files() -> Dict[str, object]:
    files: List[Dict[str, object]] = []
    for path in _iter_paths():
        try:
            files.append(SysctlFile(path=path, kind=classify(path)).to_dict())
        except (OSError, ValueError):
            # The operator gets a stable reason, never the raw exception:
            # OSError text carries paths and permissions we need not echo.
            files.append(
                {"path": logical_path(path), "kind": "error", "detail": READ_ERROR, "entries": []}
            )
    default_file = logical_path(SYSCTL_D / DEFAULT_FILE)
    return {
        "files": files,
        "settings": sum(int(item.get("count") or 0) for item in files),
        "default_file": default_file,
        "paths": {
            "sysctl_conf": logical_path(SYSCTL_CONF),
            "sysctl_d": logical_path(SYSCTL_D),
        },
    }


def apply_command() -> List[str]:
    return ["sysctl", "--system"]


async def apply_system() -> str:
    """Re-read every sysctl file; returns the combined command output."""
    result = await run(apply_command())
    return (result.stdout + result.stderr).strip()


# procps sysctl reports a rejected setting in its output and still exits 0,
# so the output has to be inspected; these are the messages it uses.
ERROR_MARKERS = (
    "error",
    "cannot stat",
    "no such file or directory",
    "permission denied",
    "invalid",
    "unknown",
)


def apply_problems(output: str) -> List[str]:
    """Lines in ``sysctl --system`` output that mean a setting was rejected."""
    return [
        line.strip()
        for line in (output or "").splitlines()
        if any(marker in line.lower() for marker in ERROR_MARKERS)
    ]


async def apply_checked(reverting: bool = False) -> str:
    """Apply every sysctl file and raise if the kernel rejected a setting."""
    output = await apply_system()
    problems = apply_problems(output)
    if problems:
        suffix = " and they were reverted" if reverting else ""
        raise RuntimeError(f"the kernel rejected these settings{suffix}: {problems[0]}")
    return output


async def _save_and_apply(paths: Dict[Path, str]) -> str:
    """Write the files, then apply - restoring everything if the kernel says no."""
    snapshots = {str(path): read_text(path) for path in paths}
    for path, text in paths.items():
        write_text(path, text)
    try:
        return await apply_checked(reverting=True)
    except Exception:
        restore_files(snapshots)
        await apply_system()
        raise


async def update_entry(
    logical: str,
    index: int,
    key: str,
    value: str,
    expected: str = "",
) -> Dict[str, object]:
    path = load(logical)
    text = replace_entry(read_text(path), index, key, value, expected)
    await _save_and_apply({path: text})
    return list_files()


async def add_entry(logical: str, key: str, value: str) -> Dict[str, object]:
    path = load(logical)
    text = append_entry(read_text(path), key, value)
    await _save_and_apply({path: text})
    return list_files()


async def delete_entry(logical: str, index: int, expected: str = "") -> Dict[str, object]:
    path = load(logical)
    await _save_and_apply({path: remove_entry(read_text(path), index, expected)})
    return list_files()


async def delete_file(logical: str) -> Dict[str, object]:
    path = load(logical)
    if path == SYSCTL_CONF:
        raise ValueError("refusing to delete /etc/sysctl.conf; delete the settings instead")
    original = read_text(path)
    backup(path)
    path.unlink(missing_ok=True)
    try:
        await apply_checked(reverting=True)
    except Exception:
        write_text(path, original)
        await apply_system()
        raise
    return list_files()
