"""Cron jobs: view, edit and delete scheduled entries.

Three places hold cron entries:

* ``/etc/crontab`` - system wide; entries carry a user column
* ``/etc/cron.d/*`` - drop-in files; entries carry a user column
* ``/var/spool/cron/crontabs/*`` - user crontabs; no user column

A cron file is root-executed configuration, so every write validates the
schedule and the command first: a newline inside a command would smuggle in
a second job, and a free-form schedule field would let the same happen one
word later. Parsing and rendering are pure string functions so they can be
tested without root; system files are written through :func:`write_text`
(which backs up first) and user crontabs through the ``crontab`` binary, so
ownership and mode stay correct.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from ..paths import CRON_D, CRONTAB, CRON_SPOOL, ROOT
from ..util import backup, read_text, run, write_text
from .users import valid_username

SPECIAL_SCHEDULES = {
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
}
MONTH_NAMES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
DOW_NAMES = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
# minute, hour, day-of-month, month, day-of-week (7 is a second Sunday)
SCHEDULE_FIELDS = (
    (0, 59, {}),
    (0, 23, {}),
    (1, 31, {}),
    (1, 12, MONTH_NAMES),
    (0, 7, DOW_NAMES),
)
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# cron (via run-parts naming rules) silently ignores /etc/cron.d files whose
# names contain anything else - a dot, say - so new files must match this.
CRON_D_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_COMMAND = 2000
# Shown in place of an exception when one file cannot be listed. The raw
# OSError text can name paths and permissions the API caller has no business
# seeing, so the response carries a fixed reason and the operator looks at the
# path itself.
READ_ERROR = "cannot read this file"


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------

def logical_path(path: Path) -> str:
    """The absolute path as an operator would type it (no LINUSTART_ROOT)."""
    try:
        return "/" + path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def rooted_path(value: str) -> Path:
    """Map an absolute path onto this system, refusing traversal."""
    pure = PurePosixPath(value)
    if not pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"not an absolute cron path: {value!r}")
    return ROOT.joinpath(*pure.parts[1:])


def classify(path: Path) -> Tuple[str, str]:
    """(kind, owner) for a path; raises ValueError if it is not a cron file.

    ``kind`` is "system", "cron.d" or "user"; only user crontabs have an
    owner.
    """
    if path == CRONTAB:
        return ("system", "")
    try:
        relative = path.relative_to(CRON_D)
    except ValueError:
        relative = None
    if relative is not None:
        if len(relative.parts) != 1:
            raise ValueError(f"not a cron.d file: {logical_path(path)}")
        return ("cron.d", "")
    try:
        relative = path.relative_to(CRON_SPOOL)
    except ValueError:
        raise ValueError(f"not a cron file: {logical_path(path)}") from None
    owner = relative.parts[0] if relative.parts else ""
    if not valid_username(owner):
        raise ValueError(f"not a user crontab: {logical_path(path)}")
    return ("user", owner)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def _atom(token: str, low: int, high: int, names: Dict[str, int]) -> Optional[int]:
    token = token.strip().lower()
    if not token:
        return None
    if token in names:
        return names[token]
    if not token.isdigit():
        return None
    value = int(token)
    return value if low <= value <= high else None


def valid_field(raw: str, low: int, high: int, names: Optional[Dict[str, int]] = None) -> bool:
    """One cron field: ``*``, ``5``, ``1-30``, ``*/5``, ``1-30/2``, ``a,b``."""
    names = names or {}
    if not raw:
        return False
    for part in raw.split(","):
        if not part:
            return False
        base, slash, step = part.partition("/")
        if slash and (not step.isdigit() or int(step) == 0):
            return False
        if base == "*":
            continue
        if base.count("-") > 1 or base.startswith("-") or base.endswith("-"):
            return False
        if "-" in base:
            start, _, end = base.partition("-")
            low_value = _atom(start, low, high, names)
            high_value = _atom(end, low, high, names)
            if low_value is None or high_value is None or low_value > high_value:
                return False
        elif _atom(base, low, high, names) is None:
            return False
    return True


def valid_schedule(schedule: str) -> bool:
    """Five fields, or one of the ``@daily``-style shorthands."""
    schedule = (schedule or "").strip()
    if not schedule:
        return False
    if schedule.lower() in SPECIAL_SCHEDULES:
        return True
    parts = schedule.split()
    if len(parts) != 5:
        return False
    return all(
        valid_field(part, low, high, names)
        for part, (low, high, names) in zip(parts, SCHEDULE_FIELDS)
    )


def valid_command(command: str) -> bool:
    """A command is one line of text and nothing else."""
    if not command or len(command) > MAX_COMMAND:
        return False
    if any(char in command for char in "\n\r\x00"):
        return False
    return bool(command.strip())


def validate_fields(schedule: str, command: str, user: str, with_user: bool) -> Tuple[str, str, str]:
    """Normalize the three editable fields or raise with a usable message."""
    schedule = " ".join((schedule or "").split())
    if not valid_schedule(schedule):
        raise ValueError(
            f"invalid schedule: {schedule!r} (use 'm h dom mon dow' or @daily, @reboot, ...)"
        )
    command = (command or "").strip()
    if not valid_command(command):
        raise ValueError("command must be a single non-empty line")
    user = (user or "").strip()
    if with_user:
        if not valid_username(user):
            raise ValueError(f"invalid user: {user!r}")
    elif user:
        raise ValueError("user crontabs have no user column")
    return (schedule, command, user)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@dataclass
class CronEntry:
    index: int      # physical line number in the file
    schedule: str
    user: str
    command: str
    enabled: bool
    valid: bool
    raw: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "schedule": self.schedule,
            "user": self.user,
            "command": self.command,
            "enabled": self.enabled,
            "valid": self.valid,
            "raw": self.raw,
        }


def _parse_line(line: str, with_user: bool) -> Optional[Tuple[str, str, str, bool]]:
    """(schedule, user, command, schedule_is_valid) or None if not a job."""
    if not line:
        return None
    if line.startswith("@"):
        # "@daily user command" in system files, "@daily command" in a
        # user crontab
        parts = line.split(None, 2 if with_user else 1)
        schedule = parts[0].lower()
        if schedule not in SPECIAL_SCHEDULES or len(parts) < (3 if with_user else 2):
            return None
        if with_user:
            user, command = parts[1], parts[2].strip()
            if not valid_username(user):
                return None
        else:
            user, command = "", parts[1].strip()
        if not command:
            return None
        return (schedule, user, command, True)
    limit = 6 if with_user else 5
    parts = line.split(None, limit)
    if len(parts) != limit + 1:
        return None
    schedule = " ".join(parts[:5])
    if with_user:
        user = parts[5]
        command = parts[6].strip()
    else:
        user, command = "", parts[5].strip()
    if not command:
        return None
    return (schedule, user, command, valid_schedule(schedule))


def parse_entries(text: str, *, with_user: bool) -> List[CronEntry]:
    """Every cron job in a file, comments and env assignments ignored.

    Commented-out jobs are reported with ``enabled=False`` so they can be
    switched back on; a comment only counts when it really is a job, which
    is why the schedule of a commented line has to validate.
    """
    entries: List[CronEntry] = []
    for index, raw in enumerate(text.splitlines()):
        stripped = raw.strip()
        if not stripped or ENV_RE.match(stripped):
            continue
        enabled = True
        line = stripped
        if line.startswith("#"):
            candidate = line.lstrip("#").strip()
            parsed = _parse_line(candidate, with_user)
            if parsed is None or not parsed[3]:
                continue  # ordinary prose comment
            line, enabled = candidate, False
        else:
            parsed = _parse_line(line, with_user)
            if parsed is None:
                continue
        schedule, user, command, ok = parsed
        entries.append(CronEntry(index, schedule, user, command, enabled, ok, raw))
    return entries


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_entry(schedule: str, command: str, user: str = "", enabled: bool = True) -> str:
    parts = [schedule]
    if user:
        parts.append(user)
    parts.append(command)
    line = " ".join(parts)
    return line if enabled else f"# {line}"


def render_like(original: str, schedule: str, command: str, user: str = "", enabled: bool = True) -> str:
    """Render like *original* would look, reusing its column alignment.

    Crontabs are usually laid out in columns; collapsing the padding on every
    edit makes a one-line change look like a whole-file rewrite in diffs.
    """
    stripped = (original or "").strip()
    if stripped.startswith("#"):
        stripped = stripped.lstrip("#").strip()
    # one separator per gap between tokens, in order
    gaps = re.findall(r"\s+", stripped)

    def gap(index: int) -> str:
        return gaps[index] if index < len(gaps) else " "

    # tokens 0-4 are the schedule, so gap 4 sits after it
    line = f"{schedule}{gap(4)}{user}{gap(5)}{command}" if user else f"{schedule}{gap(4)}{command}"
    return line if enabled else f"# {line}"


def replace_entry(
    text: str,
    index: int,
    schedule: str,
    command: str,
    user: str = "",
    enabled: bool = True,
    *,
    with_user: bool = True,
    expected: str = "",
) -> str:
    """Rewrite one line in place, leaving every other line untouched.

    ``expected`` is the line as the caller last saw it; a mismatch means
    somebody edited the file in the meantime and the change is refused.
    """
    schedule, command, user = validate_fields(schedule, command, user, with_user)
    lines = text.splitlines()
    if index < 0 or index >= len(lines):
        raise ValueError(f"no line {index} in this cron file")
    if expected and lines[index] != expected:
        raise ValueError("this cron file changed since it was loaded; reload and try again")
    lines[index] = render_like(lines[index], schedule, command, user, enabled)
    return "\n".join(lines) + "\n"


def append_entry(
    text: str,
    schedule: str,
    command: str,
    user: str = "",
    enabled: bool = True,
    *,
    with_user: bool = True,
) -> str:
    schedule, command, user = validate_fields(schedule, command, user, with_user)
    line = render_entry(schedule, command, user, enabled)
    body = text.rstrip("\n")
    return f"{body}\n{line}\n" if body else f"{line}\n"


def remove_entry(text: str, index: int, expected: str = "") -> str:
    lines = text.splitlines()
    if index < 0 or index >= len(lines):
        raise ValueError(f"no line {index} in this cron file")
    if expected and lines[index] != expected:
        raise ValueError("this cron file changed since it was loaded; reload and try again")
    del lines[index]
    return "\n".join(lines) + "\n" if lines else ""


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

@dataclass
class CronFile:
    path: Path
    kind: str
    owner: str

    @property
    def logical(self) -> str:
        return logical_path(self.path)

    def read(self) -> str:
        return read_text(self.path)

    def to_dict(self) -> Dict[str, object]:
        text = self.read()
        entries = parse_entries(text, with_user=self.kind != "user")
        return {
            "path": self.logical,
            "kind": self.kind,
            "owner": self.owner,
            "with_user": self.kind != "user",
            "entries": [entry.to_dict() for entry in entries],
            "count": len(entries),
        }


def load(logical: str) -> CronFile:
    path = rooted_path(logical)
    kind, owner = classify(path)
    return CronFile(path=path, kind=kind, owner=owner)


def _iter_paths() -> List[Path]:
    paths: List[Path] = []
    if CRONTAB.is_file():
        paths.append(CRONTAB)
    if CRON_D.is_dir():
        for path in sorted(CRON_D.iterdir()):
            # skip run-parts drop-ins it would ignore, plus editor backups
            if path.is_file() and not path.name.startswith(".") and not path.name.endswith("~"):
                paths.append(path)
    if CRON_SPOOL.is_dir():
        for path in sorted(CRON_SPOOL.iterdir()):
            if path.is_file() and valid_username(path.name):
                paths.append(path)
    return paths


def list_files() -> Dict[str, object]:
    files = []
    for path in _iter_paths():
        try:
            kind, owner = classify(path)
            files.append(CronFile(path=path, kind=kind, owner=owner).to_dict())
        except (OSError, ValueError):
            # The operator gets a stable reason, never the raw exception:
            # OSError text carries paths and permissions we need not echo.
            files.append(
                {"path": logical_path(path), "kind": "error", "detail": READ_ERROR, "entries": []}
            )
    return {
        "files": files,
        "jobs": sum(int(item.get("count") or 0) for item in files),
        "paths": {
            "crontab": logical_path(CRONTAB),
            "cron_d": logical_path(CRON_D),
            "spool": logical_path(CRON_SPOOL),
        },
        "schedules": ["@reboot", "@hourly", "@daily", "@midnight", "@weekly", "@monthly", "@yearly"],
    }


async def save(cron_file: CronFile, text: str) -> None:
    """Install *text* as the contents of *cron_file*.

    User crontabs go through ``crontab`` so the spool keeps the right owner
    and mode, and so cron's own parser gets the final say.
    """
    if cron_file.kind == "user":
        backup(cron_file.path)
        await run(["crontab", "-u", cron_file.owner, "-"], input_text=text, check=True)
    else:
        write_text(cron_file.path, text)


async def update_entry(
    logical: str,
    index: int,
    schedule: str,
    command: str,
    user: str = "",
    enabled: bool = True,
    expected: str = "",
) -> Dict[str, object]:
    cron_file = load(logical)
    text = replace_entry(
        cron_file.read(),
        index,
        schedule,
        command,
        user or cron_file.owner,
        enabled,
        with_user=cron_file.kind != "user",
        expected=expected,
    )
    await save(cron_file, text)
    return list_files()


async def add_entry(
    logical: str,
    schedule: str,
    command: str,
    user: str = "",
    enabled: bool = True,
) -> Dict[str, object]:
    cron_file = load(logical)
    with_user = cron_file.kind != "user"
    if (
        cron_file.kind == "cron.d"
        and not cron_file.path.exists()
        and not CRON_D_NAME_RE.match(cron_file.path.name)
    ):
        raise ValueError(
            f"cron ignores /etc/cron.d files named {cron_file.path.name!r}; "
            "use letters, digits, '-' and '_' only"
        )
    if not with_user and not cron_file.owner:
        raise ValueError("cannot create a crontab without a user")
    text = append_entry(
        cron_file.read(),
        schedule,
        command,
        user if with_user else "",
        enabled,
        with_user=with_user,
    )
    await save(cron_file, text)
    return list_files()


async def delete_entry(logical: str, index: int, expected: str = "") -> Dict[str, object]:
    cron_file = load(logical)
    await save(cron_file, remove_entry(cron_file.read(), index, expected))
    return list_files()


async def delete_file(logical: str) -> Dict[str, object]:
    cron_file = load(logical)
    if cron_file.kind == "system":
        raise ValueError("refusing to delete /etc/crontab; delete the jobs instead")
    backup(cron_file.path)
    if cron_file.kind == "user":
        await run(["crontab", "-u", cron_file.owner, "-r"])
    else:
        cron_file.path.unlink(missing_ok=True)
    return list_files()