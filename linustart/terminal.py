"""Web terminal: interactive shells over WebSocket with session logging.

Each session runs a real PTY-backed shell (``bash``), optionally as another
user via ``runuser``. Everything the terminal emits is recorded to
``/var/lib/linustart/terminal/<id>.log`` and the session open/close is
recorded in the audit log, so a terminal is as accountable as any other panel
action.

The wire protocol is JSON in both directions:

* client → ``{"type": "auth", "token": "..."}`` first (when a token is set),
  then ``{"type": "input", "data": "..."}`` / ``{"type": "resize", ...}``
* server → ``{"type": "output", "data": "..."}`` / ``{"type": "closed", ...}``

Only the standard library is used (``pty``, ``os``, ``asyncio``) - no new
runtime dependencies.
"""

from __future__ import annotations

import asyncio
import codecs
import os
import shutil
import signal
import struct
import uuid

try:
    import fcntl
    import pty
    import termios

    HAS_PTY = True
except ImportError:  # Windows dev machines: the terminal itself is POSIX-only
    fcntl = pty = termios = None  # type: ignore[assignment]
    HAS_PTY = False
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .modules.users import parse_passwd
from .paths import PASSWD_FILE, SHELLS_FILE, TERMINAL_LOG_DIR
from .util import now_iso, read_text

MAX_SESSIONS = 8
# Closed sessions stay listed (with their log name) for the operator; only
# the most recent ones are kept so the list cannot grow without bound.
MAX_CLOSED_KEPT = 50
CHUNK = 8192
# Session recordings: the newest are kept, and one session stops recording
# past a size cap (a `cat /dev/urandom` must not fill the disk).
LOGS_KEPT = 200
MAX_LOG_BYTES = 50 * 1024 * 1024


def prune_logs(keep: int = LOGS_KEPT) -> None:
    """Remove the oldest session recordings beyond *keep*."""
    try:
        logs = sorted(
            (entry for entry in os.scandir(TERMINAL_LOG_DIR) if entry.is_file() and entry.name.endswith(".log")),
            key=lambda entry: entry.stat().st_mtime,
        )
    except FileNotFoundError:
        return
    for entry in logs[: max(0, len(logs) - keep)]:
        try:
            os.unlink(entry.path)
        except OSError:
            pass


def pick_shell() -> str:
    """Prefer bash, fall back to the first valid login shell."""
    for candidate in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
        if shutil.which(candidate):
            return candidate
    for line in read_text(SHELLS_FILE).splitlines():
        line = line.strip()
        if line.startswith("/") and os.access(line, os.X_OK):
            return line
    return "/bin/sh"


def shell_argv(user: Optional[str] = None) -> List[str]:
    """argv for the session's shell; non-root users go through ``runuser``."""
    shell = pick_shell()
    if user and user != "root":
        if not shutil.which("runuser"):
            raise RuntimeError("runuser is not available; cannot start a session as another user")
        return ["runuser", "-u", user, "--", shell, "-l"]
    return [shell, "-l"]


def validate_user(name: Optional[str]) -> Optional[str]:
    if name is None or name == "":
        return None
    name = name.strip()
    for entry in parse_passwd(read_text(PASSWD_FILE)):
        if entry["name"] == name:
            return name
    raise ValueError(f"no such user: {name}")


def clamp_size(value: object, low: int, high: int, default: int) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


@dataclass
class TerminalSession:
    id: str
    user: str
    argv: List[str]
    cols: int
    rows: int
    proc: asyncio.subprocess.Process
    master_fd: int
    log_path: str
    created_at: str = field(default_factory=now_iso)
    closed: bool = False
    eof: bool = False
    closed_at: Optional[str] = None
    output: "asyncio.Queue[Optional[str]]" = field(default_factory=asyncio.Queue)
    decoder: object = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"))
    log_handle: Optional[object] = field(default=None, repr=False)
    log_bytes: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "user": self.user,
            "cols": self.cols,
            "rows": self.rows,
            "created_at": self.created_at,
            "closed": self.closed,
            "closed_at": self.closed_at,
            "log": os.path.basename(self.log_path),
        }


class TerminalManager:
    """Owns PTY sessions and pumps their output into asyncio queues."""

    def __init__(self) -> None:
        self.sessions: Dict[str, TerminalSession] = {}

    def active(self) -> List[TerminalSession]:
        return [s for s in self.sessions.values() if not s.closed]

    async def create(self, user: Optional[str] = None, cols: object = 100, rows: object = 30) -> TerminalSession:
        if not HAS_PTY:
            raise RuntimeError("the web terminal needs a POSIX platform with pty support")
        target = validate_user(user)
        if len(self.active()) >= MAX_SESSIONS:
            raise RuntimeError(f"too many open terminal sessions (limit {MAX_SESSIONS})")
        cols_n = clamp_size(cols, 20, 500, 100)
        rows_n = clamp_size(rows, 5, 200, 30)

        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows_n, cols_n, 0, 0))

        argv = shell_argv(target)
        env = {
            **os.environ,
            "TERM": "xterm-256color",
            "COLUMNS": str(cols_n),
            "LINES": str(rows_n),
        }

        def child_setup() -> None:
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            preexec_fn=child_setup,
        )
        os.close(slave_fd)

        session_id = uuid.uuid4().hex[:12]
        TERMINAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
        prune_logs(LOGS_KEPT - 1)  # room for this one
        log_path = TERMINAL_LOG_DIR / f"{session_id}.log"
        # Kept open for the life of the session: reopening the file for every
        # chunk of output costs a syscall round trip per keystroke echo.
        log_handle = log_path.open("a", encoding="utf-8")
        log_handle.write(
            f"# session {session_id} user={target or 'root'} opened {now_iso()} "
            f"cols={cols_n} rows={rows_n} argv={' '.join(argv)}\n"
        )
        log_handle.flush()

        session = TerminalSession(
            id=session_id,
            user=target or "root",
            argv=argv,
            cols=cols_n,
            rows=rows_n,
            proc=proc,
            master_fd=master_fd,
            log_path=str(log_path),
            output=asyncio.Queue(),
            log_handle=log_handle,
        )
        self._prune_closed()
        self.sessions[session_id] = session
        asyncio.get_running_loop().add_reader(master_fd, self._on_readable, session)
        return session

    def _prune_closed(self) -> None:
        closed = [sid for sid, s in self.sessions.items() if s.closed]
        for sid in closed[: max(0, len(closed) - MAX_CLOSED_KEPT)]:
            del self.sessions[sid]

    def _log(self, session: TerminalSession, text: str, *, force: bool = False) -> None:
        handle = session.log_handle
        if handle is None:
            return
        if not force and session.log_bytes >= MAX_LOG_BYTES:
            return
        if not force and session.log_bytes + len(text) >= MAX_LOG_BYTES:
            text = f"\n# recording stopped: session output passed {MAX_LOG_BYTES // (1024 * 1024)} MiB\n"
            session.log_bytes = MAX_LOG_BYTES
        else:
            session.log_bytes += len(text)
        try:
            handle.write(text)  # type: ignore[union-attr]
            handle.flush()  # type: ignore[union-attr]
        except (OSError, ValueError):
            pass

    def _on_readable(self, session: TerminalSession) -> None:
        if session.closed or session.eof:
            return
        try:
            data = os.read(session.master_fd, CHUNK)
        except OSError:
            data = b""
        if not data:
            self._pump_closed(session)
            return
        text = session.decoder.decode(data)  # type: ignore[union-attr]
        self._log(session, text)
        session.output.put_nowait(text)

    def _pump_closed(self, session: TerminalSession) -> None:
        """The shell is gone: stop watching the fd and tell the pump once.

        A PTY master whose child exited stays readable (every read fails with
        EIO), so the reader must be removed here - otherwise the event loop
        calls back in a tight loop, burning a CPU and queueing a sentinel on
        every pass until the browser happens to disconnect.
        """
        if session.closed or session.eof:
            return
        session.eof = True
        try:
            asyncio.get_running_loop().remove_reader(session.master_fd)
        except (RuntimeError, ValueError):
            pass
        session.output.put_nowait(None)

    def write(self, session_id: str, data: str) -> None:
        session = self._get(session_id)
        if session.closed or session.eof:
            raise ValueError("session is closed")
        payload = data.encode("utf-8")
        try:
            # os.write may take only part of a large paste; finish the job.
            while payload:
                written = os.write(session.master_fd, payload)
                payload = payload[written:]
        except OSError as exc:
            raise ValueError(f"the shell is no longer accepting input: {exc}")

    def resize(self, session_id: str, cols: object, rows: object) -> None:
        session = self._get(session_id)
        if session.closed:
            raise ValueError("session is closed")
        session.cols = clamp_size(cols, 20, 500, session.cols)
        session.rows = clamp_size(rows, 5, 200, session.rows)
        fcntl.ioctl(
            session.master_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", session.rows, session.cols, 0, 0),
        )

    async def close(self, session_id: str, reason: str = "closed by panel") -> Dict[str, object]:
        session = self.sessions.get(session_id)
        if session is None:
            raise ValueError(f"no such terminal session: {session_id}")
        if not session.closed:
            session.closed = True
            session.closed_at = now_iso()
            try:
                asyncio.get_running_loop().remove_reader(session.master_fd)
            except (RuntimeError, ValueError):
                pass
            try:
                os.close(session.master_fd)
            except OSError:
                pass
            if session.proc.returncode is None:
                try:
                    os.killpg(os.getpgid(session.proc.pid), signal.SIGHUP)
                except OSError:
                    pass
                try:
                    await asyncio.wait_for(session.proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    session.proc.kill()
                    await session.proc.wait()
            self._log(session, f"\n# session {session.id} closed {session.closed_at} ({reason})\n", force=True)
            try:
                session.log_handle.close()  # type: ignore[union-attr]
            except (AttributeError, OSError):
                pass
            session.log_handle = None
        return session.to_dict()

    def _get(self, session_id: str) -> TerminalSession:
        session = self.sessions.get(session_id)
        if session is None:
            raise ValueError(f"no such terminal session: {session_id}")
        return session

    def list(self) -> List[Dict[str, object]]:
        return [session.to_dict() for session in self.sessions.values()]
