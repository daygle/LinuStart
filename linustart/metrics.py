"""Resource history and threshold alerts.

A sampler records CPU, memory, root-filesystem usage and the 1-minute load
average once a minute, keeps the last 24 hours (persisted across restarts),
and evaluates alert thresholds on every sample. An alert fires only after
its metric has stayed over the threshold for ``sustain_minutes``, is not
repeated within ``cooldown_minutes``, and is followed by a recovery notice
once the metric drops back. Alerts go by email through the configured relay
(the same pipeline as unattended-upgrades reports) and into the audit log.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import shutil
import tempfile
import time
from collections import deque
from typing import Deque, Dict, List, Mapping, Optional

from . import audit
from .paths import ALERTS_FILE, METRICS_FILE

PROC_STAT = "/proc/stat"
PROC_MEMINFO = "/proc/meminfo"
PROC_LOADAVG = "/proc/loadavg"
INTERVAL = 60
HISTORY = 24 * 60
PERSIST_EVERY = 10
METRICS = ("cpu", "mem", "disk", "load")

DEFAULT_ALERTS: Dict[str, object] = {
    "enabled": False,
    "cpu": 90,
    "mem": 90,
    "disk": 90,
    "load_per_cpu": 2.0,
    "sustain_minutes": 5,
    "cooldown_minutes": 360,
    "recipient": "",
}
LIMITS = {
    "cpu": (1, 100), "mem": (1, 100), "disk": (1, 100),
    "load_per_cpu": (0.1, 100.0), "sustain_minutes": (1, 120), "cooldown_minutes": (5, 10080),
}
LABELS = {"cpu": "CPU usage", "mem": "Memory usage", "disk": "Disk usage (/)", "load": "Load average"}


# --------------------------------------------------------------------------
# Sampling
# --------------------------------------------------------------------------

def read_cpu_times(text: str) -> Optional[tuple]:
    """(busy, total) jiffies from the aggregate ``cpu`` line of /proc/stat."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "cpu":
            values = [int(v) for v in parts[1:9] if v.isdigit()]
            if len(values) < 5:
                return None
            idle = values[3] + values[4]  # idle + iowait
            total = sum(values)
            return total - idle, total
    return None


def cpu_percent(previous: Optional[tuple], current: Optional[tuple]) -> Optional[float]:
    if not previous or not current:
        return None
    busy = current[0] - previous[0]
    total = current[1] - previous[1]
    if total <= 0:
        return None
    return round(max(0.0, min(100.0, 100.0 * busy / total)), 1)


def mem_percent(text: str) -> Optional[float]:
    values: Dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            values[key] = int(fields[0])
    total, available = values.get("MemTotal"), values.get("MemAvailable")
    if not total or available is None:
        return None
    return round(100.0 * (total - available) / total, 1)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


class MetricsRecorder:
    def __init__(self, interval: float = INTERVAL, history: int = HISTORY) -> None:
        self.interval = interval
        self.samples: Deque[Dict[str, object]] = deque(maxlen=history)
        self._cpu_prev = read_cpu_times(_read(PROC_STAT))
        self._since_persist = 0
        self.cpus = os.cpu_count() or 1
        self.streak: Dict[str, int] = {key: 0 for key in METRICS}
        self.active: Dict[str, bool] = {key: False for key in METRICS}
        self.last_sent: Dict[str, float] = {key: float("-inf") for key in METRICS}  # never sent
        self.task: Optional[asyncio.Task] = None

    # ---- samples ---------------------------------------------------------
    def sample(self) -> Dict[str, object]:
        current = read_cpu_times(_read(PROC_STAT))
        cpu = cpu_percent(self._cpu_prev, current)
        self._cpu_prev = current
        try:
            usage = shutil.disk_usage("/")
            disk = round(100.0 * usage.used / usage.total, 1) if usage.total else None
        except OSError:
            disk = None
        try:
            load = float(_read(PROC_LOADAVG).split()[0])
        except (IndexError, ValueError):
            load = None
        return {"t": int(time.time()), "cpu": cpu, "mem": mem_percent(_read(PROC_MEMINFO)),
                "disk": disk, "load": load}

    def load(self) -> None:
        """Restore persisted history, dropping anything older than the window."""
        try:
            with open(METRICS_FILE, encoding="utf-8") as handle:
                stored = json.load(handle)
        except (OSError, ValueError):
            return
        cutoff = time.time() - self.samples.maxlen * self.interval  # type: ignore[operator]
        for item in stored if isinstance(stored, list) else []:
            if isinstance(item, dict) and isinstance(item.get("t"), (int, float)) and item["t"] >= cutoff:
                self.samples.append({key: item.get(key) for key in ("t",) + METRICS})

    def persist(self) -> None:
        path = os.fspath(METRICS_FILE)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".metrics.", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(list(self.samples), handle)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except OSError:
            pass  # history is a convenience; never let it break the panel

    # ---- alerts ----------------------------------------------------------
    def thresholds(self, config: Mapping[str, object]) -> Dict[str, float]:
        return {
            "cpu": float(config["cpu"]),  # type: ignore[arg-type]
            "mem": float(config["mem"]),  # type: ignore[arg-type]
            "disk": float(config["disk"]),  # type: ignore[arg-type]
            "load": float(config["load_per_cpu"]) * self.cpus,  # type: ignore[arg-type]
        }

    def evaluate(self, sample: Mapping[str, object], config: Mapping[str, object],
                 now: Optional[float] = None) -> List[Dict[str, object]]:
        """Alert/recovery events this sample triggers (and updates state)."""
        if not config.get("enabled"):
            self.streak = {key: 0 for key in METRICS}
            return []
        now = time.time() if now is None else now
        sustain = max(1, math.ceil(float(config["sustain_minutes"]) * 60 / self.interval))  # type: ignore[arg-type]
        cooldown = float(config["cooldown_minutes"]) * 60  # type: ignore[arg-type]
        events: List[Dict[str, object]] = []
        for key, limit in self.thresholds(config).items():
            value = sample.get(key)
            if not isinstance(value, (int, float)):
                continue
            if value > limit:
                self.streak[key] += 1
                if (not self.active[key] and self.streak[key] >= sustain
                        and now - self.last_sent[key] >= cooldown):
                    self.active[key] = True
                    self.last_sent[key] = now
                    events.append({"kind": "alert", "metric": key, "value": value, "limit": limit})
            else:
                self.streak[key] = 0
                if self.active[key]:
                    self.active[key] = False
                    events.append({"kind": "recovered", "metric": key, "value": value, "limit": limit})
        return events

    # ---- loop ------------------------------------------------------------
    async def run(self, notify) -> None:
        while True:
            sample = self.sample()
            self.samples.append(sample)
            for event in self.evaluate(sample, load_alert_config()):
                await notify(event)
            self._since_persist += 1
            if self._since_persist >= PERSIST_EVERY:
                self._since_persist = 0
                self.persist()
            await asyncio.sleep(self.interval)

    def start(self, notify) -> None:
        self.load()
        self.task = asyncio.get_running_loop().create_task(self.run(notify))

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        self.persist()


# --------------------------------------------------------------------------
# Alert configuration and delivery
# --------------------------------------------------------------------------

def validate_alert_config(raw: Mapping[str, object]) -> Dict[str, object]:
    from .modules.mail import valid_recipient

    config = dict(DEFAULT_ALERTS)
    for key, value in raw.items():
        if key not in DEFAULT_ALERTS:
            raise ValueError(f"unknown alert setting: {key}")
        if key == "enabled":
            if not isinstance(value, bool):
                raise ValueError("enabled must be true or false")
            config[key] = value
        elif key == "recipient":
            recipient = str(value or "").strip()
            if recipient and not valid_recipient(recipient):
                raise ValueError(f"invalid alert recipient: {recipient!r}")
            config[key] = recipient
        else:
            low, high = LIMITS[key]
            try:
                number = float(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number") from None
            if not low <= number <= high:
                raise ValueError(f"{key} must be between {low} and {high}")
            config[key] = number if key == "load_per_cpu" else int(number)
    return config


def load_alert_config() -> Dict[str, object]:
    try:
        with open(ALERTS_FILE, encoding="utf-8") as handle:
            return validate_alert_config(json.load(handle))
    except (OSError, ValueError, AttributeError):
        return dict(DEFAULT_ALERTS)


def save_alert_config(raw: Mapping[str, object]) -> Dict[str, object]:
    from .util import write_text

    config = validate_alert_config(raw)
    write_text(ALERTS_FILE, json.dumps(config, indent=2) + "\n")
    return config


async def alert_recipient(config: Mapping[str, object]) -> str:
    """The configured recipient, else the mail page's report address."""
    from .modules import mail

    recipient = str(config.get("recipient") or "")
    if recipient:
        return recipient
    state = await mail.status()
    return str(state.get("report_to") or state.get("from_address") or "")


def alert_message(event: Mapping[str, object], hostname: str, recipient: str, sender: str) -> str:
    from .modules.mail import _header_value

    label = LABELS.get(str(event["metric"]), str(event["metric"]))
    unit = "" if event["metric"] == "load" else "%"
    if event["kind"] == "alert":
        subject = f"[{hostname}] {label} is {event['value']}{unit} (limit {event['limit']:g}{unit})"
        body = (f"{label} on {hostname} has stayed above {event['limit']:g}{unit}.\n"
                f"Current value: {event['value']}{unit}\n")
    elif event["kind"] == "recovered":
        subject = f"[{hostname}] {label} recovered ({event['value']}{unit})"
        body = f"{label} on {hostname} is back below {event['limit']:g}{unit}.\n"
    else:
        subject = f"[{hostname}] LinuStart alert test"
        body = "This is a test of LinuStart's resource alerts.\n"
    return (
        (f"From: LinuStart <{_header_value(sender)}>\n" if sender else "From: LinuStart\n")
        + f"To: {_header_value(recipient)}\n"
        + f"Subject: {_header_value(subject)}\n\n"
        + body
        + "\n-- \nSent by LinuStart resource alerts.\n"
    )


async def send_alert(event: Mapping[str, object]) -> bool:
    """Deliver one alert/recovery email; always audit-logged."""
    import socket

    from .modules import mail
    from .util import run

    config = load_alert_config()
    recipient = await alert_recipient(config)
    label = LABELS.get(str(event.get("metric")), "test")
    detail = f"{event['kind']}: {label} {event.get('value', '')}".strip()
    if not recipient or not mail.valid_recipient(recipient):
        audit.record("alert", f"{detail} (no recipient configured; not emailed)", ok=False)
        return False
    sender = str((await mail.status()).get("from_address") or "")
    message = alert_message(event, socket.gethostname(), recipient, sender)
    try:
        result = await run(mail.test_command(sender, recipient), input_text=message, timeout=60)
        ok = result.ok
    except RuntimeError:
        ok = False
    audit.record("alert", f"{detail} -> {recipient}" + ("" if ok else " (sendmail failed)"), ok=ok)
    return ok
