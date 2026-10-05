"""Resource sampling, history persistence and alert evaluation."""

import asyncio
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from linustart import audit, metrics  # noqa: E402

CONFIG = dict(metrics.DEFAULT_ALERTS, enabled=True, cpu=80, sustain_minutes=3, cooldown_minutes=60)


def test_cpu_percent_from_proc_stat_deltas():
    first = metrics.read_cpu_times("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n")
    second = metrics.read_cpu_times("cpu  150 0 150 900 0 0 0 0 0 0\n")
    assert first == (200, 1000) and second == (300, 1200)
    assert metrics.cpu_percent(first, second) == 50.0
    assert metrics.cpu_percent(None, second) is None


def test_mem_percent():
    assert metrics.mem_percent("MemTotal: 1000 kB\nMemFree: 1 kB\nMemAvailable: 250 kB\n") == 75.0
    assert metrics.mem_percent("junk") is None


def test_sample_reads_the_live_system():
    sample = metrics.MetricsRecorder().sample()
    assert set(sample) == {"t", "cpu", "mem", "disk", "load"}
    assert 0 <= sample["disk"] <= 100


def test_alert_needs_a_sustained_breach_then_recovers():
    recorder = metrics.MetricsRecorder(interval=60)
    events = [recorder.evaluate({"cpu": v}, CONFIG, now=1000 + i * 60) for i, v in enumerate([95, 95, 95, 95])]
    assert events[0] == [] and events[1] == []  # three minutes before it counts
    assert events[2] == [{"kind": "alert", "metric": "cpu", "value": 95, "limit": 80.0}]
    assert events[3] == []  # already active: no repeat
    assert recorder.evaluate({"cpu": 10}, CONFIG, now=1300)[0]["kind"] == "recovered"


def test_cooldown_suppresses_a_quick_repeat():
    recorder = metrics.MetricsRecorder(interval=60)
    for i in range(3):
        recorder.evaluate({"cpu": 95}, CONFIG, now=i * 60)
    recorder.evaluate({"cpu": 10}, CONFIG, now=200)
    repeat = [recorder.evaluate({"cpu": 95}, CONFIG, now=300 + i * 60) for i in range(3)]
    assert all(not e for e in repeat)  # inside the 60-minute cooldown
    # the breach never ended, so the alert goes out as soon as the cooldown has passed
    later = [recorder.evaluate({"cpu": 95}, CONFIG, now=4000 + i * 60) for i in range(3)]
    assert later[0] and later[0][0]["kind"] == "alert" and not later[1]


def test_load_threshold_scales_with_cpus():
    recorder = metrics.MetricsRecorder()
    recorder.cpus = 4
    assert recorder.thresholds(CONFIG)["load"] == 8.0


def test_disabled_alerts_do_nothing():
    recorder = metrics.MetricsRecorder()
    assert recorder.evaluate({"cpu": 100}, dict(CONFIG, enabled=False)) == []


def test_alert_config_validation_and_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics, "ALERTS_FILE", tmp_path / "alerts.json")
    from linustart import util

    monkeypatch.setattr(util, "BACKUP_DIR", tmp_path / "backups")
    saved = metrics.save_alert_config({"enabled": True, "disk": 85, "recipient": "ops@example.com"})
    assert saved["disk"] == 85 and metrics.load_alert_config() == saved
    for bad in [{"cpu": 0}, {"cpu": 101}, {"enabled": "yes"}, {"recipient": "-x@y.zz"}, {"bogus": 1}]:
        with pytest.raises(ValueError):
            metrics.validate_alert_config(bad)


def test_history_persists_and_drops_stale_samples(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics, "METRICS_FILE", tmp_path / "metrics.json")
    now = int(metrics.time.time())
    recorder = metrics.MetricsRecorder(interval=60, history=10)
    recorder.samples.extend({"t": now - i * 60, "cpu": i, "mem": 1, "disk": 1, "load": 0.1} for i in range(3))
    recorder.persist()
    (tmp_path / "metrics.json").write_text(json.dumps(
        json.loads((tmp_path / "metrics.json").read_text()) + [{"t": now - 99999, "cpu": 1}]))
    fresh = metrics.MetricsRecorder(interval=60, history=10)
    fresh.load()
    assert len(fresh.samples) == 3  # the day-old sample is outside the window


def test_alert_message_and_delivery(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", tmp_path / "audit.log")
    message = metrics.alert_message({"kind": "alert", "metric": "disk", "value": 93.5, "limit": 90.0},
                                    "web1", "ops@example.com", "panel@example.com")
    assert "Subject: [web1] Disk usage (/) is 93.5% (limit 90%)" in message
    assert "\nTo: ops@example.com\n" in message

    async def no_recipient(config):
        return ""

    monkeypatch.setattr(metrics, "alert_recipient", no_recipient)
    monkeypatch.setattr(metrics, "load_alert_config", lambda: dict(metrics.DEFAULT_ALERTS))
    assert asyncio.run(metrics.send_alert({"kind": "test", "metric": "test"})) is False
    assert "no recipient configured" in (tmp_path / "audit.log").read_text()
