"""Append-only audit log of everything the panel changes."""

from __future__ import annotations

import json
from typing import Dict, List

from .paths import AUDIT_LOG
from .util import now_iso


def record(action: str, detail: str, *, ok: bool = True) -> None:
    entry = {"ts": now_iso(), "action": action, "detail": detail, "ok": ok}
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def read(limit: int = 200) -> List[Dict[str, object]]:
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    entries: List[Dict[str, object]] = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries.reverse()
    return entries
