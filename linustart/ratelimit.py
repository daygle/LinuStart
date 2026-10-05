"""Brute-force protection for the access token.

Each client address may present a wrong token a limited number of times in
a sliding window; after that every request from it is refused (HTTP 429)
until the lockout ends - without even looking at the token, so a locked-out
guesser learns nothing. Requests that carry no token at all are not counted:
the browser makes several of those before anyone has typed a token in.

The state is in memory on purpose: a restart clearing it is harmless, and
nothing an attacker sends can make it grow without bound.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

MAX_FAILURES = 10
WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 900
MAX_TRACKED = 4096


class AuthThrottle:
    def __init__(
        self,
        max_failures: int = MAX_FAILURES,
        window: float = WINDOW_SECONDS,
        lockout: float = LOCKOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self.clock = clock
        self._failures: Dict[str, List[float]] = {}
        self._locked_until: Dict[str, float] = {}

    def retry_after(self, key: str) -> int:
        """Seconds until *key* may try again (0 when it is not locked out)."""
        until = self._locked_until.get(key)
        if until is None:
            return 0
        left = until - self.clock()
        if left <= 0:
            del self._locked_until[key]
            return 0
        return int(left) + 1

    def failure(self, key: str) -> bool:
        """Record a wrong token; True when this failure starts a lockout."""
        now = self.clock()
        recent = [t for t in self._failures.get(key, []) if now - t < self.window]
        recent.append(now)
        if len(recent) >= self.max_failures:
            self._failures.pop(key, None)
            self._locked_until[key] = now + self.lockout
            return True
        self._failures[key] = recent
        self._prune(now)
        return False

    def success(self, key: str) -> None:
        self._failures.pop(key, None)

    def _prune(self, now: float) -> None:
        if len(self._failures) <= MAX_TRACKED:
            return
        for key in [k for k, times in self._failures.items() if now - times[-1] >= self.window]:
            del self._failures[key]
        # Still over: drop the oldest offenders rather than grow.
        if len(self._failures) > MAX_TRACKED:
            for key in sorted(self._failures, key=lambda k: self._failures[k][-1])[: len(self._failures) - MAX_TRACKED]:
                del self._failures[key]
        for key in [k for k, until in self._locked_until.items() if until <= now]:
            del self._locked_until[key]


def client_key(host: Optional[str]) -> str:
    return host or "unknown"
