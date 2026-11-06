"""Brute-force protection for the access token.

Each client address may present a wrong token a limited number of times in
a sliding window; after that every request from it is refused (HTTP 429)
until the lockout ends - without even looking at the token, so a locked-out
guesser learns nothing. Requests that carry no token at all are not counted:
the browser makes several of those before anyone has typed a token in.

The address is the transport peer, or - behind a reverse proxy - the client
address that proxy reports for it. That report is only believed when the peer
is a configured trusted proxy (see ``client_address``): otherwise everyone
behind the proxy would share one lockout, and trusting the header blindly
would let a guesser pick a new identity per request.

The state is in memory on purpose: a restart clearing it is harmless, and
nothing an attacker sends can make it grow without bound.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

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
            self._prune(now)  # pruned after the insert, so the cap holds
            return True
        self._failures[key] = recent
        self._prune(now)
        return False

    def success(self, key: str) -> None:
        self._failures.pop(key, None)

    def _prune(self, now: float) -> None:
        """Drop state that no longer means anything, so it cannot grow.

        Runs on every recorded failure rather than only when the failure map
        is large: a scan from many addresses locks each address out once, and
        those lockouts would otherwise stay in memory for the life of the
        process even after they expired.
        """
        for key in [k for k, until in self._locked_until.items() if until <= now]:
            del self._locked_until[key]
        # Still over the cap (a flood from many addresses): drop the lockouts
        # that expire soonest. A few of those can guess again, which is the
        # price of a map that cannot grow without bound.
        excess = len(self._locked_until) - MAX_TRACKED
        if excess > 0:
            for key in sorted(self._locked_until, key=lambda k: self._locked_until[k])[:excess]:
                del self._locked_until[key]
        if len(self._failures) > MAX_TRACKED:
            for key in [k for k, times in self._failures.items() if now - times[-1] >= self.window]:
                del self._failures[key]
            # Still over: drop the oldest offenders rather than grow.
            excess = len(self._failures) - MAX_TRACKED
            if excess > 0:
                for key in sorted(self._failures, key=lambda k: self._failures[k][-1])[:excess]:
                    del self._failures[key]


Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def client_key(host: Optional[str]) -> str:
    return host or "unknown"


def parse_address(value: str) -> Optional[Address]:
    """An IP address from a peer name or a header entry.

    ``X-Forwarded-For`` entries are usually bare, but some proxies append a
    port (``192.0.2.1:443``, ``[2001:db8::1]:443``), so those are accepted
    too. Anything else is reported as unknown rather than guessed at.
    """
    text = value.strip()
    if not text:
        return None
    if text.startswith("["):  # bracketed IPv6, with or without a port
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1 and "." in text:  # 192.0.2.1:443
        text = text.rsplit(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    # ::ffff:192.0.2.1 and 192.0.2.1 are the same client, not two keys.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def parse_trusted_proxies(values: Iterable[str]) -> Tuple[Network, ...]:
    """Parse the configured proxy addresses (single hosts or CIDR ranges).

    Raises ValueError on a bad entry: silently ignoring a typo would leave the
    operator believing the throttle is per client while it is not.
    """
    networks: List[Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            raise ValueError(f"not an IP address or network: {value!r}") from None
    return tuple(networks)


def _is_trusted(address: Address, networks: Tuple[Network, ...]) -> bool:
    # Comparing an IPv4 address with an IPv6 network raises TypeError.
    return any(net.version == address.version and address in net for net in networks)


def client_address(
    peer: Optional[str],
    forwarded_for: Optional[str] = None,
    trusted_proxies: Tuple[Network, ...] = (),
) -> str:
    """The address to throttle for a request that arrived from *peer*.

    ``X-Forwarded-For`` is read only when the peer itself is a trusted proxy.
    Proxies append what they saw, so the right-most entry is the closest hop:
    walk left past hops that are themselves trusted proxies and stop at the
    first address that is not. A client cannot escape its lockout by sending
    its own header, because its entry lands left of the proxy's and the proxy
    address in turn is skipped.
    """
    origin = parse_address(peer or "")
    fallback = client_key(str(origin) if origin is not None else peer)
    if origin is None or not forwarded_for or not _is_trusted(origin, trusted_proxies):
        return fallback
    hops = [parse_address(part) for part in forwarded_for.split(",") if part.strip()]
    # A garbled chain cannot be trusted at all; the peer is what we know.
    if not hops or any(hop is None for hop in hops):
        return fallback
    for hop in reversed(hops):
        if not _is_trusted(hop, trusted_proxies):
            return str(hop)
    # Every hop is one of our own proxies: keep them, and everyone behind
    # them, on the shared peer key rather than inventing an identity.
    return fallback
