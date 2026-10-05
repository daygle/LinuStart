"""Reboot and power-off control: schedule, inspect and cancel a pending action.

Powering a machine off ends this process too, so the action is never run
directly. Instead it is handed to ``systemd-run`` as a one-shot timer; the
panel survives long enough to answer the request, and the operator keeps a
window in which the action can still be cancelled. This mirrors the way the
self-updater defers its own service restart.

Pure helpers validate input and build argv so they can be tested without a
systemd system; the async helpers do the talking to systemd.
"""

from __future__ import annotations

from typing import Dict, List

from ..util import run

ACTIONS = ("reboot", "shutdown")

# systemd's own verbs for each action in the allowlist above.
SYSTEMCTL_VERB = {"reboot": "reboot", "shutdown": "poweroff"}

# A short delay by default: just enough for the HTTP response to reach the
# browser before the machine goes away.
DEFAULT_DELAY = 5
MIN_DELAY = 0
MAX_DELAY = 3600

# Countdowns offered by the UI.
POWER_DELAYS = (5, 30, 60, 300)

# Transient units are namespaced so they cannot collide with anything else.
UNIT_PREFIX = "linustart-power"


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def normalize_action(action: str) -> str:
    """Validate an action name and return it in canonical form."""
    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise ValueError(f"action must be one of: {', '.join(ACTIONS)}")
    return action


def normalize_delay(delay: object) -> int:
    """Coerce a countdown to whole seconds inside the allowed range.

    Accepts an int or a numeric string (JSON clients send both). Booleans are
    rejected explicitly: ``True`` is an int in Python, and silently treating
    it as 1 second would be a nasty surprise.
    """
    if delay is None:
        return DEFAULT_DELAY
    if isinstance(delay, bool):
        raise ValueError("delay must be a number of seconds")
    if isinstance(delay, int):
        seconds = delay
    elif isinstance(delay, str):
        text = delay.strip()
        if not text:
            return DEFAULT_DELAY
        try:
            seconds = int(text)
        except ValueError:
            raise ValueError("delay must be a whole number of seconds") from None
    else:
        raise ValueError("delay must be a whole number of seconds")
    if seconds < MIN_DELAY or seconds > MAX_DELAY:
        raise ValueError(f"delay must be between {MIN_DELAY} and {MAX_DELAY} seconds")
    return seconds


def unit_name(action: str) -> str:
    """Transient unit name backing *action*, without the ``.timer`` suffix."""
    return f"{UNIT_PREFIX}-{normalize_action(action)}"


def timer_unit(action: str) -> str:
    return f"{unit_name(action)}.timer"


def describe_delay(seconds: int) -> str:
    """Human wording for a countdown, used in job descriptions and toasts."""
    if seconds <= 0:
        return "immediately"
    if seconds < 60:
        return f"in {seconds}s"
    if seconds % 60 == 0:
        return f"in {seconds // 60}m"
    return f"in {seconds // 60}m {seconds % 60}s"


def action_argv(action: str, delay: object = DEFAULT_DELAY) -> List[str]:
    """Build the ``systemd-run`` command that schedules *action*.

    The timer runs ``systemctl <verb>`` once, after ``--on-active`` seconds.
    ``systemd-run`` returns immediately, so the panel keeps serving.
    """
    action = normalize_action(action)
    seconds = normalize_delay(delay)
    verb = SYSTEMCTL_VERB[action]
    return [
        "systemd-run",
        f"--on-active={seconds}",
        f"--unit={unit_name(action)}",
        f"--description=LinuStart scheduled {action}",
        "systemctl",
        verb,
    ]


def cancel_argv(action: str) -> List[str]:
    """Build the command that stops a pending *action* timer."""
    return ["systemctl", "stop", timer_unit(action)]


def parse_show(text: str) -> Dict[str, str]:
    """Parse ``systemctl show`` key=value output."""
    props: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key] = value
    return props


def parse_timer(text: str) -> Dict[str, object]:
    """Summarise a timer unit's state.

    ``ActiveState`` of ``active`` with a set ``NextElapseUSecRealtime`` means
    the timer is loaded and armed; anything else means there is nothing
    pending to cancel.
    """
    props = parse_show(text)
    active = props.get("ActiveState", "")
    next_elapse = props.get("NextElapseUSecRealtime", "").strip()
    armed = active == "active" and next_elapse not in ("", "n/a")
    return {"armed": armed, "active_state": active, "next_elapse": next_elapse}


# --------------------------------------------------------------------------
# Async operations
# --------------------------------------------------------------------------

async def timer_state(action: str) -> Dict[str, object]:
    """Inspect the timer backing *action*; missing unit means 'not pending'."""
    unit = timer_unit(action)
    result = await run(["systemctl", "show", unit, "--no-pager"])
    if not result.ok:
        # An unknown unit is the normal case when nothing is scheduled.
        return {"armed": False, "active_state": "", "next_elapse": ""}
    return parse_timer(result.stdout)


async def status() -> Dict[str, object]:
    """Report whether a reboot or shutdown is currently pending."""
    pending: List[Dict[str, object]] = []
    for action in ACTIONS:
        state = await timer_state(action)
        if state["armed"]:
            pending.append(
                {
                    "action": action,
                    "unit": timer_unit(action),
                    "next_elapse": state["next_elapse"],
                }
            )
    return {
        "pending": bool(pending),
        "actions": pending,
        "action": pending[0]["action"] if pending else None,
        "unit": pending[0]["unit"] if pending else None,
        "delays": list(POWER_DELAYS),
        "default_delay": DEFAULT_DELAY,
    }


async def schedule(action: str, delay: object = DEFAULT_DELAY) -> Dict[str, object]:
    """Arm a one-shot timer that reboots or powers off the machine.

    Any timer already armed for the same action is stopped first, so
    repeatedly pressing the button cannot stack up timers or reset the
    countdown unexpectedly. A timer armed for the *other* action is left
    alone: cancelling that one stays the operator's explicit choice.
    """
    action = normalize_action(action)
    seconds = normalize_delay(delay)
    await run(cancel_argv(action))
    result = await run(action_argv(action, seconds))
    if not result.ok:
        raise RuntimeError(
            f"could not schedule {action}: {(result.stderr or result.stdout).strip()}"
        )
    return {
        "ok": True,
        "action": action,
        "delay": seconds,
        "when": describe_delay(seconds),
        "unit": timer_unit(action),
    }


async def cancel(action: str) -> Dict[str, object]:
    """Stop a pending *action* timer. A no-op when nothing is armed."""
    action = normalize_action(action)
    state = await timer_state(action)
    if not state["armed"]:
        return {"ok": True, "action": action, "cancelled": False}
    result = await run(cancel_argv(action))
    if not result.ok:
        raise RuntimeError(
            f"could not cancel {action}: {(result.stderr or result.stdout).strip()}"
        )
    return {"ok": True, "action": action, "cancelled": True}
