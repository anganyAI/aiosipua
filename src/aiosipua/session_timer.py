"""Session timers (RFC 4028) — dead-call detection without retransmission.

One :class:`SessionTimer` per dialog, in one of two roles:

- **refresher**: sends a bodyless UPDATE at half the negotiated interval,
  forever, until cancelled.
- **watchdog** (non-refresher): if no refresh arrives before
  ``interval - min(32, interval/3)`` (RFC 4028 §10), the session is
  declared dead and the *expire* callback sends the BYE.

Negotiation (Session-Expires / Min-SE, refresher param, 422 retry) lives
in the UAS/UAC integration points; this module owns header parsing and
the timer machinery.

Limitations, by design: a refresher whose UPDATEs go unanswered does not
detect the dead session itself (detection belongs to the watchdog side),
and a UAS never refreshes through re-INVITE — when the peer's Allow
lacks UPDATE, the UAS hands the refresher role to the peer instead.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from .incoming_call import IncomingCall

from .utils import format_addr

logger = logging.getLogger(__name__)

DEFAULT_SESSION_EXPIRES = 1800
DEFAULT_MIN_SE = 90  # RFC 4028 §4
REFRESH_FRACTION = 0.5


def parse_session_expires(raw: str) -> tuple[int, str | None]:
    """Parse a Session-Expires value: ``"1800;refresher=uac"`` → ``(1800, "uac")``.

    Returns ``(0, None)`` when the interval is unparseable.
    """
    parts = [p.strip() for p in raw.split(";")]
    try:
        interval = int(parts[0])
    except ValueError:
        return 0, None
    refresher: str | None = None
    for param in parts[1:]:
        if param.lower().startswith("refresher="):
            refresher = param.split("=", 1)[1].strip().lower()
    return interval, refresher


def watchdog_delay(interval: float) -> float:
    """Non-refresher deadline before declaring the session dead (RFC 4028 §10)."""
    return max(interval - min(32.0, interval / 3.0), 0.0)


def peer_allows_update(allow_values: list[str]) -> bool:
    """Whether an Allow list permits UPDATE; an absent Allow is assumed permissive."""
    if not allow_values:
        return True
    return "UPDATE" in (v.strip().upper() for v in allow_values)


class SessionTimer:
    """Per-dialog session keepalive: refresh loop or expiry watchdog."""

    def __init__(
        self,
        interval: int,
        *,
        we_refresh: bool,
        refresh: Callable[[], Any],
        expire: Callable[[], Any],
    ) -> None:
        self.interval = interval
        self.we_refresh = we_refresh
        self._refresh = refresh
        self._expire = expire
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Arm the timer for its role (idempotent: restarts from now)."""
        self.cancel()
        coro = self._refresh_loop() if self.we_refresh else self._watchdog()
        self._task = asyncio.get_running_loop().create_task(coro)

    def refreshed(self) -> None:
        """A refresh arrived — re-arm the watchdog (no-op for the refresher role)."""
        if not self.we_refresh and self._task is not None:
            self.start()

    def cancel(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval * REFRESH_FRACTION)
            self._refresh()

    async def _watchdog(self) -> None:
        await asyncio.sleep(watchdog_delay(self.interval))
        self._task = None
        logger.warning("Session expired without refresh (interval %ds)", self.interval)
        self._expire()


def send_session_refresh(call: IncomingCall) -> None:
    """Send the UAS-side refresh: a bodyless in-dialog UPDATE (RFC 4028 §7.4)."""
    if call.transport is None:
        return
    addr = call._signaling_addr()
    update = call.dialog.create_request("UPDATE", via_host=addr[0], via_port=addr[1])
    update.headers.set_single("Contact", f"<sip:{format_addr(*addr)}>")
    update.headers.set_single("Session-Expires", f"{call.session_interval};refresher=uas")
    call.transport.send(update, call.source_addr)
