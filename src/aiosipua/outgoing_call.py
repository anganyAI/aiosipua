"""High-level API for a single outgoing SIP call (UAC side).

:class:`OutgoingCall` wraps an outbound INVITE and offers
``wait_answered`` / ``cancel`` / ``hangup`` plus the negotiated SDP answer
and ringing/answer/rejection callbacks.  Instances are created by
:meth:`aiosipua.uac.SipUAC.send_invite`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .dialog import DialogState

if TYPE_CHECKING:
    from collections.abc import Callable

    from .auth import SipDigestAuth
    from .dialog import Dialog
    from .message import SipRequest
    from .sdp import SdpMessage
    from .transport import SipTransport
    from .uac import SipUAC


@dataclass
class OutgoingCall:
    """An outgoing SIP call (INVITE transaction).

    Provides a high-level API for waiting on the call outcome and
    terminating the call: :meth:`wait_answered`, :meth:`cancel`,
    :meth:`hangup`.
    """

    dialog: Dialog
    invite: SipRequest
    sdp_offer: SdpMessage | None = None
    transport: SipTransport | None = field(default=None, repr=False)
    remote_addr: tuple[str, int] = ("0.0.0.0", 0)
    user_agent: str | None = field(default=None, repr=False)

    # Populated on 200 OK
    sdp_answer: SdpMessage | None = field(default=None, init=False)

    # Async signaling
    _answered: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
    _rejected: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
    _reject_code: int = field(default=0, init=False, repr=False)
    _reject_reason: str = field(default="", init=False, repr=False)

    # Digest auth (optional)
    _auth: SipDigestAuth | None = field(default=None, init=False, repr=False)
    _auth_attempts: int = field(default=0, init=False, repr=False)

    # Highest RSeq already acknowledged with a PRACK (RFC 3262)
    _last_pracked_rseq: int = field(default=0, init=False, repr=False)

    # Callbacks (optional)
    on_ringing: Callable[[OutgoingCall], Any] | None = field(default=None, repr=False)
    on_answer: Callable[[OutgoingCall], Any] | None = field(default=None, repr=False)
    on_rejected: Callable[[OutgoingCall, int, str], Any] | None = field(default=None, repr=False)

    @property
    def call_id(self) -> str:
        """The Call-ID of this call."""
        return self.dialog.call_id

    @property
    def caller(self) -> str:
        """The caller URI (From header = local)."""
        return self.dialog.local_uri

    @property
    def callee(self) -> str:
        """The callee URI (To header = remote)."""
        return self.dialog.remote_uri

    async def wait_answered(self, timeout: float = 30.0) -> None:
        """Wait for the call to be answered or rejected.

        Args:
            timeout: Maximum seconds to wait.

        Raises:
            TimeoutError: If neither answered nor rejected within *timeout*.
            RuntimeError: If the call was rejected (includes status code and reason).
        """
        answered = asyncio.create_task(self._answered.wait())
        rejected = asyncio.create_task(self._rejected.wait())
        try:
            done, pending = await asyncio.wait(
                {answered, rejected},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if not done:
                raise TimeoutError(f"No response within {timeout}s")
            if self._rejected.is_set():
                raise RuntimeError(f"Call rejected: {self._reject_code} {self._reject_reason}")
        finally:
            answered.cancel()
            rejected.cancel()

    def cancel(self, uac: SipUAC) -> SipRequest | None:
        """Cancel the outgoing call (sends CANCEL if dialog is EARLY).

        Returns the CANCEL request, or ``None`` if not in EARLY state.
        """
        if self.dialog.state != DialogState.EARLY:
            return None
        return uac.send_cancel(self)

    def hangup(self, uac: SipUAC) -> SipRequest | None:
        """Hang up the call (sends BYE if dialog is CONFIRMED).

        Returns the BYE request, or ``None`` if not in CONFIRMED state.
        """
        if self.dialog.state != DialogState.CONFIRMED:
            return None
        return uac.send_bye(self.dialog, self.remote_addr)
