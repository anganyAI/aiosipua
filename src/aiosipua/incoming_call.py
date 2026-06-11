"""High-level API for a single incoming SIP call (UAS side).

:class:`IncomingCall` wraps an INVITE and offers ``trying`` / ``ringing`` /
``accept`` / ``reject`` / ``hangup`` plus structured access to caller
metadata (X-headers, room/session ids).  Instances are created and
dispatched by :class:`aiosipua.uas.SipUAS`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import transaction as _timers
from .dialog import DialogState, _default_reason
from .sdp import serialize_sdp

if TYPE_CHECKING:
    from collections.abc import Callable

    from .dialog import Dialog
    from .message import SipRequest, SipResponse
    from .sdp import SdpMessage
    from .transport import SipTransport


@dataclass
class IncomingCall:
    """An incoming SIP call (INVITE transaction).

    Provides a high-level API for responding to the call: :meth:`trying`,
    :meth:`ringing`, :meth:`accept`, :meth:`reject`, and :meth:`hangup`.

    With ``retransmit_2xx`` enabled (the UAS turns it on for unreliable
    transports), :meth:`accept` keeps retransmitting the 200 OK until the
    ACK arrives (RFC 3261 §13.3.1.4); if no ACK shows up within 64×T1 the
    dialog is terminated and ``on_ack_timeout`` fires.
    """

    dialog: Dialog
    invite: SipRequest
    sdp_offer: SdpMessage | None = None
    transport: SipTransport | None = field(default=None, repr=False)
    source_addr: tuple[str, int] = ("0.0.0.0", 0)
    user_agent: str | None = field(default=None, repr=False)
    advertised_addr: tuple[str, int] | None = field(default=None, repr=False)
    retransmit_2xx: bool = field(default=False, repr=False)
    on_ack_timeout: Callable[[IncomingCall], Any] | None = field(default=None, repr=False)
    _answered: bool = field(default=False, init=False, repr=False)
    _retrans_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)

    @property
    def call_id(self) -> str:
        """The Call-ID of this call."""
        return self.dialog.call_id

    @property
    def caller(self) -> str:
        """The caller URI (From header)."""
        return self.dialog.remote_uri

    @property
    def callee(self) -> str:
        """The callee URI (To header / request URI)."""
        return self.dialog.local_uri

    @property
    def room_id(self) -> str | None:
        """Room ID from X-Room-ID header, if present."""
        return self.invite.get_header("x-room-id")

    @property
    def session_id(self) -> str | None:
        """Session ID from X-Session-ID header, if present."""
        return self.invite.get_header("x-session-id")

    @property
    def x_headers(self) -> dict[str, str]:
        """All X-* headers from the INVITE as a dict."""
        result: dict[str, str] = {}
        for name, values in self.invite.headers.items():
            if name.lower().startswith("x-") and values:
                result[name] = values[0]
        return result

    def trying(self) -> None:
        """Send a 100 Trying response."""
        self._send_response(100, "Trying")

    def ringing(self, *, early_sdp: SdpMessage | None = None) -> None:
        """Send a 180 Ringing response, optionally with early media SDP."""
        body = ""
        content_type = ""
        if early_sdp is not None:
            body = serialize_sdp(early_sdp)
            content_type = "application/sdp"
        self._send_response(180, "Ringing", body=body, content_type=content_type)

    def accept(self, sdp_answer: SdpMessage | None = None) -> None:
        """Send a 200 OK, accepting the call.

        Args:
            sdp_answer: The SDP answer to include in the response body.
                If ``None``, a 200 OK with no body is sent.
        """
        body = ""
        content_type = ""
        if sdp_answer is not None:
            body = serialize_sdp(sdp_answer)
            content_type = "application/sdp"
        resp = self._send_response(200, "OK", body=body, content_type=content_type)
        self.dialog.confirm()
        self._answered = True
        if self.retransmit_2xx and resp is not None:
            self._start_2xx_retransmission(resp)

    def reject(self, status_code: int = 486, reason: str = "") -> None:
        """Reject the call with an error response.

        Args:
            status_code: SIP error status code (default 486 Busy Here).
            reason: Reason phrase; auto-filled if empty.
        """
        if not reason:
            reason = _default_reason(status_code)
        self._send_response(status_code, reason)
        self.dialog.terminate()

    def _signaling_addr(self) -> tuple[str, int]:
        """Address to advertise in Via/Contact (advertised_addr, else bind address)."""
        if self.advertised_addr is not None:
            return self.advertised_addr
        if self.transport is not None:
            return self.transport.local_addr
        return ("0.0.0.0", 5060)

    def hangup(self) -> SipRequest | None:
        """Send a BYE to terminate an established call.

        Returns the BYE request that was sent, or ``None`` if the call
        was not in a confirmed state.
        """
        if self.dialog.state != DialogState.CONFIRMED:
            return None

        local_addr = self._signaling_addr()

        bye = self.dialog.create_request(
            "BYE",
            via_host=local_addr[0],
            via_port=local_addr[1],
        )

        self.dialog.terminate()

        if self.transport is not None:
            self.transport.send(bye, self.source_addr)

        return bye

    def _send_response(
        self,
        status_code: int,
        reason: str,
        *,
        body: str = "",
        content_type: str = "",
    ) -> SipResponse | None:
        """Build and send a response to the INVITE.

        Returns the response, or ``None`` if there is no transport to send it on.
        """
        contact: str | None = None
        if self.transport is not None:
            addr = self._signaling_addr()
            contact = f"<sip:{addr[0]}:{addr[1]}>"

        resp = self.dialog.create_response(
            self.invite,
            status_code,
            reason,
            contact=contact,
        )

        if body:
            resp.body = body
        if content_type:
            resp.headers.set_single("Content-Type", content_type)
        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)

        if self.transport is None:
            return None
        self.transport.send_reply(resp)
        return resp

    # --- 2xx retransmission (RFC 3261 §13.3.1.4) ---

    def _start_2xx_retransmission(self, response: SipResponse) -> None:
        """Retransmit *response* until the ACK arrives or 64×T1 elapses."""
        self._stop_2xx_retransmission()
        self._retrans_task = asyncio.get_running_loop().create_task(self._retransmit_2xx(response))

    def _stop_2xx_retransmission(self) -> None:
        """Stop retransmitting (ACK received or call torn down)."""
        if self._retrans_task is not None:
            self._retrans_task.cancel()
            self._retrans_task = None

    async def _retransmit_2xx(self, response: SipResponse) -> None:
        interval = _timers.T1
        elapsed = 0.0
        while elapsed < _timers.TIMER_H:
            await asyncio.sleep(interval)
            elapsed += interval
            if self.transport is not None:
                self.transport.send_reply(response)
            interval = min(interval * 2, _timers.T2)

        # No ACK within 64×T1 — the peer never confirmed the dialog
        self._retrans_task = None
        self.dialog.terminate()
        if self.on_ack_timeout is not None:
            self.on_ack_timeout(self)
