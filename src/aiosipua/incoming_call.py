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
    from .session_timer import SessionTimer
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
    # Session timers (RFC 4028): negotiated interval and refresher role
    session_interval: int | None = field(default=None, repr=False)
    session_refresher_us: bool = field(default=True, repr=False)
    on_ack_timeout: Callable[[IncomingCall], Any] | None = field(default=None, repr=False)
    on_prack_timeout: Callable[[IncomingCall], Any] | None = field(default=None, repr=False)
    # Our SDP answer, recorded by accept()
    sdp_answer: SdpMessage | None = field(default=None, init=False, repr=False)
    _answered: bool = field(default=False, init=False, repr=False)
    _retrans_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _reliable_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _rseq: int = field(default=0, init=False, repr=False)
    _pending_rseq: int | None = field(default=None, init=False, repr=False)
    _session_timer: SessionTimer | None = field(default=None, init=False, repr=False)

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

    def _caller_supports(self, token: str) -> bool:
        """Whether the caller advertised *token* in Supported/Require."""
        tokens = self.invite.headers.get("supported") + self.invite.headers.get("require")
        return token in (t.strip().lower() for t in tokens)

    @property
    def supports_100rel(self) -> bool:
        """Whether the caller advertised 100rel support (RFC 3262)."""
        return self._caller_supports("100rel")

    def ringing(self, *, early_sdp: SdpMessage | None = None, reliable: bool = False) -> None:
        """Send a 180 Ringing response, optionally with early media SDP.

        With ``reliable=True`` the 180 is sent reliably (RFC 3262): it
        carries ``RSeq`` + ``Require: 100rel`` and is retransmitted until
        the PRACK arrives; without a PRACK within 64×T1 the INVITE is
        rejected with 504 and ``on_prack_timeout`` fires.

        Raises:
            ValueError: If ``reliable=True`` but the caller did not
                advertise 100rel, or a reliable provisional is already
                awaiting its PRACK (RFC 3262 §3 forbids overlapping ones).
        """
        body = ""
        content_type = ""
        if early_sdp is not None:
            body = serialize_sdp(early_sdp)
            content_type = "application/sdp"

        if not reliable:
            self._send_response(180, "Ringing", body=body, content_type=content_type)
            return

        if not self.supports_100rel:
            raise ValueError("Caller did not advertise 100rel support")
        if self._reliable_task is not None:
            raise ValueError("A reliable provisional is already awaiting PRACK")

        self._rseq += 1
        resp = self._send_response(
            180,
            "Ringing",
            body=body,
            content_type=content_type,
            extra_headers={"RSeq": str(self._rseq), "Require": "100rel"},
        )
        if resp is not None:
            self._pending_rseq = self._rseq
            self._reliable_task = asyncio.get_running_loop().create_task(
                self._retransmit_loop(resp, self._on_prack_timeout)
            )

    def accept(self, sdp_answer: SdpMessage | None = None) -> None:
        """Send a 200 OK, accepting the call.

        Args:
            sdp_answer: The SDP answer to include in the response body.
                If ``None``, a 200 OK with no body is sent.

        Raises:
            ValueError: If a reliable provisional is still awaiting its
                PRACK (RFC 3262 §3 forbids the 2xx until then).
        """
        if self._reliable_task is not None:
            raise ValueError("Cannot accept: reliable provisional awaiting PRACK")

        body = ""
        content_type = ""
        if sdp_answer is not None:
            body = serialize_sdp(sdp_answer)
            content_type = "application/sdp"

        extra: dict[str, str] = {}
        if self.session_interval:
            refresher = "uas" if self.session_refresher_us else "uac"
            extra["Session-Expires"] = f"{self.session_interval};refresher={refresher}"
            if self._caller_supports("timer"):
                extra["Require"] = "timer"

        resp = self._send_response(
            200, "OK", body=body, content_type=content_type, extra_headers=extra or None
        )
        self.sdp_answer = sdp_answer
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
        extra_headers: dict[str, str] | None = None,
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
        if extra_headers:
            for name, value in extra_headers.items():
                resp.headers.set_single(name, value)

        if self.transport is None:
            return None
        self.transport.send_reply(resp)
        return resp

    # --- Response retransmission (RFC 3261 §13.3.1.4, RFC 3262 §3) ---

    async def _retransmit_loop(
        self, response: SipResponse, on_timeout: Callable[[], None]
    ) -> None:
        """Retransmit *response* with T1-doubling until cancelled or 64×T1 elapses."""
        interval = _timers.T1
        elapsed = 0.0
        while elapsed < _timers.TIMER_H:
            await asyncio.sleep(interval)
            elapsed += interval
            if self.transport is not None:
                self.transport.send_reply(response)
            interval = min(interval * 2, _timers.T2)
        on_timeout()

    def _start_2xx_retransmission(self, response: SipResponse) -> None:
        """Retransmit the 2xx until the ACK arrives or 64×T1 elapses."""
        self._stop_2xx_retransmission()
        self._retrans_task = asyncio.get_running_loop().create_task(
            self._retransmit_loop(response, self._on_ack_timeout)
        )

    def _on_ack_timeout(self) -> None:
        # No ACK within 64×T1 — the peer never confirmed the dialog
        self._retrans_task = None
        self.dialog.terminate()
        if self.on_ack_timeout is not None:
            self.on_ack_timeout(self)

    def _on_prack_timeout(self) -> None:
        # No PRACK within 64×T1 — reject the INVITE (RFC 3262 §3)
        self._reliable_task = None
        self._pending_rseq = None
        self.reject(504, "Server Time-out")
        if self.on_prack_timeout is not None:
            self.on_prack_timeout(self)

    def _ack_reliable(self, rack: str) -> bool:
        """Match a PRACK's RAck against the pending reliable provisional."""
        parts = rack.split()
        try:
            rseq = int(parts[0]) if parts else -1
        except ValueError:
            return False
        if self._pending_rseq is None or rseq != self._pending_rseq:
            return False
        self._pending_rseq = None
        self._stop_reliable_retransmission()
        return True

    def _stop_2xx_retransmission(self) -> None:
        """Stop retransmitting the 2xx (ACK received or call torn down)."""
        if self._retrans_task is not None:
            self._retrans_task.cancel()
            self._retrans_task = None

    def _stop_reliable_retransmission(self) -> None:
        """Stop retransmitting the reliable provisional (PRACK received)."""
        if self._reliable_task is not None:
            self._reliable_task.cancel()
            self._reliable_task = None

    def _stop_retransmissions(self) -> None:
        """Stop every pending retransmission and timer (call torn down)."""
        self._stop_2xx_retransmission()
        self._stop_reliable_retransmission()
        if self._session_timer is not None:
            self._session_timer.cancel()
            self._session_timer = None
