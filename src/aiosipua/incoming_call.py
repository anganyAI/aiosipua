"""High-level API for a single incoming SIP call (UAS side).

:class:`IncomingCall` wraps an INVITE and offers ``trying`` / ``ringing`` /
``accept`` / ``reject`` / ``hangup`` plus structured access to caller
metadata (X-headers, room/session ids).  Instances are created and
dispatched by :class:`aiosipua.uas.SipUAS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .dialog import DialogState, _default_reason
from .sdp import serialize_sdp

if TYPE_CHECKING:
    from .dialog import Dialog
    from .message import SipRequest
    from .sdp import SdpMessage
    from .transport import SipTransport


@dataclass
class IncomingCall:
    """An incoming SIP call (INVITE transaction).

    Provides a high-level API for responding to the call: :meth:`trying`,
    :meth:`ringing`, :meth:`accept`, :meth:`reject`, and :meth:`hangup`.
    """

    dialog: Dialog
    invite: SipRequest
    sdp_offer: SdpMessage | None = None
    transport: SipTransport | None = field(default=None, repr=False)
    source_addr: tuple[str, int] = ("0.0.0.0", 0)
    user_agent: str | None = field(default=None, repr=False)
    advertised_addr: tuple[str, int] | None = field(default=None, repr=False)
    _answered: bool = field(default=False, init=False, repr=False)

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
        self._send_response(200, "OK", body=body, content_type=content_type)
        self.dialog.confirm()
        self._answered = True

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
    ) -> None:
        """Build and send a response to the INVITE."""
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

        if self.transport is not None:
            self.transport.send_reply(resp)
