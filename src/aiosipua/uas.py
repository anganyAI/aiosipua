"""SIP User Agent Server (UAS) — handles incoming calls.

Provides :class:`SipUAS`, which listens on a :class:`SipTransport` and
dispatches incoming requests through callbacks.  INVITE requests are wrapped
in :class:`IncomingCall` objects that offer a high-level API for accepting,
rejecting, and hanging up calls.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .dialog import Dialog, DialogState, _default_reason, create_dialog_from_request
from .message import SipRequest, SipResponse
from .sdp import SdpMessage, parse_sdp, serialize_sdp
from .transaction import TransactionLayer
from .utils import generate_tag

if TYPE_CHECKING:
    from .transport import SipTransport

logger = logging.getLogger(__name__)

# Callback types
InviteCallback = Callable[["IncomingCall"], Any]
ByeCallback = Callable[["IncomingCall", SipRequest], Any]
RequestCallback = Callable[[SipRequest, "tuple[str, int]"], Any]


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

    def hangup(self) -> SipRequest | None:
        """Send a BYE to terminate an established call.

        Returns the BYE request that was sent, or ``None`` if the call
        was not in a confirmed state.
        """
        if self.dialog.state != DialogState.CONFIRMED:
            return None

        local_addr = ("0.0.0.0", 5060)
        if self.transport is not None:
            local_addr = self.transport.local_addr

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
            addr = self.transport.local_addr
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

        if self.transport is not None:
            self.transport.send_reply(resp)


class SipUAS:
    """SIP User Agent Server — listens for incoming requests.

    Dispatches INVITE, BYE, CANCEL, re-INVITE, and OPTIONS requests
    through registered callbacks.  Automatically sends 100 Trying for
    new INVITEs.

    Usage::

        uas = SipUAS(transport)
        uas.on_invite = my_invite_handler
        uas.on_bye = my_bye_handler
        await uas.start()
    """

    def __init__(self, transport: SipTransport) -> None:
        self.transport = transport
        self.transactions = TransactionLayer()

        # Callbacks
        self.on_invite: InviteCallback | None = None
        self.on_bye: ByeCallback | None = None
        self.on_reinvite: InviteCallback | None = None
        self.on_cancel: RequestCallback | None = None
        self.on_options: RequestCallback | None = None

        # Active calls keyed by call-id
        self._calls: dict[str, IncomingCall] = {}

    @property
    def active_calls(self) -> dict[str, IncomingCall]:
        """Active calls keyed by Call-ID (read-only copy)."""
        return dict(self._calls)

    def get_call(self, call_id: str) -> IncomingCall | None:
        """Look up an active call by Call-ID."""
        return self._calls.get(call_id)

    def get_dialog(self, call_id: str) -> Dialog | None:
        """Look up the dialog for an active call by Call-ID."""
        call = self._calls.get(call_id)
        return call.dialog if call else None

    async def start(self) -> None:
        """Start the UAS by binding the transport and registering the message handler."""
        self.transport.on_message = self._on_message
        await self.transport.start()

    async def stop(self) -> None:
        """Stop the UAS and close the transport."""
        await self.transport.stop()

    def _on_message(self, msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        """Internal message handler dispatched by the transport."""
        if isinstance(msg, SipRequest):
            self._handle_request(msg, addr)
        # Responses are not handled by a UAS

    def _handle_request(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Route an incoming request to the appropriate handler."""
        method = request.method.upper()

        if method == "INVITE":
            self._handle_invite(request, addr)
        elif method == "ACK":
            self._handle_ack(request, addr)
        elif method == "BYE":
            self._handle_bye(request, addr)
        elif method == "CANCEL":
            self._handle_cancel(request, addr)
        elif method == "OPTIONS":
            self._handle_options(request, addr)
        else:
            # Unsupported method — 405
            self._send_error(request, 405, "Method Not Allowed")

    def _handle_invite(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming INVITE (new call or re-INVITE)."""
        call_id = request.call_id or ""

        # Check for re-INVITE (existing dialog)
        existing = self._calls.get(call_id)
        if existing and existing.dialog.state == DialogState.CONFIRMED:
            # re-INVITE
            existing.invite = request
            # Re-parse SDP if present
            if request.body and request.content_type == "application/sdp":
                existing.sdp_offer = parse_sdp(request.body)
            if self.on_reinvite is not None:
                self.on_reinvite(existing)
            return

        # New INVITE — create dialog
        dialog = create_dialog_from_request(request)

        # Parse SDP offer from body
        sdp_offer: SdpMessage | None = None
        if request.body and request.content_type == "application/sdp":
            sdp_offer = parse_sdp(request.body)

        call = IncomingCall(
            dialog=dialog,
            invite=request,
            sdp_offer=sdp_offer,
            transport=self.transport,
            source_addr=addr,
        )

        self._calls[call_id] = call

        # Auto-send 100 Trying
        call.trying()

        # Dispatch to callback
        if self.on_invite is not None:
            self.on_invite(call)

    def _handle_ack(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming ACK (confirms a 2xx response)."""
        call_id = request.call_id or ""
        call = self._calls.get(call_id)
        if call is not None:
            # ACK confirms the dialog
            call.dialog.confirm()

    def _handle_bye(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming BYE (terminates a call)."""
        call_id = request.call_id or ""
        call = self._calls.get(call_id)

        if call is None:
            # No matching dialog — 481
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return

        # Send 200 OK for BYE
        resp = call.dialog.create_response(request, 200, "OK")
        self.transport.send_reply(resp)

        # Terminate dialog and remove call
        call.dialog.terminate()
        self._calls.pop(call_id, None)

        # Dispatch callback
        if self.on_bye is not None:
            self.on_bye(call, request)

    def _handle_cancel(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming CANCEL (cancels a pending INVITE)."""
        call_id = request.call_id or ""
        call = self._calls.get(call_id)

        if call is None:
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return

        # Send 200 OK for the CANCEL itself
        resp = call.dialog.create_response(request, 200, "OK")
        self.transport.send_reply(resp)

        # Send 487 Request Terminated for the original INVITE
        if not call._answered:
            call.reject(487, "Request Terminated")

        self._calls.pop(call_id, None)

        if self.on_cancel is not None:
            self.on_cancel(request, addr)

    def _handle_options(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming OPTIONS (capability query)."""
        if self.on_options is not None:
            self.on_options(request, addr)
            return

        # Default: reply 200 OK with Allow header
        call_id = request.call_id or ""
        local_tag = generate_tag()

        resp = SipResponse(status_code=200, reason_phrase="OK")

        # Copy Via
        for v in request.headers.get("via"):
            resp.headers.append("Via", v)

        # From — copy
        from_val = request.headers.get_first("from")
        if from_val:
            resp.headers.set_single("From", from_val)

        # To — copy and add tag
        to_val = request.headers.get_first("to")
        if to_val:
            resp.headers.set_single("To", f"{to_val};tag={local_tag}")

        resp.headers.set_single("Call-ID", call_id)

        cseq = request.headers.get_first("cseq")
        if cseq:
            resp.headers.set_single("CSeq", cseq)

        resp.headers.set_single("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS")

        self.transport.send_reply(resp)

    def _send_error(self, request: SipRequest, status_code: int, reason: str) -> None:
        """Send an error response for a request with no dialog context."""
        resp = SipResponse(status_code=status_code, reason_phrase=reason)

        for v in request.headers.get("via"):
            resp.headers.append("Via", v)

        from_val = request.headers.get_first("from")
        if from_val:
            resp.headers.set_single("From", from_val)

        to_val = request.headers.get_first("to")
        if to_val:
            local_tag = generate_tag()
            resp.headers.set_single("To", f"{to_val};tag={local_tag}")

        call_id = request.call_id
        if call_id:
            resp.headers.set_single("Call-ID", call_id)

        cseq = request.headers.get_first("cseq")
        if cseq:
            resp.headers.set_single("CSeq", cseq)

        self.transport.send_reply(resp)
