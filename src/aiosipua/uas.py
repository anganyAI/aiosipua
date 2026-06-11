"""SIP User Agent Server (UAS) — handles incoming calls.

Provides :class:`SipUAS`, which listens on a :class:`SipTransport` and
dispatches incoming requests through callbacks.  INVITE requests are wrapped
in :class:`IncomingCall` objects that offer a high-level API for accepting,
rejecting, and hanging up calls.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .dialog import Dialog, DialogState, create_dialog_from_request
from .incoming_call import IncomingCall
from .message import SipRequest, SipResponse
from .sdp import SdpMessage, parse_sdp
from .transaction import TransactionLayer, TransactionState
from .utils import generate_tag

if TYPE_CHECKING:
    from .transport import SipTransport
    from .uac import SipUAC

logger = logging.getLogger(__name__)

# Callback types
InviteCallback = Callable[["IncomingCall"], Any]
ByeCallback = Callable[["IncomingCall", SipRequest], Any]
RequestCallback = Callable[[SipRequest, "tuple[str, int]"], Any]


def _dialog_matches(dialog: Dialog, request: SipRequest) -> bool:
    """Check an in-dialog request's tags against the dialog (RFC 3261 §12.2.2).

    A request claiming an existing Call-ID but carrying the wrong From/To
    tags does not belong to the dialog and must be answered with 481.
    """
    from_addr = request.from_addr
    to_addr = request.to_addr
    from_tag = (from_addr.tag if from_addr else None) or ""
    to_tag = (to_addr.tag if to_addr else None) or ""
    return from_tag == dialog.remote_tag and to_tag == dialog.local_tag


def _remote_cseq_valid(dialog: Dialog, request: SipRequest) -> bool:
    """Validate and record the remote CSeq (RFC 3261 §12.2.2).

    In-dialog requests must carry a CSeq strictly higher than the last one
    seen; on success the dialog's ``remote_cseq`` is updated.
    """
    cseq = request.cseq
    if cseq is None:
        return False
    if dialog.remote_cseq and cseq.seq <= dialog.remote_cseq:
        return False
    dialog.remote_cseq = cseq.seq
    return True


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

    def __init__(
        self,
        transport: SipTransport,
        *,
        user_agent: str | None = None,
        uac: SipUAC | None = None,
        advertised_addr: tuple[str, int] | None = None,
        retransmit_2xx: bool | None = None,
    ) -> None:
        self.transport = transport
        self.transactions = TransactionLayer()
        self.user_agent = user_agent
        self.uac: SipUAC | None = uac
        # Address advertised in Via/Contact (NAT: bind on private, signal public)
        self.advertised_addr = advertised_addr
        # 2xx retransmission until ACK (RFC 3261 §13.3.1.4) — defaults to the
        # transport's reliability: on for UDP, off for TCP
        if retransmit_2xx is None:
            retransmit_2xx = not getattr(transport, "reliable", True)
        self.retransmit_2xx = retransmit_2xx

        # Callbacks
        self.on_invite: InviteCallback | None = None
        self.on_bye: ByeCallback | None = None
        self.on_reinvite: InviteCallback | None = None
        self.on_cancel: RequestCallback | None = None
        self.on_options: RequestCallback | None = None
        self.on_ack_timeout: InviteCallback | None = None

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
        """Stop the UAS: cancel pending 2xx retransmissions and close the transport."""
        for call in self._calls.values():
            call._stop_2xx_retransmission()
        await self.transport.stop()

    def _on_message(self, msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        """Internal message handler dispatched by the transport."""
        if isinstance(msg, SipRequest):
            self._handle_request(msg, addr)
        elif isinstance(msg, SipResponse) and self.uac is not None:
            self.uac.handle_response(msg, addr)

    def _validate_in_dialog(self, dialog: Dialog, request: SipRequest) -> bool:
        """Tag and CSeq checks for an in-dialog request (RFC 3261 §12.2.2).

        Sends 481 on a tag mismatch, 500 on a non-increasing CSeq.
        """
        if not _dialog_matches(dialog, request):
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return False
        if not _remote_cseq_valid(dialog, request):
            self._send_error(request, 500, "Server Internal Error")
            return False
        return True

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

        # Check for re-INVITE (existing dialog in UAS)
        existing = self._calls.get(call_id)
        if existing and existing.dialog.state == DialogState.CONFIRMED:
            if not self._validate_in_dialog(existing.dialog, request):
                return
            # re-INVITE
            existing.invite = request
            # Re-parse SDP if present
            if request.body and request.content_type == "application/sdp":
                existing.sdp_offer = parse_sdp(request.body)
            if self.on_reinvite is not None:
                self.on_reinvite(existing)
            return

        # Check for re-INVITE on an outbound call (dialog lives in UAC)
        if self.uac is not None and call_id in self.uac._calls:
            uac_dialog = self.uac._calls[call_id].dialog
            if not self._validate_in_dialog(uac_dialog, request):
                return
            # Build an IncomingCall wrapper so the re-INVITE handler can
            # send responses (accept/reject) through the same interface.
            dialog = create_dialog_from_request(request)
            dialog.confirm()  # outbound dialog is already confirmed
            sdp_offer: SdpMessage | None = None
            if request.body and request.content_type == "application/sdp":
                sdp_offer = parse_sdp(request.body)
            wrapper = IncomingCall(
                dialog=dialog,
                invite=request,
                sdp_offer=sdp_offer,
                transport=self.transport,
                source_addr=addr,
                user_agent=self.user_agent,
                advertised_addr=self.advertised_addr,
            )
            wrapper._answered = True  # prevent reject(487) on CANCEL
            if self.on_reinvite is not None:
                self.on_reinvite(wrapper)
            return

        # New INVITE — create dialog
        dialog = create_dialog_from_request(request)

        # Track the INVITE server transaction so CANCEL can match by branch.
        # PROCEEDING (we auto-send 100 Trying below) keeps it out of the
        # transaction layer's lazy expiry while the call is ringing.
        try:
            txn = self.transactions.create_server(request)
        except ValueError:
            logger.warning("INVITE without Via branch from %s — CANCEL matching disabled", addr)
        else:
            txn.state = TransactionState.PROCEEDING

        # Parse SDP offer from body
        sdp_offer = None
        if request.body and request.content_type == "application/sdp":
            sdp_offer = parse_sdp(request.body)

        call = IncomingCall(
            dialog=dialog,
            invite=request,
            sdp_offer=sdp_offer,
            transport=self.transport,
            source_addr=addr,
            user_agent=self.user_agent,
            advertised_addr=self.advertised_addr,
            retransmit_2xx=self.retransmit_2xx,
            on_ack_timeout=self._dispatch_ack_timeout,
        )

        self._calls[call_id] = call

        # Auto-send 100 Trying
        call.trying()

        # Dispatch to callback
        if self.on_invite is not None:
            self.on_invite(call)

    def _handle_ack(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming ACK (confirms a 2xx, or closes a rejected INVITE)."""
        call_id = request.call_id or ""
        call = self._calls.get(call_id)
        if call is None or not _dialog_matches(call.dialog, request):
            return

        call._stop_2xx_retransmission()
        if call.dialog.state == DialogState.TERMINATED:
            # ACK to our error response — the INVITE transaction is over
            self._calls.pop(call_id, None)
        else:
            call.dialog.confirm()
        self._remove_invite_transaction(call.invite)

    def _dispatch_ack_timeout(self, call: IncomingCall) -> None:
        """A 2xx was never ACKed — release the call (RFC 3261 §13.3.1.4)."""
        self._calls.pop(call.call_id, None)
        self._remove_invite_transaction(call.invite)
        logger.warning("No ACK for 2xx on %s — call released", call.call_id)
        if self.on_ack_timeout is not None:
            self.on_ack_timeout(call)

    def _handle_bye(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming BYE (terminates a call)."""
        call_id = request.call_id or ""
        call = self._calls.get(call_id)

        if call is not None:
            if not self._validate_in_dialog(call.dialog, request):
                return
            call._stop_2xx_retransmission()
            self._remove_invite_transaction(call.invite)

        # Check UAC's calls for outbound dialogs
        if call is None and self.uac is not None and call_id in self.uac._calls:
            uac_dialog = self.uac._calls[call_id].dialog
            if not self._validate_in_dialog(uac_dialog, request):
                return
            # Build a wrapper so on_bye callback has the same interface
            dialog = create_dialog_from_request(request)
            dialog.confirm()
            call = IncomingCall(
                dialog=dialog,
                invite=request,
                transport=self.transport,
                source_addr=addr,
                user_agent=self.user_agent,
                advertised_addr=self.advertised_addr,
            )
            call._answered = True
            # Remove from UAC tracking
            self.uac._calls.pop(call_id, None)

        if call is None:
            # No matching dialog — 481
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return

        # Send 200 OK for BYE
        resp = call.dialog.create_response(request, 200, "OK")
        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)
        self.transport.send_reply(resp)

        # Terminate dialog and remove call
        call.dialog.terminate()
        self._calls.pop(call_id, None)

        # Dispatch callback
        if self.on_bye is not None:
            self.on_bye(call, request)

    def _handle_cancel(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Handle an incoming CANCEL (cancels a pending INVITE).

        Matched against the INVITE server transaction by Via branch
        (RFC 3261 §9.2), not by Call-ID.
        """
        vias = request.via
        branch = vias[0].branch if vias else None
        txn = self.transactions.get_server(branch, "INVITE") if branch else None

        call: IncomingCall | None = None
        if txn is not None and txn.request is not None:
            call = self._calls.get(txn.request.call_id or "")

        if call is None:
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return

        # Send 200 OK for the CANCEL itself
        resp = call.dialog.create_response(request, 200, "OK")
        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)
        self.transport.send_reply(resp)

        # Send 487 Request Terminated for the original INVITE
        if not call._answered:
            call.reject(487, "Request Terminated")

        call._stop_2xx_retransmission()
        self._calls.pop(call.call_id, None)
        if txn is not None:
            self.transactions.remove(txn)

        if self.on_cancel is not None:
            self.on_cancel(request, addr)

    def _remove_invite_transaction(self, invite: SipRequest) -> None:
        """Drop the server transaction tracked for *invite*, if any."""
        vias = invite.via
        branch = vias[0].branch if vias else None
        if not branch:
            return
        txn = self.transactions.get_server(branch, "INVITE")
        if txn is not None:
            self.transactions.remove(txn)

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
        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)

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

        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)

        self.transport.send_reply(resp)
