"""SIP User Agent Server (UAS) — handles incoming calls.

Provides :class:`SipUAS`, which listens on a :class:`SipTransport` and
dispatches incoming requests through callbacks.  INVITE requests are wrapped
in :class:`IncomingCall` objects that offer a high-level API for accepting,
rejecting, and hanging up calls.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING, Any

from .dialog import (
    Dialog,
    DialogState,
    create_dialog_from_request,
    dialog_matches,
    remote_cseq_valid,
)
from .incoming_call import IncomingCall
from .message import SipRequest, SipResponse
from .refer import handle_notify, handle_refer
from .sdp import SdpMessage, parse_sdp
from .session_timer import (
    DEFAULT_MIN_SE,
    SessionTimer,
    parse_session_expires,
    peer_allows_update,
    send_session_refresh,
)
from .transaction import TransactionLayer, TransactionState
from .uas_requests import (
    handle_ack,
    handle_bye,
    handle_cancel,
    handle_prack,
    handle_update,
    session_refreshed,
)
from .utils import generate_tag

if TYPE_CHECKING:
    from .transport import SipTransport
    from .uac import SipUAC

logger = logging.getLogger(__name__)

# Callback types
InviteCallback = Callable[["IncomingCall"], Any]
ByeCallback = Callable[["IncomingCall", SipRequest], Any]
RequestCallback = Callable[[SipRequest, "tuple[str, int]"], Any]
# UPDATE handler: returns the SDP answer when the UPDATE carries an offer
UpdateCallback = Callable[["IncomingCall", SipRequest], "SdpMessage | None"]
# REFER handler: (call, refer-to URI)
ReferCallback = Callable[["IncomingCall", str], Any]
# Transfer progress: (call_id, sipfrag status, reason)
TransferProgressCallback = Callable[[str, int, str], Any]


class SipUAS:
    """SIP User Agent Server — listens for incoming requests.

    Dispatches INVITE (new call and re-INVITE), ACK, PRACK, BYE, CANCEL,
    OPTIONS, UPDATE, REFER, and NOTIFY through registered callbacks, and
    automatically sends 100 Trying for new INVITEs.  Optional behaviours:
    2xx retransmission until ACK (``retransmit_2xx``, on by default over
    UDP), session timers (``session_expires``, RFC 4028), and an
    advertised signaling address for NAT (``advertised_addr``).

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
        session_expires: int | None = None,
        min_se: int = DEFAULT_MIN_SE,
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
        # Session timers (RFC 4028): enabled when session_expires is set
        self.session_expires = session_expires
        self.min_se = min_se

        # Callbacks
        self.on_invite: InviteCallback | None = None
        self.on_bye: ByeCallback | None = None
        self.on_reinvite: InviteCallback | None = None
        self.on_cancel: RequestCallback | None = None
        self.on_options: RequestCallback | None = None
        self.on_update: UpdateCallback | None = None
        self.on_refer: ReferCallback | None = None
        self.on_transfer_progress: TransferProgressCallback | None = None
        self.on_ack_timeout: InviteCallback | None = None
        self.on_prack_timeout: InviteCallback | None = None
        self.on_session_expired: InviteCallback | None = None

        # Active calls keyed by call-id
        self._calls: dict[str, IncomingCall] = {}

        # Method dispatch (anything else gets 405)
        self._handlers: dict[str, Callable[[SipRequest, tuple[str, int]], None]] = {
            "INVITE": self._handle_invite,
            "ACK": partial(handle_ack, self),
            "PRACK": partial(handle_prack, self),
            "BYE": partial(handle_bye, self),
            "CANCEL": partial(handle_cancel, self),
            "OPTIONS": self._handle_options,
            "UPDATE": partial(handle_update, self),
            "REFER": partial(handle_refer, self),
            "NOTIFY": partial(handle_notify, self),
        }

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
        """Stop the UAS: cancel every pending timer and close the transport."""
        for call in self._calls.values():
            call._stop_retransmissions()
        if self.uac is not None:
            self.uac.close()
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
        if not dialog_matches(dialog, request):
            self._send_error(request, 481, "Call/Transaction Does Not Exist")
            return False
        if not remote_cseq_valid(dialog, request):
            self._send_error(request, 500, "Server Internal Error")
            return False
        return True

    def _handle_request(self, request: SipRequest, addr: tuple[str, int]) -> None:
        """Route an incoming request to the appropriate handler."""
        handler = self._handlers.get(request.method.upper())
        if handler is None:
            self._send_error(request, 405, "Method Not Allowed")
            return
        handler(request, addr)

    def _find_dialog(self, call_id: str) -> tuple[IncomingCall | None, Dialog | None]:
        """Locate the dialog for an in-dialog request.

        Returns ``(call, dialog)``: the call is ``None`` when the dialog
        belongs to an outbound call tracked by the UAC.
        """
        call = self._calls.get(call_id)
        if call is not None:
            return call, call.dialog
        if self.uac is not None:
            uac_call = self.uac.get_call(call_id)
            if uac_call is not None:
                return None, uac_call.dialog
        return None, None

    def _wrap_uac_dialog(self, request: SipRequest, addr: tuple[str, int]) -> IncomingCall:
        """Wrap an in-dialog request on an outbound call's dialog in an IncomingCall.

        Gives handlers the same respond-through-the-call interface for
        requests arriving on dialogs the UAC initiated.
        """
        dialog = create_dialog_from_request(request)
        dialog.confirm()  # outbound dialog is already confirmed
        sdp_offer: SdpMessage | None = None
        if request.body and request.content_type == "application/sdp":
            sdp_offer = parse_sdp(request.text)
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
        return wrapper

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
                existing.sdp_offer = parse_sdp(request.text)
            session_refreshed(self, call_id, existing)
            if self.on_reinvite is not None:
                self.on_reinvite(existing)
            return

        # Check for re-INVITE on an outbound call (dialog lives in UAC)
        if self.uac is not None and call_id in self.uac._calls:
            uac_dialog = self.uac._calls[call_id].dialog
            if not self._validate_in_dialog(uac_dialog, request):
                return
            if self.on_reinvite is not None:
                self.on_reinvite(self._wrap_uac_dialog(request, addr))
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

        # Session timers (RFC 4028): negotiate the interval and refresher role
        session_interval: int | None = None
        refresher_us = True
        if self.session_expires is not None:
            se_raw = request.get_header("session-expires")
            interval, refresher = (
                parse_session_expires(se_raw) if se_raw else (self.session_expires, None)
            )
            if 0 < interval < self.min_se:
                self._send_error(
                    request,
                    422,
                    "Session Interval Too Small",
                    extra_headers={"Min-SE": str(self.min_se)},
                )
                return
            session_interval = interval if interval > 0 else self.session_expires
            # Honour the offered refresher; we never refresh through re-INVITE,
            # so hand the role to the peer when its Allow lacks UPDATE
            refresher_us = refresher != "uac"
            if refresher_us and not peer_allows_update(request.headers.get("allow")):
                refresher_us = False

        # Parse SDP offer from body
        sdp_offer = None
        if request.body and request.content_type == "application/sdp":
            sdp_offer = parse_sdp(request.text)

        call = IncomingCall(
            dialog=dialog,
            invite=request,
            sdp_offer=sdp_offer,
            transport=self.transport,
            source_addr=addr,
            user_agent=self.user_agent,
            advertised_addr=self.advertised_addr,
            retransmit_2xx=self.retransmit_2xx,
            session_interval=session_interval,
            session_refresher_us=refresher_us,
            on_ack_timeout=self._dispatch_ack_timeout,
            on_prack_timeout=self._dispatch_prack_timeout,
        )

        self._calls[call_id] = call

        # Auto-send 100 Trying
        call.trying()

        # Dispatch to callback
        if self.on_invite is not None:
            self.on_invite(call)

    def _start_session_timer(self, call: IncomingCall) -> None:
        """Arm the RFC 4028 timer for a confirmed call (idempotent)."""
        if not call.session_interval or call._session_timer is not None:
            return
        call._session_timer = SessionTimer(
            call.session_interval,
            we_refresh=call.session_refresher_us,
            refresh=partial(send_session_refresh, call),
            expire=partial(self._dispatch_session_expired, call),
        )
        call._session_timer.start()

    def _dispatch_session_expired(self, call: IncomingCall) -> None:
        """No refresh before the deadline — the session is dead (RFC 4028 §10)."""
        self._calls.pop(call.call_id, None)
        self._remove_invite_transaction(call.invite)
        call.hangup()
        logger.warning("Session expired on %s — BYE sent", call.call_id)
        if self.on_session_expired is not None:
            self.on_session_expired(call)

    def _dispatch_ack_timeout(self, call: IncomingCall) -> None:
        """A 2xx was never ACKed — release the call (RFC 3261 §13.3.1.4)."""
        self._calls.pop(call.call_id, None)
        self._remove_invite_transaction(call.invite)
        logger.warning("No ACK for 2xx on %s — call released", call.call_id)
        if self.on_ack_timeout is not None:
            self.on_ack_timeout(call)

    def _dispatch_prack_timeout(self, call: IncomingCall) -> None:
        """A reliable provisional was never PRACKed — the INVITE was rejected (RFC 3262 §3)."""
        self._calls.pop(call.call_id, None)
        logger.warning("No PRACK for reliable 18x on %s — call rejected", call.call_id)
        if self.on_prack_timeout is not None:
            self.on_prack_timeout(call)

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

        resp.headers.set_single("Allow", ", ".join(self._handlers))
        if self.user_agent:
            resp.headers.set_single("User-Agent", self.user_agent)

        self.transport.send_reply(resp)

    def _send_error(
        self,
        request: SipRequest,
        status_code: int,
        reason: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        """Send an error response for a request with no dialog context."""
        resp = SipResponse(status_code=status_code, reason_phrase=reason)
        if extra_headers:
            for name, value in extra_headers.items():
                resp.headers.set_single(name, value)

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
