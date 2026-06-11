"""In-dialog request handling for the UAS (RFC 3261 §12.2.2).

Module functions dispatched by :class:`aiosipua.uas.SipUAS` for requests
arriving on established dialogs: ACK, PRACK, BYE, CANCEL, and UPDATE.
Each handler validates the dialog (tags + CSeq) before acting.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .dialog import DialogState, dialog_matches
from .sdp import serialize_sdp

if TYPE_CHECKING:
    from .incoming_call import IncomingCall
    from .message import SipRequest
    from .sdp import SdpMessage
    from .uas import SipUAS

logger = logging.getLogger(__name__)


def handle_ack(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an incoming ACK (confirms a 2xx, or closes a rejected INVITE)."""
    call_id = request.call_id or ""
    call = uas._calls.get(call_id)
    if call is None or not dialog_matches(call.dialog, request):
        return

    call._stop_2xx_retransmission()
    if call.dialog.state == DialogState.TERMINATED:
        # ACK to our error response — the INVITE transaction is over
        uas._calls.pop(call_id, None)
    else:
        call.dialog.confirm()
        uas._start_session_timer(call)
    uas._remove_invite_transaction(call.invite)


def handle_prack(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle a PRACK acknowledging a reliable provisional (RFC 3262 §3)."""
    call_id = request.call_id or ""
    call = uas._calls.get(call_id)
    if call is None:
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return
    if not uas._validate_in_dialog(call.dialog, request):
        return

    rack = request.get_header("rack") or ""
    if not call._ack_reliable(rack):
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return

    resp = call.dialog.create_response(request, 200, "OK")
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)


def handle_bye(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an incoming BYE (terminates a call)."""
    call_id = request.call_id or ""
    call = uas._calls.get(call_id)

    if call is not None:
        if not uas._validate_in_dialog(call.dialog, request):
            return
        call._stop_retransmissions()
        uas._remove_invite_transaction(call.invite)

    # Check UAC's calls for outbound dialogs
    if call is None and uas.uac is not None and call_id in uas.uac._calls:
        uac_dialog = uas.uac._calls[call_id].dialog
        if not uas._validate_in_dialog(uac_dialog, request):
            return
        # Wrap so the on_bye callback has the same interface
        call = uas._wrap_uac_dialog(request, addr)
        # Remove from UAC tracking
        uas.uac._calls.pop(call_id, None)

    if call is None:
        # No matching dialog — 481
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return

    # Send 200 OK for BYE
    resp = call.dialog.create_response(request, 200, "OK")
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)

    # Terminate dialog and remove call
    call.dialog.terminate()
    uas._calls.pop(call_id, None)

    # Dispatch callback
    if uas.on_bye is not None:
        uas.on_bye(call, request)


def handle_cancel(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an incoming CANCEL (cancels a pending INVITE).

    Matched against the INVITE server transaction by Via branch
    (RFC 3261 §9.2), not by Call-ID.
    """
    vias = request.via
    branch = vias[0].branch if vias else None
    txn = uas.transactions.get_server(branch, "INVITE") if branch else None

    call: IncomingCall | None = None
    if txn is not None and txn.request is not None:
        call = uas._calls.get(txn.request.call_id or "")

    if call is None:
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return

    # Send 200 OK for the CANCEL itself
    resp = call.dialog.create_response(request, 200, "OK")
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)

    # Send 487 Request Terminated for the original INVITE
    call._stop_retransmissions()
    if not call._answered:
        call.reject(487, "Request Terminated")

    uas._calls.pop(call.call_id, None)
    if txn is not None:
        uas.transactions.remove(txn)

    if uas.on_cancel is not None:
        uas.on_cancel(request, addr)


def handle_update(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an in-dialog UPDATE (RFC 3311) — session refresh or renegotiation.

    Bodyless UPDATEs (e.g. RFC 4028 refreshes) get an automatic 200.
    UPDATEs carrying an SDP offer are answered with the SDP returned by
    ``on_update``, or rejected with 488 when no handler answers.
    """
    call_id = request.call_id or ""
    # UPDATE on an outbound call's dialog: refresh only (no renegotiation)
    call, dialog = uas._find_dialog(call_id)

    if dialog is None:
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return
    if not uas._validate_in_dialog(dialog, request):
        return

    has_offer = bool(request.body) and request.content_type == "application/sdp"
    sdp_answer: SdpMessage | None = None
    if call is not None and uas.on_update is not None:
        sdp_answer = uas.on_update(call, request)

    if has_offer and sdp_answer is None:
        resp = dialog.create_response(request, 488, "Not Acceptable Here")
    else:
        resp = dialog.create_response(request, 200, "OK")
        if sdp_answer is not None:
            resp.body = serialize_sdp(sdp_answer)
            resp.headers.set_single("Content-Type", "application/sdp")
        session_refreshed(uas, call_id, call)
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)


def session_refreshed(uas: SipUAS, call_id: str, call: IncomingCall | None) -> None:
    """Re-arm the session watchdog after an accepted refresh."""
    if call is not None and call._session_timer is not None:
        call._session_timer.refreshed()
        return
    if uas.uac is not None:
        uac_call = uas.uac.get_call(call_id)
        if uac_call is not None and uac_call._session_timer is not None:
            uac_call._session_timer.refreshed()
