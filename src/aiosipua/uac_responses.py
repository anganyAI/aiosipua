"""Response processing for outgoing calls (RFC 3261 §13.2.2).

The UAC's response state machine: routes REGISTER responses to their
:class:`~aiosipua.registration.Registration`, drives the outgoing-call
lifecycle on INVITE responses (provisional → PRACK, 2xx → ACK, 401/407 →
digest retry, 3xx-6xx → rejection), and ignores responses that don't
affect call state.  Entry point: :func:`process_response`, called by
:meth:`aiosipua.uac.SipUAC.handle_response`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .auth import answer_challenge
from .sdp import parse_sdp
from .session_timer import SessionTimer, parse_session_expires, peer_allows_update
from .utils import generate_branch

if TYPE_CHECKING:
    from .message import SipRequest, SipResponse
    from .outgoing_call import OutgoingCall
    from .uac import SipUAC

logger = logging.getLogger(__name__)


def process_response(uac: SipUAC, response: SipResponse, addr: tuple[str, int]) -> None:
    """Process an incoming SIP response for *uac*."""
    call_id = response.call_id or ""
    cseq = response.cseq

    # REGISTER responses belong to a Registration, not a call
    if cseq is not None and cseq.method.upper() == "REGISTER":
        registration = uac._registrations.get(call_id)
        if registration is not None:
            registration._handle_response(response)
        else:
            logger.debug("REGISTER response for unknown Call-ID: %s", call_id)
        return

    call = uac._calls.get(call_id)
    if call is None:
        logger.debug("Response for unknown Call-ID: %s", call_id)
        return

    # Match to transaction
    uac.transactions.match_response(response)

    # Only INVITE responses drive call state — a 200 to INFO/BYE must not
    # trigger ACK or answer callbacks
    if cseq is not None and cseq.method.upper() != "INVITE":
        logger.debug("%d for %s %s", response.status_code, cseq.method, call_id)
        return

    status = response.status_code

    if status == 100:
        # 100 Trying — just log
        logger.debug("100 Trying for %s", call_id)

    elif status in (180, 183):
        # Provisional — update remote tag, PRACK if reliable, fire ringing callback
        _update_remote_tag(call, response)
        _prack_if_reliable(uac, call, response)
        logger.info("%d %s for %s", status, response.reason_phrase, call_id)
        if call.on_ringing is not None:
            call.on_ringing(call)

    elif 200 <= status <= 299:
        # Success — confirm dialog, parse SDP answer, send ACK
        _update_remote_tag(call, response)

        # Parse SDP answer
        if response.body and response.content_type == "application/sdp":
            call.sdp_answer = parse_sdp(response.text)

        first_answer = not call._answered.is_set()
        call.dialog.confirm()
        _send_ack(uac, call, response)

        if first_answer:
            call._answered.set()
            _start_session_timer(uac, call, response)
            logger.info("Call answered: %s", call_id)
            if call.on_answer is not None:
                call.on_answer(call)
        else:
            # 2xx to a re-INVITE: ACK only, no answer callback replay
            logger.info("re-INVITE answered: %s", call_id)

    elif status == 422 and call._session_expires_requested and not call._se_retried:
        # Session Interval Too Small — retry with the registrar's Min-SE (RFC 4028 §6)
        _retry_invite_min_se(uac, call, response)

    elif status in (401, 407) and call._auth is not None and call._auth_attempts == 0:
        # Auth challenge — retry with credentials, else fall through to rejection
        if not _retry_invite_with_auth(uac, call, response, status):
            _reject_call(uac, call, status, response.reason_phrase)

    elif 300 <= status <= 699:
        _reject_call(uac, call, status, response.reason_phrase)


def _reject_call(uac: SipUAC, call: OutgoingCall, status: int, reason: str) -> None:
    """Mark the call rejected, fire callbacks, and drop it from tracking."""
    call._reject_code = status
    call._reject_reason = reason
    call.dialog.terminate()
    call._rejected.set()
    call._cancel_session_timer()

    logger.info("Call rejected: %s (%d %s)", call.call_id, status, reason)
    if call.on_rejected is not None:
        call.on_rejected(call, status, reason)

    uac._calls.pop(call.call_id, None)


def _update_remote_tag(call: OutgoingCall, response: SipResponse) -> None:
    """Extract remote tag from To header and update the dialog."""
    to_addr = response.to_addr
    if to_addr and to_addr.tag and not call.dialog.remote_tag:
        call.dialog.remote_tag = to_addr.tag


def _prack_if_reliable(uac: SipUAC, call: OutgoingCall, response: SipResponse) -> None:
    """Acknowledge a reliable provisional with a PRACK (RFC 3262 §4).

    Retransmitted provisionals (same RSeq) are PRACKed only once.
    """
    rseq_raw = response.get_header("rseq")
    if not rseq_raw:
        return
    try:
        rseq = int(rseq_raw.strip())
    except ValueError:
        return
    if rseq <= call._last_pracked_rseq:
        return

    cseq = response.cseq
    cseq_num = cseq.seq if cseq else 1

    addr = uac._local_addr()
    prack = call.dialog.create_request("PRACK", via_host=addr[0], via_port=addr[1])
    prack.headers.set_single("RAck", f"{rseq} {cseq_num} INVITE")

    uac.transactions.create_client(prack)
    uac.transport.send(prack, call.remote_addr)
    call._last_pracked_rseq = rseq
    logger.debug("PRACKed RSeq %d for %s", rseq, call.call_id)


def _retry_invite_with_auth(
    uac: SipUAC, call: OutgoingCall, response: SipResponse, status: int
) -> bool:
    """Answer a 401/407 by re-sending the INVITE. Returns True if retry was sent."""
    assert call._auth is not None  # guaranteed by caller
    auth_header = answer_challenge(call._auth, response, status, "INVITE", call.invite.uri)
    if auth_header is None:
        return False

    invite = uac._build_invite(call.dialog, sdp_offer=call.sdp_offer, user_agent=call.user_agent)
    apply_session_headers(call, invite)
    invite.headers.set_single(auth_header[0], auth_header[1])

    uac.transactions.create_client(invite)
    uac.transport.send(invite, call.remote_addr)

    # Update call to reference the new INVITE
    call.invite = invite
    call._auth_attempts += 1

    logger.info("Retrying INVITE with %s for %s", auth_header[0], call.call_id)
    return True


def _send_ack(uac: SipUAC, call: OutgoingCall, response: SipResponse) -> SipRequest:
    """Send an ACK for a 2xx response to an INVITE (RFC 3261 §13.2.2.4).

    ACK for 2xx is a new transaction (new branch) but uses the same CSeq
    number as the INVITE being acknowledged — taken from the response's
    CSeq so that re-INVITEs are ACKed with their own number.
    """
    from .headers import CSeq as CSeqObj
    from .headers import Via, stringify_cseq, stringify_via
    from .message import SipRequest

    addr = uac._local_addr()

    # CSeq number of the INVITE being acknowledged (echoed in the response)
    response_cseq = response.cseq
    if response_cseq is not None:
        cseq_num = response_cseq.seq
    else:
        invite_cseq = call.invite.cseq
        cseq_num = invite_cseq.seq if invite_cseq else 1

    ack = SipRequest(
        method="ACK",
        uri=call.dialog.remote_target or call.dialog.remote_uri,
    )

    # Via — new branch
    via = Via(
        transport="UDP",
        host=addr[0],
        port=addr[1],
        params={"branch": generate_branch(), "rport": None},
    )
    ack.headers.append("Via", stringify_via(via))

    # From (local)
    ack.headers.set_single("From", f"<{call.dialog.local_uri}>;tag={call.dialog.local_tag}")

    # To (remote — with tag)
    to_val = f"<{call.dialog.remote_uri}>"
    if call.dialog.remote_tag:
        to_val += f";tag={call.dialog.remote_tag}"
    ack.headers.set_single("To", to_val)

    # Call-ID
    ack.headers.set_single("Call-ID", call.dialog.call_id)

    # CSeq — same number as INVITE, method=ACK
    ack.headers.set_single("CSeq", stringify_cseq(CSeqObj(seq=cseq_num, method="ACK")))

    # Max-Forwards
    ack.headers.set_single("Max-Forwards", "70")

    # Route set
    for route in call.dialog.route_set:
        ack.headers.append("Route", route)

    uac.transport.send(ack, call.remote_addr)

    logger.debug("Sent ACK for %s", call.dialog.call_id)
    return ack


# --- Session timers, UAC side (RFC 4028) ---


def apply_session_headers(call: OutgoingCall, invite: SipRequest) -> None:
    """Stamp the session-timer headers on an INVITE (initial or retried)."""
    if not call._session_expires_requested:
        return
    invite.headers.set_single("Supported", "100rel, timer")
    invite.headers.set_single("Session-Expires", str(call._session_expires_requested))


def _retry_invite_min_se(uac: SipUAC, call: OutgoingCall, response: SipResponse) -> None:
    """Answer a 422 by retrying the INVITE with the server's Min-SE (RFC 4028 §6)."""
    raw = response.get_header("min-se") or ""
    try:
        min_se = int(raw.strip())
    except ValueError:
        min_se = 0
    requested = call._session_expires_requested or 0
    if min_se <= requested:
        _reject_call(uac, call, 422, response.reason_phrase)
        return

    call._se_retried = True
    call._session_expires_requested = min_se

    invite = uac._build_invite(call.dialog, sdp_offer=call.sdp_offer, user_agent=call.user_agent)
    apply_session_headers(call, invite)
    invite.headers.set_single("Min-SE", str(min_se))
    uac.transactions.create_client(invite)
    uac.transport.send(invite, call.remote_addr)
    call.invite = invite
    logger.info("Retrying INVITE with Session-Expires %d for %s", min_se, call.call_id)


def _start_session_timer(uac: SipUAC, call: OutgoingCall, response: SipResponse) -> None:
    """Arm the RFC 4028 timer from the 2xx's Session-Expires, if any."""
    se_raw = response.get_header("session-expires")
    if not se_raw:
        return
    interval, refresher = parse_session_expires(se_raw)
    if interval <= 0:
        return

    # Per RFC 4028 §7.2 the 2xx names the refresher; absent, the requester
    # (us) refreshes
    we_refresh = refresher != "uas"
    update_ok = peer_allows_update(response.headers.get("allow"))

    def refresh() -> None:
        if update_ok:
            uac._send_in_dialog(
                call.dialog,
                "UPDATE",
                call.remote_addr,
                extra_headers={"Session-Expires": f"{interval};refresher=uac"},
            )
        elif call.sdp_offer is not None:
            # Peer has no UPDATE — refresh through a re-INVITE with our offer
            uac.send_reinvite(call.dialog, call.sdp_offer, call.remote_addr)

    def expire() -> None:
        logger.warning("Session expired on %s — BYE sent", call.call_id)
        uac.send_bye(call.dialog, call.remote_addr)
        if call.on_session_expired is not None:
            call.on_session_expired(call)

    call._session_timer = SessionTimer(
        interval, we_refresh=we_refresh, refresh=refresh, expire=expire
    )
    call._session_timer.start()
