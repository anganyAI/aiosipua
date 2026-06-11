"""SIP User Agent Client (UAC) — backend-initiated actions.

Supports outbound call initiation (:meth:`SipUAC.send_invite`) as well as
in-dialog requests: BYE (hangup), re-INVITE (session update / hold / unhold),
CANCEL (early dialog), and INFO (DTMF via SIP INFO).

All methods use the dialog's ``route_set`` for in-dialog routing
through the proxy chain (Kamailio / OpenSIPS).  No retransmission
timers — the proxy handles reliability.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .auth import SipDigestAuth, answer_challenge
from .dialog import Dialog, DialogState
from .outgoing_call import OutgoingCall
from .sdp import SdpMessage, parse_sdp, serialize_sdp
from .transaction import TransactionLayer
from .utils import generate_branch, generate_call_id, generate_tag

if TYPE_CHECKING:
    from .message import SipRequest, SipResponse
    from .registration import Registration
    from .transport import SipTransport

logger = logging.getLogger(__name__)


class SipUAC:
    """SIP UAC — sends requests and handles responses for outgoing calls.

    Usage::

        uac = SipUAC(transport)
        call = uac.send_invite("sip:me@local", "sip:them@remote", addr)
        await call.wait_answered()
        call.hangup(uac)
    """

    def __init__(
        self,
        transport: SipTransport,
        *,
        advertised_addr: tuple[str, int] | None = None,
    ) -> None:
        self.transport = transport
        self.transactions = TransactionLayer()
        # Address advertised in Via/Contact (NAT: bind on private, signal public)
        self.advertised_addr = advertised_addr

        # Outgoing calls keyed by Call-ID
        self._calls: dict[str, OutgoingCall] = {}
        # Active registrations keyed by Call-ID (populated by Registration)
        self._registrations: dict[str, Registration] = {}

    def _local_addr(self) -> tuple[str, int]:
        return self.advertised_addr or self.transport.local_addr

    # --- Outbound INVITE ---

    def send_invite(
        self,
        from_uri: str,
        to_uri: str,
        remote_addr: tuple[str, int],
        sdp_offer: SdpMessage | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
        user_agent: str | None = None,
        auth: SipDigestAuth | None = None,
    ) -> OutgoingCall:
        """Initiate an outbound call by sending an INVITE.

        Args:
            from_uri: Caller SIP URI (e.g. ``"sip:me@example.com"``).
            to_uri: Callee SIP URI (e.g. ``"sip:them@example.com"``).
            remote_addr: Address to send the INVITE to (proxy or remote UA).
            sdp_offer: Optional SDP offer to include in the INVITE body.
            extra_headers: Optional extra headers (e.g. ``{"X-Room-ID": "room-1"}``).
            user_agent: Optional User-Agent header value.
            auth: Optional digest credentials for automatic 401/407 retry.

        Returns:
            An :class:`OutgoingCall` that can be used to await the response.
        """
        call_id = generate_call_id(self._local_addr()[0])

        # Create dialog
        dialog = Dialog(
            call_id=call_id,
            local_tag=generate_tag(),
            remote_tag="",
            local_uri=from_uri,
            remote_uri=to_uri,
            remote_target=to_uri,
            state=DialogState.EARLY,
            local_cseq=0,
        )

        invite = self._build_invite(dialog, sdp_offer=sdp_offer, user_agent=user_agent)

        # Extra headers
        if extra_headers:
            for name, value in extra_headers.items():
                invite.headers.set_single(name, value)

        # Create client transaction
        self.transactions.create_client(invite)

        # Send
        self.transport.send(invite, remote_addr)

        # Create OutgoingCall
        call = OutgoingCall(
            dialog=dialog,
            invite=invite,
            sdp_offer=sdp_offer,
            transport=self.transport,
            remote_addr=remote_addr,
            user_agent=user_agent,
        )
        if auth is not None:
            call._auth = auth
        self._calls[call_id] = call

        logger.info("Sent INVITE %s → %s (Call-ID: %s)", from_uri, to_uri, call_id)
        return call

    def handle_response(self, response: SipResponse, addr: tuple[str, int]) -> None:
        """Handle an incoming SIP response (matched to an outgoing call).

        Called by :class:`SipUAS` when it receives a response message.

        Args:
            response: The SIP response.
            addr: Source address of the response.
        """
        call_id = response.call_id or ""
        cseq = response.cseq

        # REGISTER responses belong to a Registration, not a call
        if cseq is not None and cseq.method.upper() == "REGISTER":
            registration = self._registrations.get(call_id)
            if registration is not None:
                registration._handle_response(response)
            else:
                logger.debug("REGISTER response for unknown Call-ID: %s", call_id)
            return

        call = self._calls.get(call_id)
        if call is None:
            logger.debug("Response for unknown Call-ID: %s", call_id)
            return

        # Match to transaction
        self.transactions.match_response(response)

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
            # Provisional — update remote tag, fire ringing callback
            self._update_remote_tag(call, response)
            logger.info("%d %s for %s", status, response.reason_phrase, call_id)
            if call.on_ringing is not None:
                call.on_ringing(call)

        elif 200 <= status <= 299:
            # Success — confirm dialog, parse SDP answer, send ACK
            self._update_remote_tag(call, response)

            # Parse SDP answer
            if response.body and response.content_type == "application/sdp":
                call.sdp_answer = parse_sdp(response.body)

            first_answer = not call._answered.is_set()
            call.dialog.confirm()
            self._send_ack(call, response)

            if first_answer:
                call._answered.set()
                logger.info("Call answered: %s", call_id)
                if call.on_answer is not None:
                    call.on_answer(call)
            else:
                # 2xx to a re-INVITE: ACK only, no answer callback replay
                logger.info("re-INVITE answered: %s", call_id)

        elif status in (401, 407) and call._auth is not None and call._auth_attempts == 0:
            # Auth challenge — retry with credentials
            if self._handle_auth_challenge(call, response, status):
                return

            # Fall through to rejection if challenge couldn't be handled
            call._reject_code = status
            call._reject_reason = response.reason_phrase
            call.dialog.terminate()
            call._rejected.set()

            logger.info("Call rejected: %s (%d %s)", call_id, status, response.reason_phrase)
            if call.on_rejected is not None:
                call.on_rejected(call, status, response.reason_phrase)

            self._calls.pop(call_id, None)
            return

        elif 300 <= status <= 699:
            # Failure — reject
            call._reject_code = status
            call._reject_reason = response.reason_phrase
            call.dialog.terminate()
            call._rejected.set()

            logger.info("Call rejected: %s (%d %s)", call_id, status, response.reason_phrase)
            if call.on_rejected is not None:
                call.on_rejected(call, status, response.reason_phrase)

            self._calls.pop(call_id, None)

    def get_call(self, call_id: str) -> OutgoingCall | None:
        """Look up an outgoing call by Call-ID."""
        return self._calls.get(call_id)

    def remove_call(self, call_id: str) -> None:
        """Remove an outgoing call from tracking."""
        self._calls.pop(call_id, None)

    # --- In-dialog requests ---

    def send_bye(self, dialog: Dialog, remote_addr: tuple[str, int]) -> SipRequest:
        """Send a BYE to terminate an established call.

        Args:
            dialog: The confirmed dialog to terminate.
            remote_addr: Address to send the BYE to (proxy or remote UA).

        Returns:
            The BYE request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send BYE: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        bye = dialog.create_request("BYE", via_host=addr[0], via_port=addr[1])

        # Add Contact header
        bye.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        self.transport.send(bye, remote_addr)
        dialog.terminate()

        # Remove from outgoing calls if tracked
        self._calls.pop(dialog.call_id, None)

        return bye

    def send_reinvite(
        self,
        dialog: Dialog,
        sdp: SdpMessage,
        remote_addr: tuple[str, int],
    ) -> SipRequest:
        """Send a re-INVITE to update the session (codec change, hold, etc.).

        Args:
            dialog: The confirmed dialog to update.
            sdp: The new SDP offer.
            remote_addr: Address to send the re-INVITE to.

        Returns:
            The re-INVITE request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send re-INVITE: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        invite = dialog.create_request("INVITE", via_host=addr[0], via_port=addr[1])

        # Contact
        invite.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        # SDP body
        invite.body = serialize_sdp(sdp)
        invite.headers.set_single("Content-Type", "application/sdp")

        self.transport.send(invite, remote_addr)

        # Keep the tracked call pointing at the latest INVITE
        call = self._calls.get(dialog.call_id)
        if call is not None:
            call.invite = invite

        return invite

    def send_cancel(self, call: OutgoingCall) -> SipRequest:
        """Send a CANCEL for a pending INVITE (RFC 3261 §9.1).

        The CANCEL is constructed from the original INVITE: same Request-URI,
        same topmost Via (same branch), same From/To/Call-ID, and the same
        CSeq number with method CANCEL.

        Args:
            call: The outgoing call whose INVITE should be cancelled.

        Returns:
            The CANCEL request that was sent.

        Raises:
            ValueError: If the dialog is not in EARLY state.
        """
        from .headers import CSeq as CSeqObj
        from .headers import stringify_cseq
        from .message import SipRequest

        dialog = call.dialog
        if dialog.state != DialogState.EARLY:
            raise ValueError(f"Cannot send CANCEL: dialog is {dialog.state.value}, expected early")

        invite = call.invite
        cancel = SipRequest(method="CANCEL", uri=invite.uri)

        # Topmost Via copied verbatim — the branch must match the INVITE's
        top_via = invite.headers.get_first("via")
        if top_via:
            cancel.headers.append("Via", top_via)

        for name in ("From", "To", "Call-ID"):
            val = invite.headers.get_first(name)
            if val:
                cancel.headers.set_single(name, val)

        invite_cseq = invite.cseq
        seq = invite_cseq.seq if invite_cseq else 1
        cancel.headers.set_single("CSeq", stringify_cseq(CSeqObj(seq=seq, method="CANCEL")))
        cancel.headers.set_single("Max-Forwards", "70")

        for route in invite.headers.get("route"):
            cancel.headers.append("Route", route)

        self.transactions.create_client(cancel)
        self.transport.send(cancel, call.remote_addr)
        dialog.terminate()

        # Remove from outgoing calls if tracked
        self._calls.pop(dialog.call_id, None)

        return cancel

    def send_info(
        self,
        dialog: Dialog,
        body: str,
        content_type: str,
        remote_addr: tuple[str, int],
    ) -> SipRequest:
        """Send an INFO request within a dialog (e.g. DTMF via SIP INFO).

        Args:
            dialog: The confirmed dialog.
            body: The INFO body (e.g. ``"Signal=1\\r\\nDuration=250\\r\\n"``).
            content_type: Content-Type for the body
                (e.g. ``"application/dtmf-relay"``).
            remote_addr: Address to send the INFO to.

        Returns:
            The INFO request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send INFO: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        info = dialog.create_request("INFO", via_host=addr[0], via_port=addr[1])

        info.body = body
        info.headers.set_single("Content-Type", content_type)

        self.transport.send(info, remote_addr)

        return info

    # --- Internal helpers ---

    def _update_remote_tag(self, call: OutgoingCall, response: SipResponse) -> None:
        """Extract remote tag from To header and update the dialog."""
        to_addr = response.to_addr
        if to_addr and to_addr.tag and not call.dialog.remote_tag:
            call.dialog.remote_tag = to_addr.tag

    def _handle_auth_challenge(
        self,
        call: OutgoingCall,
        response: SipResponse,
        status: int,
    ) -> bool:
        """Handle a 401/407 auth challenge. Returns True if retry was sent."""
        assert call._auth is not None  # guaranteed by caller
        auth_header = answer_challenge(call._auth, response, status, "INVITE", call.invite.uri)
        if auth_header is None:
            return False

        self._resend_invite_with_auth(call, auth_header)
        call._auth_attempts += 1

        logger.info("Retrying INVITE with %s for %s", auth_header[0], call.call_id)
        return True

    def _build_invite(
        self,
        dialog: Dialog,
        *,
        sdp_offer: SdpMessage | None,
        user_agent: str | None,
    ) -> SipRequest:
        """Build an INVITE for *dialog* with a fresh branch and the next CSeq."""
        from .headers import CSeq as CSeqObj
        from .headers import Via, stringify_cseq, stringify_via
        from .message import SipRequest

        addr = self._local_addr()
        invite = SipRequest(method="INVITE", uri=dialog.remote_uri)

        via = Via(
            transport="UDP",
            host=addr[0],
            port=addr[1],
            params={"branch": generate_branch(), "rport": None},
        )
        invite.headers.append("Via", stringify_via(via))
        invite.headers.set_single("From", f"<{dialog.local_uri}>;tag={dialog.local_tag}")
        invite.headers.set_single("To", f"<{dialog.remote_uri}>")
        invite.headers.set_single("Call-ID", dialog.call_id)
        invite.headers.set_single(
            "CSeq", stringify_cseq(CSeqObj(seq=dialog.next_cseq(), method="INVITE"))
        )
        invite.headers.set_single("Max-Forwards", "70")
        invite.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        if sdp_offer is not None:
            invite.body = serialize_sdp(sdp_offer)
            invite.headers.set_single("Content-Type", "application/sdp")
        if user_agent:
            invite.headers.set_single("User-Agent", user_agent)

        return invite

    def _resend_invite_with_auth(self, call: OutgoingCall, auth_header: tuple[str, str]) -> None:
        """Re-send INVITE with auth credentials (RFC 3261 §22.2)."""
        invite = self._build_invite(
            call.dialog, sdp_offer=call.sdp_offer, user_agent=call.user_agent
        )
        invite.headers.set_single(auth_header[0], auth_header[1])

        self.transactions.create_client(invite)
        self.transport.send(invite, call.remote_addr)

        # Update call to reference the new INVITE
        call.invite = invite

    def _send_ack(self, call: OutgoingCall, response: SipResponse) -> SipRequest:
        """Send an ACK for a 2xx response to an INVITE (RFC 3261 section 13.2.2.4).

        ACK for 2xx is a new transaction (new branch) but uses the same CSeq
        number as the INVITE being acknowledged — taken from the response's
        CSeq so that re-INVITEs are ACKed with their own number.
        """
        from .headers import CSeq as CSeqObj
        from .headers import Via, stringify_cseq, stringify_via
        from .message import SipRequest

        addr = self._local_addr()
        branch = generate_branch()

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
            params={"branch": branch, "rport": None},
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

        self.transport.send(ack, call.remote_addr)

        logger.debug("Sent ACK for %s", call.dialog.call_id)
        return ack
