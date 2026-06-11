"""SIP User Agent Client (UAC) — backend-initiated actions.

Supports outbound call initiation (:meth:`SipUAC.send_invite`) as well as
in-dialog requests: BYE (hangup), re-INVITE (session update / hold / unhold),
UPDATE (RFC 3311), CANCEL (early dialog), and INFO (DTMF via SIP INFO).
Response processing lives in :mod:`aiosipua.uac_responses`.

All methods use the dialog's ``route_set`` for in-dialog routing
through the proxy chain (Kamailio / OpenSIPS).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .dialog import Dialog, DialogState
from .outgoing_call import OutgoingCall
from .sdp import SdpMessage, serialize_sdp
from .transaction import TransactionLayer
from .uac_responses import apply_session_headers, process_response
from .utils import generate_branch, generate_call_id, generate_tag

if TYPE_CHECKING:
    from .auth import SipDigestAuth
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
        session_expires: int | None = None,
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
            session_expires: Requested session-timer interval in seconds
                (RFC 4028); omitted, no timers are negotiated.

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
        if session_expires is not None:
            call._session_expires_requested = session_expires
            apply_session_headers(call, invite)
        self._calls[call_id] = call

        logger.info("Sent INVITE %s → %s (Call-ID: %s)", from_uri, to_uri, call_id)
        return call

    def handle_response(self, response: SipResponse, addr: tuple[str, int]) -> None:
        """Handle an incoming SIP response (matched to an outgoing call).

        Called by :class:`SipUAS` when it receives a response message.
        The actual state machine lives in :mod:`aiosipua.uac_responses`.

        Args:
            response: The SIP response.
            addr: Source address of the response.
        """
        process_response(self, response, addr)

    def close(self) -> None:
        """Cancel every pending timer owned by this UAC.

        Outgoing-call session timers and registration refresh/expiry tasks
        would otherwise keep firing against a closed transport.
        """
        for call in self._calls.values():
            call._cancel_session_timer()
        for registration in self._registrations.values():
            registration._cancel_timers()

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

        bye = self._send_in_dialog(dialog, "BYE", remote_addr)
        dialog.terminate()

        # Remove from outgoing calls if tracked
        call = self._calls.pop(dialog.call_id, None)
        if call is not None:
            call._cancel_session_timer()

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

        invite = self._send_in_dialog(
            dialog, "INVITE", remote_addr, body=serialize_sdp(sdp), content_type="application/sdp"
        )

        # Keep the tracked call pointing at the latest INVITE
        call = self._calls.get(dialog.call_id)
        if call is not None:
            call.invite = invite

        return invite

    def send_update(
        self,
        dialog: Dialog,
        remote_addr: tuple[str, int],
        *,
        sdp: SdpMessage | None = None,
    ) -> SipRequest:
        """Send an UPDATE within a dialog (RFC 3311) — session refresh or renegotiation.

        Unlike re-INVITE, UPDATE is allowed before the dialog is confirmed
        (early media renegotiation).

        Args:
            dialog: The early or confirmed dialog.
            remote_addr: Address to send the UPDATE to.
            sdp: Optional SDP offer; omitted for bare refreshes (RFC 4028).

        Returns:
            The UPDATE request that was sent.

        Raises:
            ValueError: If the dialog is terminated.
        """
        if dialog.state == DialogState.TERMINATED:
            raise ValueError("Cannot send UPDATE: dialog is terminated")

        body = serialize_sdp(sdp) if sdp is not None else ""
        content_type = "application/sdp" if sdp is not None else ""
        return self._send_in_dialog(
            dialog, "UPDATE", remote_addr, body=body, content_type=content_type
        )

    def send_refer(
        self,
        dialog: Dialog,
        refer_to: str,
        remote_addr: tuple[str, int],
    ) -> SipRequest:
        """Send a REFER for a blind transfer (RFC 3515).

        The remote party is asked to call *refer_to*; it reports progress
        with ``Event: refer`` NOTIFYs, surfaced through the UAS's
        ``on_transfer_progress`` callback.

        Args:
            dialog: The confirmed dialog.
            refer_to: Transfer target URI (e.g. ``"sip:agent@example.com"``).
            remote_addr: Address to send the REFER to.

        Returns:
            The REFER request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send REFER: dialog is {dialog.state.value}, expected confirmed"
            )

        target = refer_to if refer_to.startswith("<") else f"<{refer_to}>"
        return self._send_in_dialog(
            dialog, "REFER", remote_addr, extra_headers={"Refer-To": target}
        )

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
        call._cancel_session_timer()

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

        return self._send_in_dialog(
            dialog, "INFO", remote_addr, body=body, content_type=content_type, contact=False
        )

    # --- Internal helpers ---

    def _send_in_dialog(
        self,
        dialog: Dialog,
        method: str,
        remote_addr: tuple[str, int],
        *,
        body: str = "",
        content_type: str = "",
        contact: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> SipRequest:
        """Build and send an in-dialog request (shared by BYE/re-INVITE/UPDATE/INFO/REFER)."""
        addr = self._local_addr()
        request = dialog.create_request(method, via_host=addr[0], via_port=addr[1])
        if contact:
            request.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")
        if body:
            request.text = body
            request.headers.set_single("Content-Type", content_type)
        if extra_headers:
            for name, value in extra_headers.items():
                request.headers.set_single(name, value)
        self.transport.send(request, remote_addr)
        return request

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
        invite.headers.set_single("Supported", "100rel")

        if sdp_offer is not None:
            invite.text = serialize_sdp(sdp_offer)
            invite.headers.set_single("Content-Type", "application/sdp")
        if user_agent:
            invite.headers.set_single("User-Agent", user_agent)

        return invite
