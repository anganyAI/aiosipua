"""SIP User Agent Client (UAC) — backend-initiated actions.

Supports outbound call initiation (:meth:`SipUAC.send_invite`) as well as
in-dialog requests: BYE (hangup), re-INVITE (session update / hold / unhold),
CANCEL (early dialog), and INFO (DTMF via SIP INFO).

All methods use the dialog's ``route_set`` for in-dialog routing
through the proxy chain (Kamailio / OpenSIPS).  No retransmission
timers — the proxy handles reliability.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .dialog import Dialog, DialogState
from .sdp import SdpMessage, parse_sdp, serialize_sdp
from .transaction import TransactionLayer
from .utils import generate_branch, generate_call_id, generate_tag

if TYPE_CHECKING:
    from collections.abc import Callable

    from .headers import AuthCredentials
    from .message import SipRequest, SipResponse
    from .transport import SipTransport

logger = logging.getLogger(__name__)


@dataclass
class SipDigestAuth:
    """Credentials for SIP digest authentication (RFC 2617)."""

    username: str
    password: str


@dataclass
class OutgoingCall:
    """An outgoing SIP call (INVITE transaction).

    Provides a high-level API for waiting on the call outcome and
    terminating the call: :meth:`wait_answered`, :meth:`cancel`,
    :meth:`hangup`.
    """

    dialog: Dialog
    invite: SipRequest
    sdp_offer: SdpMessage | None = None
    transport: SipTransport | None = field(default=None, repr=False)
    remote_addr: tuple[str, int] = ("0.0.0.0", 0)
    user_agent: str | None = field(default=None, repr=False)

    # Populated on 200 OK
    sdp_answer: SdpMessage | None = field(default=None, init=False)

    # Async signaling
    _answered: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
    _rejected: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
    _reject_code: int = field(default=0, init=False, repr=False)
    _reject_reason: str = field(default="", init=False, repr=False)

    # Digest auth (optional)
    _auth: SipDigestAuth | None = field(default=None, init=False, repr=False)
    _auth_attempts: int = field(default=0, init=False, repr=False)

    # Callbacks (optional)
    on_ringing: Callable[[OutgoingCall], Any] | None = field(default=None, repr=False)
    on_answer: Callable[[OutgoingCall], Any] | None = field(default=None, repr=False)
    on_rejected: Callable[[OutgoingCall, int, str], Any] | None = field(
        default=None, repr=False
    )

    @property
    def call_id(self) -> str:
        """The Call-ID of this call."""
        return self.dialog.call_id

    @property
    def caller(self) -> str:
        """The caller URI (From header = local)."""
        return self.dialog.local_uri

    @property
    def callee(self) -> str:
        """The callee URI (To header = remote)."""
        return self.dialog.remote_uri

    async def wait_answered(self, timeout: float = 30.0) -> None:
        """Wait for the call to be answered or rejected.

        Args:
            timeout: Maximum seconds to wait.

        Raises:
            TimeoutError: If neither answered nor rejected within *timeout*.
            RuntimeError: If the call was rejected (includes status code and reason).
        """
        answered = asyncio.create_task(self._answered.wait())
        rejected = asyncio.create_task(self._rejected.wait())
        try:
            done, pending = await asyncio.wait(
                {answered, rejected},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if not done:
                raise TimeoutError(f"No response within {timeout}s")
            if self._rejected.is_set():
                raise RuntimeError(
                    f"Call rejected: {self._reject_code} {self._reject_reason}"
                )
        finally:
            answered.cancel()
            rejected.cancel()

    def cancel(self, uac: SipUAC) -> SipRequest | None:
        """Cancel the outgoing call (sends CANCEL if dialog is EARLY).

        Returns the CANCEL request, or ``None`` if not in EARLY state.
        """
        if self.dialog.state != DialogState.EARLY:
            return None
        return uac.send_cancel(self.dialog, self.remote_addr)

    def hangup(self, uac: SipUAC) -> SipRequest | None:
        """Hang up the call (sends BYE if dialog is CONFIRMED).

        Returns the BYE request, or ``None`` if not in CONFIRMED state.
        """
        if self.dialog.state != DialogState.CONFIRMED:
            return None
        return uac.send_bye(self.dialog, self.remote_addr)


class SipUAC:
    """SIP UAC — sends requests and handles responses for outgoing calls.

    Usage::

        uac = SipUAC(transport)
        call = uac.send_invite("sip:me@local", "sip:them@remote", addr)
        await call.wait_answered()
        call.hangup(uac)
    """

    def __init__(self, transport: SipTransport) -> None:
        self.transport = transport
        self.transactions = TransactionLayer()

        # Outgoing calls keyed by Call-ID
        self._calls: dict[str, OutgoingCall] = {}

    def _local_addr(self) -> tuple[str, int]:
        return self.transport.local_addr

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
        from .message import SipRequest

        addr = self._local_addr()
        domain = addr[0]
        call_id = generate_call_id(domain)
        local_tag = generate_tag()
        branch = generate_branch()

        # Create dialog
        dialog = Dialog(
            call_id=call_id,
            local_tag=local_tag,
            remote_tag="",
            local_uri=from_uri,
            remote_uri=to_uri,
            remote_target=to_uri,
            state=DialogState.EARLY,
            local_cseq=0,
        )

        # Build INVITE request — use dialog.next_cseq() for proper CSeq
        cseq_num = dialog.next_cseq()

        from .headers import CSeq as CSeqObj
        from .headers import Via, stringify_cseq, stringify_via

        invite = SipRequest(method="INVITE", uri=to_uri)

        # Via
        via = Via(
            transport="UDP",
            host=addr[0],
            port=addr[1],
            params={"branch": branch},
        )
        invite.headers.append("Via", stringify_via(via))

        # From (local)
        invite.headers.set_single("From", f"<{from_uri}>;tag={local_tag}")

        # To (remote — no tag yet)
        invite.headers.set_single("To", f"<{to_uri}>")

        # Call-ID
        invite.headers.set_single("Call-ID", call_id)

        # CSeq
        invite.headers.set_single(
            "CSeq", stringify_cseq(CSeqObj(seq=cseq_num, method="INVITE"))
        )

        # Max-Forwards
        invite.headers.set_single("Max-Forwards", "70")

        # Contact
        invite.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        # SDP body
        if sdp_offer is not None:
            invite.body = serialize_sdp(sdp_offer)
            invite.headers.set_single("Content-Type", "application/sdp")

        # User-Agent
        if user_agent:
            invite.headers.set_single("User-Agent", user_agent)

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
        call = self._calls.get(call_id)
        if call is None:
            logger.debug("Response for unknown Call-ID: %s", call_id)
            return

        # Match to transaction
        self.transactions.match_response(response)

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

            call.dialog.confirm()
            self._send_ack(call)
            call._answered.set()

            logger.info("Call answered: %s", call_id)
            if call.on_answer is not None:
                call.on_answer(call)

        elif (
            status in (401, 407)
            and call._auth is not None
            and call._auth_attempts == 0
        ):
            # Auth challenge — retry with credentials
            if self._handle_auth_challenge(call, response, status):
                return

            # Fall through to rejection if challenge couldn't be handled
            call._reject_code = status
            call._reject_reason = response.reason_phrase
            call.dialog.terminate()
            call._rejected.set()

            logger.info(
                "Call rejected: %s (%d %s)", call_id, status, response.reason_phrase
            )
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

            logger.info(
                "Call rejected: %s (%d %s)", call_id, status, response.reason_phrase
            )
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

        return invite

    def send_cancel(self, dialog: Dialog, remote_addr: tuple[str, int]) -> SipRequest:
        """Send a CANCEL for a pending INVITE (early dialog).

        The CANCEL must match the original INVITE's branch and CSeq.
        Since we don't store the original INVITE here, this creates a
        new CANCEL request using the dialog's current state.

        Args:
            dialog: The early dialog to cancel.
            remote_addr: Address to send the CANCEL to.

        Returns:
            The CANCEL request that was sent.

        Raises:
            ValueError: If the dialog is not in EARLY state.
        """
        if dialog.state != DialogState.EARLY:
            raise ValueError(f"Cannot send CANCEL: dialog is {dialog.state.value}, expected early")

        addr = self._local_addr()
        cancel = dialog.create_request("CANCEL", via_host=addr[0], via_port=addr[1])

        self.transport.send(cancel, remote_addr)
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

    def _compute_digest(
        self,
        username: str,
        realm: str,
        password: str,
        method: str,
        uri: str,
        nonce: str,
    ) -> str:
        """Compute an RFC 2617 MD5 digest response."""
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

    def _handle_auth_challenge(
        self,
        call: OutgoingCall,
        response: SipResponse,
        status: int,
    ) -> bool:
        """Handle a 401/407 auth challenge. Returns True if retry was sent."""
        from .headers import AuthCredentials, parse_auth

        # Pick the right challenge header
        header_name = "WWW-Authenticate" if status == 401 else "Proxy-Authenticate"
        challenge_str = response.get_header(header_name)
        if not challenge_str:
            return False

        challenge = parse_auth(challenge_str)
        if challenge.scheme.lower() != "digest":
            return False

        realm = challenge.params.get("realm", "")
        nonce = challenge.params.get("nonce", "")
        if not nonce:
            return False

        assert call._auth is not None  # guaranteed by caller
        digest_uri = call.invite.uri
        digest_response = self._compute_digest(
            call._auth.username, realm, call._auth.password,
            "INVITE", digest_uri, nonce,
        )

        credentials = AuthCredentials(
            scheme="Digest",
            params={
                "username": call._auth.username,
                "realm": realm,
                "nonce": nonce,
                "uri": digest_uri,
                "response": digest_response,
                "algorithm": "MD5",
            },
        )

        auth_header_name = "Authorization" if status == 401 else "Proxy-Authorization"
        self._resend_invite_with_auth(call, credentials, auth_header_name)
        call._auth_attempts += 1

        logger.info(
            "Retrying INVITE with %s for %s (realm=%s)",
            auth_header_name, call.call_id, realm,
        )
        return True

    def _resend_invite_with_auth(
        self,
        call: OutgoingCall,
        credentials: AuthCredentials,
        auth_header_name: str,
    ) -> None:
        """Re-send INVITE with auth credentials (RFC 3261 §22.2)."""
        from .headers import CSeq as CSeqObj
        from .headers import Via, stringify_auth, stringify_cseq, stringify_via
        from .message import SipRequest

        addr = self._local_addr()
        branch = generate_branch()
        cseq_num = call.dialog.next_cseq()

        invite = SipRequest(method="INVITE", uri=call.invite.uri)

        # Via — new branch
        via = Via(
            transport="UDP",
            host=addr[0],
            port=addr[1],
            params={"branch": branch},
        )
        invite.headers.append("Via", stringify_via(via))

        # From (same as original)
        invite.headers.set_single(
            "From", f"<{call.dialog.local_uri}>;tag={call.dialog.local_tag}"
        )

        # To (same as original — no remote tag on retry)
        invite.headers.set_single("To", f"<{call.dialog.remote_uri}>")

        # Call-ID (same dialog)
        invite.headers.set_single("Call-ID", call.dialog.call_id)

        # CSeq — incremented
        invite.headers.set_single(
            "CSeq", stringify_cseq(CSeqObj(seq=cseq_num, method="INVITE"))
        )

        # Max-Forwards
        invite.headers.set_single("Max-Forwards", "70")

        # Contact
        invite.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        # SDP body (same as original)
        if call.sdp_offer is not None:
            from .sdp import serialize_sdp

            invite.body = serialize_sdp(call.sdp_offer)
            invite.headers.set_single("Content-Type", "application/sdp")

        # User-Agent
        if call.user_agent:
            invite.headers.set_single("User-Agent", call.user_agent)

        # Auth header
        invite.headers.set_single(auth_header_name, stringify_auth(credentials))

        # Create client transaction and send
        self.transactions.create_client(invite)
        self.transport.send(invite, call.remote_addr)

        # Update call to reference the new INVITE
        call.invite = invite

    def _send_ack(self, call: OutgoingCall) -> SipRequest:
        """Send an ACK for a 2xx response to an INVITE (RFC 3261 section 13.2.2.4).

        ACK for 2xx is a new transaction (new branch) but uses the
        same CSeq number as the original INVITE.
        """
        from .headers import CSeq as CSeqObj
        from .headers import Via, stringify_cseq, stringify_via
        from .message import SipRequest

        addr = self._local_addr()
        branch = generate_branch()

        # Get the INVITE's CSeq number
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
            params={"branch": branch},
        )
        ack.headers.append("Via", stringify_via(via))

        # From (local)
        ack.headers.set_single(
            "From", f"<{call.dialog.local_uri}>;tag={call.dialog.local_tag}"
        )

        # To (remote — with tag)
        to_val = f"<{call.dialog.remote_uri}>"
        if call.dialog.remote_tag:
            to_val += f";tag={call.dialog.remote_tag}"
        ack.headers.set_single("To", to_val)

        # Call-ID
        ack.headers.set_single("Call-ID", call.dialog.call_id)

        # CSeq — same number as INVITE, method=ACK
        ack.headers.set_single(
            "CSeq", stringify_cseq(CSeqObj(seq=cseq_num, method="ACK"))
        )

        # Max-Forwards
        ack.headers.set_single("Max-Forwards", "70")

        # Route set
        for route in call.dialog.route_set:
            ack.headers.append("Route", route)

        self.transport.send(ack, call.remote_addr)

        logger.debug("Sent ACK for %s", call.dialog.call_id)
        return ack
