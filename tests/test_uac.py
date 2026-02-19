"""Tests for aiosipua.uac."""

from __future__ import annotations

import asyncio

import pytest

from aiosipua.dialog import Dialog, DialogState
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.sdp import build_sdp, negotiate_sdp, parse_sdp, serialize_sdp
from aiosipua.uac import OutgoingCall, SipDigestAuth, SipUAC
from aiosipua.uas import IncomingCall, SipUAS

# --- Fake transport ---


class FakeTransport:
    """Minimal transport that captures sent messages."""

    def __init__(self, local_addr: tuple[str, int] = ("10.0.0.2", 5060)) -> None:
        self.local_addr = local_addr
        self.on_message = None
        self.sent: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        self._started = False

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        self._started = False

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        self.sent.append((message, addr))

    def send_reply(self, response: SipResponse) -> None:
        self.sent.append((response, ("0.0.0.0", 0)))

    def inject(self, raw: str, addr: tuple[str, int] = ("10.0.0.1", 5060)) -> None:
        """Simulate receiving a SIP message."""
        msg = SipMessage.parse(raw)
        if self.on_message is not None:
            self.on_message(msg, addr)


# --- Helpers ---

REMOTE_ADDR = ("10.0.0.1", 5060)

INVITE_WITH_SDP = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv-1;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: uac-test-1@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 117\r\n"
    "\r\n"
    "v=0\r\n"
    "o=- 1234 1234 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)

INVITE_WITH_ROUTES = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv-2;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-2\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: uac-test-2@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Record-Route: <sip:proxy1@10.0.0.10;lr>\r\n"
    "Record-Route: <sip:proxy2@10.0.0.20;lr>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


def _establish_call(
    transport: FakeTransport,
    invite_raw: str = INVITE_WITH_SDP,
) -> tuple[SipUAS, IncomingCall]:
    """Set up a UAS, inject an INVITE, and accept the call."""
    uas = SipUAS(transport)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message

    transport.inject(invite_raw)
    call = calls[0]

    # Accept (negotiate SDP if present)
    if call.sdp_offer is not None:
        answer, _ = negotiate_sdp(call.sdp_offer, "10.0.0.2", 30000)
        call.accept(answer)
    else:
        call.accept()

    return uas, call


def _make_response(
    invite: SipRequest,
    status_code: int,
    reason: str,
    *,
    remote_tag: str = "",
    sdp_body: str = "",
    extra_headers: dict[str, str] | None = None,
) -> str:
    """Build a raw SIP response matching an INVITE request."""
    via = invite.get_header("via") or ""
    from_val = invite.get_header("from") or ""
    call_id = invite.call_id or ""
    cseq = invite.get_header("cseq") or ""

    to_uri = invite.get_header("to") or ""
    to_val = f"{to_uri};tag={remote_tag}" if remote_tag and "tag=" not in to_uri else to_uri

    lines = [
        f"SIP/2.0 {status_code} {reason}",
        f"Via: {via}",
        f"From: {from_val}",
        f"To: {to_val}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        "Contact: <sip:10.0.0.1:5060>",
    ]

    if extra_headers:
        for name, value in extra_headers.items():
            lines.append(f"{name}: {value}")

    if sdp_body:
        lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(sdp_body)}")
    else:
        lines.append("Content-Length: 0")

    raw = "\r\n".join(lines) + "\r\n\r\n"
    if sdp_body:
        raw += sdp_body
    return raw


# --- Tests: Existing in-dialog requests ---


class TestSendBye:
    def test_bye_sends_request(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        bye = uac.send_bye(call.dialog, REMOTE_ADDR)

        assert bye.method == "BYE"
        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "BYE"
        assert addr == REMOTE_ADDR

    def test_bye_terminates_dialog(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)

        uac = SipUAC(transport)  # type: ignore[arg-type]
        uac.send_bye(call.dialog, REMOTE_ADDR)

        assert call.dialog.state == DialogState.TERMINATED

    def test_bye_has_correct_headers(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        bye = uac.send_bye(call.dialog, REMOTE_ADDR)

        assert bye.call_id == "uac-test-1@example.com"
        # From should be our local URI with local tag
        from_val = bye.get_header("from")
        assert from_val is not None
        assert f"tag={call.dialog.local_tag}" in from_val
        # To should be remote URI with remote tag
        to_val = bye.get_header("to")
        assert to_val is not None
        assert "tag=from-tag-1" in to_val
        # Via
        vias = bye.via
        assert len(vias) == 1
        assert vias[0].branch is not None
        assert vias[0].host == "10.0.0.2"
        # Contact
        contact = bye.get_header("contact")
        assert contact is not None
        assert "10.0.0.2:5060" in contact

    def test_bye_requires_confirmed_dialog(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(call_id="test", local_tag="l", remote_tag="r", state=DialogState.EARLY)
        uac = SipUAC(transport)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="expected confirmed"):
            uac.send_bye(dialog, REMOTE_ADDR)

    def test_bye_with_route_set(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport, INVITE_WITH_ROUTES)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        bye = uac.send_bye(call.dialog, REMOTE_ADDR)

        # Route set should be reversed Record-Route from INVITE
        routes = bye.get_header_values("route")
        assert len(routes) == 2
        # UAS reverses Record-Route: proxy2 first, proxy1 second
        assert "proxy2" in routes[0]
        assert "proxy1" in routes[1]


class TestSendReinvite:
    def test_reinvite_sends_request(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        invite = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)

        assert invite.method == "INVITE"
        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "INVITE"
        assert addr == REMOTE_ADDR

    def test_reinvite_has_sdp_body(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        invite = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)

        assert invite.content_type == "application/sdp"
        assert invite.body != ""
        # Parse the SDP back and verify
        parsed = parse_sdp(invite.body)
        assert parsed.audio is not None
        assert parsed.audio.port == 30000

    def test_reinvite_has_contact(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        invite = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)

        contact = invite.get_header("contact")
        assert contact is not None
        assert "10.0.0.2:5060" in contact

    def test_reinvite_requires_confirmed(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(call_id="test", local_tag="l", remote_tag="r", state=DialogState.EARLY)
        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        with pytest.raises(ValueError, match="expected confirmed"):
            uac.send_reinvite(dialog, sdp, REMOTE_ADDR)

    def test_reinvite_increments_cseq(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")

        inv1 = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)
        inv2 = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)

        c1 = inv1.cseq
        c2 = inv2.cseq
        assert c1 is not None and c2 is not None
        assert c2.seq == c1.seq + 1

    def test_reinvite_hold(self) -> None:
        """Hold scenario: re-INVITE with sendonly direction."""
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        # Modify SDP for hold: change direction to sendonly
        audio = sdp.audio
        assert audio is not None
        audio.attributes.pop("sendrecv", None)
        audio.attributes["sendonly"] = []

        invite = uac.send_reinvite(call.dialog, sdp, REMOTE_ADDR)
        parsed = parse_sdp(invite.body)
        assert parsed.audio is not None
        assert parsed.audio.direction == "sendonly"


class TestSendCancel:
    def test_cancel_sends_request(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(
            call_id="cancel-test",
            local_tag="l",
            remote_tag="r",
            local_uri="sip:bob@example.com",
            remote_uri="sip:alice@example.com",
            remote_target="sip:alice@10.0.0.1:5060",
            state=DialogState.EARLY,
        )

        uac = SipUAC(transport)  # type: ignore[arg-type]
        cancel = uac.send_cancel(dialog, REMOTE_ADDR)

        assert cancel.method == "CANCEL"
        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "CANCEL"
        assert addr == REMOTE_ADDR

    def test_cancel_terminates_dialog(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(
            call_id="cancel-test",
            local_tag="l",
            remote_tag="r",
            local_uri="sip:bob@example.com",
            remote_uri="sip:alice@example.com",
            remote_target="sip:alice@10.0.0.1:5060",
            state=DialogState.EARLY,
        )

        uac = SipUAC(transport)  # type: ignore[arg-type]
        uac.send_cancel(dialog, REMOTE_ADDR)

        assert dialog.state == DialogState.TERMINATED

    def test_cancel_requires_early_dialog(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(
            call_id="test",
            local_tag="l",
            remote_tag="r",
            state=DialogState.CONFIRMED,
        )
        uac = SipUAC(transport)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="expected early"):
            uac.send_cancel(dialog, REMOTE_ADDR)

    def test_cancel_has_correct_headers(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(
            call_id="cancel-hdr",
            local_tag="ltag",
            remote_tag="rtag",
            local_uri="sip:bob@example.com",
            remote_uri="sip:alice@example.com",
            remote_target="sip:alice@10.0.0.1:5060",
            state=DialogState.EARLY,
        )

        uac = SipUAC(transport)  # type: ignore[arg-type]
        cancel = uac.send_cancel(dialog, REMOTE_ADDR)

        assert cancel.call_id == "cancel-hdr"
        cseq = cancel.cseq
        assert cseq is not None
        assert cseq.method == "CANCEL"


class TestSendInfo:
    def test_info_sends_request(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        info = uac.send_info(
            call.dialog,
            "Signal=1\r\nDuration=250\r\n",
            "application/dtmf-relay",
            REMOTE_ADDR,
        )

        assert info.method == "INFO"
        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "INFO"
        assert addr == REMOTE_ADDR

    def test_info_has_body(self) -> None:
        transport = FakeTransport()
        _, call = _establish_call(transport)
        transport.sent.clear()

        uac = SipUAC(transport)  # type: ignore[arg-type]
        info = uac.send_info(
            call.dialog,
            "Signal=1\r\nDuration=250\r\n",
            "application/dtmf-relay",
            REMOTE_ADDR,
        )

        assert info.content_type == "application/dtmf-relay"
        assert "Signal=1" in info.body

    def test_info_requires_confirmed(self) -> None:
        transport = FakeTransport()
        dialog = Dialog(call_id="test", local_tag="l", remote_tag="r", state=DialogState.EARLY)
        uac = SipUAC(transport)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="expected confirmed"):
            uac.send_info(dialog, "body", "text/plain", REMOTE_ADDR)


class TestBackendInitiatedBye:
    """Integration test: full call flow with backend-initiated BYE."""

    def test_establish_and_backend_bye(self) -> None:
        transport = FakeTransport()
        uas, call = _establish_call(transport)
        local_tag = call.dialog.local_tag

        # Inject ACK to fully confirm
        ack_raw = (
            "ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-1\r\n"
            f"From: <sip:alice@example.com>;tag=from-tag-1\r\n"
            f"To: <sip:bob@example.com>;tag={local_tag}\r\n"
            "Call-ID: uac-test-1@example.com\r\n"
            "CSeq: 1 ACK\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(ack_raw)
        assert call.dialog.state == DialogState.CONFIRMED

        transport.sent.clear()

        # Backend initiates BYE via UAC
        uac = SipUAC(transport)  # type: ignore[arg-type]
        bye = uac.send_bye(call.dialog, REMOTE_ADDR)

        # Verify BYE was sent
        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "BYE"
        assert addr == REMOTE_ADDR

        # Verify BYE headers
        assert bye.call_id == "uac-test-1@example.com"
        from_val = bye.get_header("from")
        assert from_val is not None
        assert f"tag={local_tag}" in from_val
        to_val = bye.get_header("to")
        assert to_val is not None
        assert "tag=from-tag-1" in to_val

        # Dialog should be terminated
        assert call.dialog.state == DialogState.TERMINATED

    def test_establish_and_backend_bye_with_routes(self) -> None:
        """BYE through proxy chain uses route_set from Record-Route."""
        transport = FakeTransport()
        uas, call = _establish_call(transport, INVITE_WITH_ROUTES)

        # Verify route set was captured from Record-Route (reversed)
        assert len(call.dialog.route_set) == 2
        assert "proxy2" in call.dialog.route_set[0]
        assert "proxy1" in call.dialog.route_set[1]

        transport.sent.clear()

        # Backend BYE
        uac = SipUAC(transport)  # type: ignore[arg-type]
        bye = uac.send_bye(call.dialog, REMOTE_ADDR)

        # BYE should carry Route headers from route_set
        routes = bye.get_header_values("route")
        assert len(routes) == 2
        assert "proxy2" in routes[0]
        assert "proxy1" in routes[1]

        # Request-URI should be remote target (Contact from INVITE)
        assert bye.uri == "sip:alice@10.0.0.1:5060"


# --- Tests: Outbound INVITE (send_invite) ---


class TestSendInvite:
    def test_send_invite_creates_invite(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        assert isinstance(call, OutgoingCall)
        assert call.caller == "sip:me@example.com"
        assert call.callee == "sip:them@example.com"
        assert call.dialog.state == DialogState.EARLY
        assert call.remote_addr == REMOTE_ADDR

    def test_send_invite_sends_request(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        uac.send_invite("sip:me@example.com", "sip:them@example.com", REMOTE_ADDR)

        assert len(transport.sent) == 1
        msg, addr = transport.sent[0]
        assert isinstance(msg, SipRequest)
        assert msg.method == "INVITE"
        assert msg.uri == "sip:them@example.com"
        assert addr == REMOTE_ADDR

    def test_send_invite_headers(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )
        invite = call.invite

        # From
        from_val = invite.get_header("from")
        assert from_val is not None
        assert "sip:me@example.com" in from_val
        assert f"tag={call.dialog.local_tag}" in from_val

        # To (no tag yet)
        to_val = invite.get_header("to")
        assert to_val is not None
        assert "sip:them@example.com" in to_val
        assert "tag=" not in to_val

        # Call-ID
        assert invite.call_id is not None
        assert invite.call_id == call.call_id

        # CSeq
        cseq = invite.cseq
        assert cseq is not None
        assert cseq.method == "INVITE"
        assert cseq.seq == 1

        # Via
        vias = invite.via
        assert len(vias) == 1
        assert vias[0].host == "10.0.0.2"
        assert vias[0].port == 5060
        assert vias[0].branch is not None

        # Max-Forwards
        assert invite.get_header("max-forwards") == "70"

        # Contact
        contact = invite.get_header("contact")
        assert contact is not None
        assert "10.0.0.2:5060" in contact

    def test_send_invite_with_sdp(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            sdp_offer=sdp,
        )

        assert call.invite.content_type == "application/sdp"
        assert call.invite.body != ""
        assert call.sdp_offer is sdp

        # Verify SDP is parseable
        parsed = parse_sdp(call.invite.body)
        assert parsed.audio is not None
        assert parsed.audio.port == 30000

    def test_send_invite_without_sdp(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        assert call.invite.body == ""
        assert call.sdp_offer is None

    def test_send_invite_extra_headers(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            extra_headers={"X-Room-ID": "room-42", "X-Session-ID": "sess-1"},
        )

        assert call.invite.get_header("x-room-id") == "room-42"
        assert call.invite.get_header("x-session-id") == "sess-1"

    def test_send_invite_user_agent(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            user_agent="RoomKit/1.0",
        )

        assert call.invite.get_header("user-agent") == "RoomKit/1.0"
        assert call.user_agent == "RoomKit/1.0"

    def test_send_invite_stored_in_calls(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        assert uac.get_call(call.call_id) is call

    def test_send_invite_creates_client_transaction(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        uac.send_invite("sip:me@example.com", "sip:them@example.com", REMOTE_ADDR)

        # Should have one client transaction
        txns = uac.transactions.client_transactions
        assert len(txns) == 1


class TestHandleResponse:
    def _make_uac_and_call(
        self,
    ) -> tuple[FakeTransport, SipUAC, OutgoingCall]:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            sdp_offer=sdp,
        )
        return transport, uac, call

    def test_100_trying_ignored(self) -> None:
        transport, uac, call = self._make_uac_and_call()

        raw = _make_response(call.invite, 100, "Trying")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        # Dialog still EARLY, not answered, not rejected
        assert call.dialog.state == DialogState.EARLY
        assert not call._answered.is_set()
        assert not call._rejected.is_set()

    def test_180_ringing_updates_tag(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        remote_tag = "remote-tag-180"

        raw = _make_response(call.invite, 180, "Ringing", remote_tag=remote_tag)
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert call.dialog.remote_tag == remote_tag
        assert call.dialog.state == DialogState.EARLY

    def test_180_ringing_fires_callback(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        ringing_events: list[OutgoingCall] = []
        call.on_ringing = lambda c: ringing_events.append(c)

        raw = _make_response(call.invite, 180, "Ringing", remote_tag="rtag")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert len(ringing_events) == 1
        assert ringing_events[0] is call

    def test_183_session_progress(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        ringing_events: list[OutgoingCall] = []
        call.on_ringing = lambda c: ringing_events.append(c)

        raw = _make_response(call.invite, 183, "Session Progress", remote_tag="rtag")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert len(ringing_events) == 1
        assert call.dialog.state == DialogState.EARLY

    def test_200_ok_confirms_dialog(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        remote_tag = "remote-tag-200"

        sdp_answer = build_sdp("10.0.0.1", 20000, 0, "PCMU")
        sdp_body = serialize_sdp(sdp_answer)

        raw = _make_response(
            call.invite, 200, "OK",
            remote_tag=remote_tag,
            sdp_body=sdp_body,
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert call.dialog.state == DialogState.CONFIRMED
        assert call.dialog.remote_tag == remote_tag
        assert call._answered.is_set()
        assert not call._rejected.is_set()

    def test_200_ok_parses_sdp_answer(self) -> None:
        transport, uac, call = self._make_uac_and_call()

        sdp_answer = build_sdp("10.0.0.1", 20000, 0, "PCMU")
        sdp_body = serialize_sdp(sdp_answer)

        raw = _make_response(
            call.invite, 200, "OK",
            remote_tag="rtag",
            sdp_body=sdp_body,
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert call.sdp_answer is not None
        assert call.sdp_answer.audio is not None
        assert call.sdp_answer.audio.port == 20000

    def test_200_ok_sends_ack(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        transport.sent.clear()

        raw = _make_response(call.invite, 200, "OK", remote_tag="rtag")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        # Should have sent an ACK
        assert len(transport.sent) == 1
        ack_msg, ack_addr = transport.sent[0]
        assert isinstance(ack_msg, SipRequest)
        assert ack_msg.method == "ACK"
        assert ack_addr == REMOTE_ADDR

        # ACK headers
        assert ack_msg.call_id == call.call_id
        ack_cseq = ack_msg.cseq
        assert ack_cseq is not None
        assert ack_cseq.method == "ACK"
        # ACK CSeq number matches INVITE CSeq number
        invite_cseq = call.invite.cseq
        assert invite_cseq is not None
        assert ack_cseq.seq == invite_cseq.seq

        # ACK has new branch (different from INVITE)
        invite_branch = call.invite.via[0].branch
        ack_branch = ack_msg.via[0].branch
        assert ack_branch is not None
        assert ack_branch != invite_branch

    def test_200_ok_fires_callback(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        answer_events: list[OutgoingCall] = []
        call.on_answer = lambda c: answer_events.append(c)

        raw = _make_response(call.invite, 200, "OK", remote_tag="rtag")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert len(answer_events) == 1
        assert answer_events[0] is call

    def test_486_busy_rejects(self) -> None:
        transport, uac, call = self._make_uac_and_call()

        raw = _make_response(call.invite, 486, "Busy Here")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert call.dialog.state == DialogState.TERMINATED
        assert call._rejected.is_set()
        assert not call._answered.is_set()
        assert call._reject_code == 486
        assert call._reject_reason == "Busy Here"

        # Removed from calls
        assert uac.get_call(call.call_id) is None

    def test_603_decline_rejects(self) -> None:
        transport, uac, call = self._make_uac_and_call()

        raw = _make_response(call.invite, 603, "Decline")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert call._reject_code == 603
        assert call._reject_reason == "Decline"
        assert call.dialog.state == DialogState.TERMINATED

    def test_reject_fires_callback(self) -> None:
        transport, uac, call = self._make_uac_and_call()
        reject_events: list[tuple[OutgoingCall, int, str]] = []
        call.on_rejected = lambda c, code, reason: reject_events.append((c, code, reason))

        raw = _make_response(call.invite, 486, "Busy Here")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)

        uac.handle_response(resp, REMOTE_ADDR)

        assert len(reject_events) == 1
        assert reject_events[0] == (call, 486, "Busy Here")

    def test_unknown_call_id_ignored(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        resp = SipResponse(status_code=200, reason_phrase="OK")
        resp.headers.set_single("Call-ID", "nonexistent@example.com")
        resp.headers.set_single("CSeq", "1 INVITE")
        resp.headers.append("Via", "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-xxx")

        # Should not raise
        uac.handle_response(resp, REMOTE_ADDR)


class TestOutgoingCallMethods:
    def test_cancel_early_dialog(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )
        transport.sent.clear()

        result = call.cancel(uac)

        assert result is not None
        assert result.method == "CANCEL"
        assert call.dialog.state == DialogState.TERMINATED
        assert uac.get_call(call.call_id) is None

    def test_cancel_confirmed_returns_none(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        # Force dialog to confirmed
        call.dialog.confirm()

        result = call.cancel(uac)
        assert result is None

    def test_hangup_confirmed_dialog(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        # Simulate 200 OK to confirm
        raw = _make_response(call.invite, 200, "OK", remote_tag="rtag")
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)
        assert call.dialog.state == DialogState.CONFIRMED

        transport.sent.clear()

        result = call.hangup(uac)

        assert result is not None
        assert result.method == "BYE"
        assert call.dialog.state == DialogState.TERMINATED

    def test_hangup_early_returns_none(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        result = call.hangup(uac)
        assert result is None

    def test_call_properties(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        assert call.call_id == call.dialog.call_id
        assert call.caller == "sip:me@example.com"
        assert call.callee == "sip:them@example.com"


class TestWaitAnswered:
    @pytest.mark.asyncio()
    async def test_wait_answered_success(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        # Simulate 200 OK in a background task
        async def answer_later() -> None:
            await asyncio.sleep(0.01)
            raw = _make_response(call.invite, 200, "OK", remote_tag="rtag")
            resp = SipMessage.parse(raw)
            assert isinstance(resp, SipResponse)
            uac.handle_response(resp, REMOTE_ADDR)

        asyncio.create_task(answer_later())
        await call.wait_answered(timeout=2.0)

        assert call._answered.is_set()
        assert call.dialog.state == DialogState.CONFIRMED

    @pytest.mark.asyncio()
    async def test_wait_answered_rejected(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        # Simulate rejection in a background task
        async def reject_later() -> None:
            await asyncio.sleep(0.01)
            raw = _make_response(call.invite, 486, "Busy Here")
            resp = SipMessage.parse(raw)
            assert isinstance(resp, SipResponse)
            uac.handle_response(resp, REMOTE_ADDR)

        asyncio.create_task(reject_later())
        with pytest.raises(RuntimeError, match="486 Busy Here"):
            await call.wait_answered(timeout=2.0)

    @pytest.mark.asyncio()
    async def test_wait_answered_timeout(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        with pytest.raises(TimeoutError):
            await call.wait_answered(timeout=0.05)


class TestUASResponseForwarding:
    """Test that SipUAS forwards SipResponse to UAC."""

    def test_uas_forwards_response_to_uac(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        # Send INVITE via UAC
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        # Inject a 180 Ringing response via UAS transport
        ringing_events: list[OutgoingCall] = []
        call.on_ringing = lambda c: ringing_events.append(c)

        raw = _make_response(call.invite, 180, "Ringing", remote_tag="rtag")
        transport.inject(raw)

        assert len(ringing_events) == 1
        assert call.dialog.remote_tag == "rtag"

    def test_uas_forwards_200_ok_to_uac(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        sdp_answer = build_sdp("10.0.0.1", 20000, 0, "PCMU")
        sdp_body = serialize_sdp(sdp_answer)

        raw = _make_response(
            call.invite, 200, "OK",
            remote_tag="rtag-200",
            sdp_body=sdp_body,
        )
        transport.inject(raw)

        assert call.dialog.state == DialogState.CONFIRMED
        assert call._answered.is_set()
        assert call.sdp_answer is not None

    def test_uas_without_uac_ignores_responses(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        # Inject a response — should not raise
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-xxx\r\n"
            "From: <sip:me@example.com>;tag=ftag\r\n"
            "To: <sip:them@example.com>;tag=ttag\r\n"
            "Call-ID: unknown@example.com\r\n"
            "CSeq: 1 INVITE\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(raw)  # no error


class TestFullOutboundCallFlow:
    """Integration: INVITE → 100 → 180 → 200+ACK → BYE."""

    def test_full_outbound_flow(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        ringing_events: list[OutgoingCall] = []
        answer_events: list[OutgoingCall] = []

        # 1. Send INVITE
        sdp_offer = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            sdp_offer=sdp_offer,
        )
        call.on_ringing = lambda c: ringing_events.append(c)
        call.on_answer = lambda c: answer_events.append(c)

        # INVITE was sent
        assert len(transport.sent) == 1
        assert transport.sent[0][0].method == "INVITE"  # type: ignore[union-attr]

        # 2. 100 Trying
        raw_100 = _make_response(call.invite, 100, "Trying")
        transport.inject(raw_100)
        assert call.dialog.state == DialogState.EARLY

        # 3. 180 Ringing
        raw_180 = _make_response(call.invite, 180, "Ringing", remote_tag="callee-tag")
        transport.inject(raw_180)
        assert len(ringing_events) == 1
        assert call.dialog.remote_tag == "callee-tag"

        # 4. 200 OK with SDP answer
        sdp_answer = build_sdp("10.0.0.1", 20000, 0, "PCMU")
        sdp_body = serialize_sdp(sdp_answer)
        raw_200 = _make_response(
            call.invite, 200, "OK",
            remote_tag="callee-tag",
            sdp_body=sdp_body,
        )
        transport.sent.clear()
        transport.inject(raw_200)

        assert call.dialog.state == DialogState.CONFIRMED
        assert call._answered.is_set()
        assert call.sdp_answer is not None
        assert len(answer_events) == 1

        # ACK was sent
        assert len(transport.sent) == 1
        ack_msg = transport.sent[0][0]
        assert isinstance(ack_msg, SipRequest)
        assert ack_msg.method == "ACK"

        # 5. Hangup (BYE)
        transport.sent.clear()
        bye = call.hangup(uac)
        assert bye is not None
        assert bye.method == "BYE"
        assert call.dialog.state == DialogState.TERMINATED
        assert len(transport.sent) == 1

    def test_outbound_call_rejected_flow(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        reject_events: list[tuple[OutgoingCall, int, str]] = []

        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )
        call.on_rejected = lambda c, code, reason: reject_events.append((c, code, reason))

        # 100 Trying
        raw_100 = _make_response(call.invite, 100, "Trying")
        transport.inject(raw_100)

        # 486 Busy
        raw_486 = _make_response(call.invite, 486, "Busy Here")
        transport.inject(raw_486)

        assert call.dialog.state == DialogState.TERMINATED
        assert len(reject_events) == 1
        assert reject_events[0][1] == 486
        assert uac.get_call(call.call_id) is None


class TestRemoveCall:
    def test_remove_call(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR
        )

        assert uac.get_call(call.call_id) is not None
        uac.remove_call(call.call_id)
        assert uac.get_call(call.call_id) is None

    def test_remove_nonexistent_call(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        # Should not raise
        uac.remove_call("nonexistent")


# --- Tests: Digest Authentication ---


class TestDigestAuth:
    """Tests for SIP digest authentication on outbound INVITE."""

    CHALLENGE_407 = (
        'Digest realm="asterisk", nonce="abc123def456",'
        ' algorithm=MD5, qop="auth"'
    )
    CHALLENGE_401 = (
        'Digest realm="example.com", nonce="nonce-401-value",'
        ' algorithm=MD5'
    )

    def _make_uac_and_call_with_auth(
        self,
        auth: SipDigestAuth | None = None,
    ) -> tuple[FakeTransport, SipUAC, OutgoingCall]:
        if auth is None:
            auth = SipDigestAuth(username="alice", password="secret")
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            sdp_offer=sdp,
            auth=auth,
        )
        return transport, uac, call

    def test_407_triggers_retry_with_proxy_authorization(self) -> None:
        """407 with credentials → auto-retry INVITE with Proxy-Authorization."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        original_invite = call.invite
        transport.sent.clear()

        # Inject 407
        raw = _make_response(
            original_invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        # Should have re-sent INVITE (not rejected)
        assert not call._rejected.is_set()
        assert len(transport.sent) == 1
        retry_msg, retry_addr = transport.sent[0]
        assert isinstance(retry_msg, SipRequest)
        assert retry_msg.method == "INVITE"
        assert retry_addr == REMOTE_ADDR

        # Should have Proxy-Authorization header
        proxy_auth = retry_msg.get_header("proxy-authorization")
        assert proxy_auth is not None
        assert "Digest" in proxy_auth
        assert 'username="alice"' in proxy_auth
        assert 'realm="asterisk"' in proxy_auth
        assert 'nonce="abc123def456"' in proxy_auth
        assert "response=" in proxy_auth

        # CSeq should be incremented
        orig_cseq = original_invite.cseq
        retry_cseq = retry_msg.cseq
        assert orig_cseq is not None and retry_cseq is not None
        assert retry_cseq.seq == orig_cseq.seq + 1

        # New Via branch
        orig_branch = original_invite.via[0].branch
        retry_branch = retry_msg.via[0].branch
        assert retry_branch is not None
        assert retry_branch != orig_branch

        # call.invite updated to new INVITE
        assert call.invite is retry_msg

        # Now simulate 200 OK to the retried INVITE
        transport.sent.clear()
        raw_200 = _make_response(
            call.invite, 200, "OK", remote_tag="rtag",
        )
        resp_200 = SipMessage.parse(raw_200)
        assert isinstance(resp_200, SipResponse)
        uac.handle_response(resp_200, REMOTE_ADDR)

        assert call.dialog.state == DialogState.CONFIRMED
        assert call._answered.is_set()

    def test_401_triggers_retry_with_authorization(self) -> None:
        """401 with credentials → auto-retry INVITE with Authorization."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        original_invite = call.invite
        transport.sent.clear()

        raw = _make_response(
            original_invite, 401, "Unauthorized",
            extra_headers={"WWW-Authenticate": self.CHALLENGE_401},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        assert not call._rejected.is_set()
        assert len(transport.sent) == 1
        retry_msg = transport.sent[0][0]
        assert isinstance(retry_msg, SipRequest)

        # Should have Authorization (not Proxy-Authorization)
        auth_header = retry_msg.get_header("authorization")
        assert auth_header is not None
        assert 'realm="example.com"' in auth_header
        assert 'nonce="nonce-401-value"' in auth_header

        # Should NOT have Proxy-Authorization
        assert retry_msg.get_header("proxy-authorization") is None

    def test_digest_computation_correctness(self) -> None:
        """Verify digest response matches known RFC 2617 computation."""
        import hashlib

        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        result = uac._compute_digest(
            username="alice",
            realm="asterisk",
            password="secret",
            method="INVITE",
            uri="sip:them@example.com",
            nonce="abc123def456",
        )

        # Manual computation
        ha1 = hashlib.md5(b"alice:asterisk:secret").hexdigest()
        ha2 = hashlib.md5(b"INVITE:sip:them@example.com").hexdigest()
        expected = hashlib.md5(f"{ha1}:abc123def456:{ha2}".encode()).hexdigest()

        assert result == expected

    def test_max_one_retry(self) -> None:
        """Second 407 after auth attempt → rejection (no infinite loop)."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        original_invite = call.invite
        transport.sent.clear()

        # First 407 → triggers retry
        raw_407 = _make_response(
            original_invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp = SipMessage.parse(raw_407)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)
        assert not call._rejected.is_set()
        assert call._auth_attempts == 1

        # Second 407 → should reject (wrong password scenario)
        transport.sent.clear()
        raw_407_again = _make_response(
            call.invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp2 = SipMessage.parse(raw_407_again)
        assert isinstance(resp2, SipResponse)
        uac.handle_response(resp2, REMOTE_ADDR)

        assert call._rejected.is_set()
        assert call._reject_code == 407
        assert uac.get_call(call.call_id) is None

    def test_no_retry_without_credentials(self) -> None:
        """401/407 without auth → immediate rejection."""
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call = uac.send_invite(
            "sip:me@example.com", "sip:them@example.com", REMOTE_ADDR,
            sdp_offer=sdp,
            # No auth parameter
        )
        transport.sent.clear()

        raw = _make_response(
            call.invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        # Should reject immediately — no retry
        assert call._rejected.is_set()
        assert call._reject_code == 407
        assert len(transport.sent) == 0

    def test_non_digest_scheme_rejected(self) -> None:
        """Non-Digest auth scheme → rejection (no retry)."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        transport.sent.clear()

        raw = _make_response(
            call.invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": 'Basic realm="asterisk"'},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        # Should reject — Basic scheme not supported
        assert call._rejected.is_set()
        assert call._reject_code == 407
        assert len(transport.sent) == 0

    def test_retry_preserves_sdp_body(self) -> None:
        """Retry INVITE includes the same SDP offer as the original."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        transport.sent.clear()

        raw = _make_response(
            call.invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        retry_msg = transport.sent[0][0]
        assert isinstance(retry_msg, SipRequest)
        assert retry_msg.content_type == "application/sdp"
        assert retry_msg.body != ""

        # Parse and verify SDP preserved
        parsed = parse_sdp(retry_msg.body)
        assert parsed.audio is not None
        assert parsed.audio.port == 30000

    def test_retry_preserves_call_id_and_from_tag(self) -> None:
        """Retry uses the same Call-ID, From tag, and dialog."""
        transport, uac, call = self._make_uac_and_call_with_auth()
        original_call_id = call.call_id
        original_local_tag = call.dialog.local_tag
        transport.sent.clear()

        raw = _make_response(
            call.invite, 407, "Proxy Authentication Required",
            extra_headers={"Proxy-Authenticate": self.CHALLENGE_407},
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        retry_msg = transport.sent[0][0]
        assert isinstance(retry_msg, SipRequest)
        assert retry_msg.call_id == original_call_id
        from_val = retry_msg.get_header("from") or ""
        assert f"tag={original_local_tag}" in from_val

        # Call is still tracked
        assert uac.get_call(original_call_id) is call
