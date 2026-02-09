"""Tests for aiosipua.uac."""

from __future__ import annotations

import pytest

from aiosipua.dialog import Dialog, DialogState
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.sdp import build_sdp, negotiate_sdp, parse_sdp
from aiosipua.uac import SipUAC
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


# --- Tests ---


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
