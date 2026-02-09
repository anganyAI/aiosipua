"""Tests for aiosipua.uas."""

from __future__ import annotations

import pytest

from aiosipua.dialog import DialogState
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.sdp import build_sdp, negotiate_sdp
from aiosipua.uas import IncomingCall, SipUAS

# --- Fake transport for testing ---


class FakeTransport:
    """Minimal SipTransport stand-in that captures sent messages."""

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
        # In the real transport this uses Via routing; for testing just
        # store it with a dummy addr.
        self.sent.append((response, ("0.0.0.0", 0)))

    def inject(self, raw: str, addr: tuple[str, int] = ("10.0.0.1", 5060)) -> None:
        """Simulate receiving a SIP message."""
        msg = SipMessage.parse(raw)
        if self.on_message is not None:
            self.on_message(msg, addr)


# --- Test data helpers ---

INVITE_RAW = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv-1;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: test-call-1@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

INVITE_WITH_SDP = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv-2;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-2\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: test-call-2@example.com\r\n"
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


def _make_ack(call_id: str, from_tag: str, to_tag: str) -> str:
    return (
        "ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-1\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_bye(call_id: str, from_tag: str, to_tag: str) -> str:
    return (
        "BYE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bye-1;rport\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 2 BYE\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_cancel(call_id: str, from_tag: str) -> str:
    return (
        "CANCEL sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv-1\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        "To: <sip:bob@example.com>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_options() -> str:
    return (
        "OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt-1;rport\r\n"
        "From: <sip:alice@example.com>;tag=opt-tag\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: options-1@example.com\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


# --- Tests ---


class TestSipUASInvite:
    @pytest.fixture()
    def uas_setup(self) -> tuple[SipUAS, FakeTransport, list[IncomingCall]]:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        uas.on_invite = lambda call: calls.append(call)
        # Don't start (no event loop needed for inject)
        transport.on_message = uas._on_message
        return uas, transport, calls

    def test_invite_creates_call(
        self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]
    ) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_RAW)

        assert len(calls) == 1
        call = calls[0]
        assert call.call_id == "test-call-1@example.com"
        assert call.caller == "sip:alice@example.com"
        assert call.callee == "sip:bob@example.com"
        assert call.dialog.state == DialogState.EARLY

    def test_invite_sends_100_trying(
        self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]
    ) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_RAW)

        # First sent message should be 100 Trying
        assert len(transport.sent) >= 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 100
        assert resp.reason_phrase == "Trying"

    def test_invite_with_sdp(
        self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]
    ) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_WITH_SDP)

        call = calls[0]
        assert call.sdp_offer is not None
        assert call.sdp_offer.audio is not None
        assert len(call.sdp_offer.audio.codecs) == 2

    def test_active_calls(
        self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]
    ) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_RAW)

        active = uas.active_calls
        assert "test-call-1@example.com" in active

    def test_get_call(self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_RAW)

        call = uas.get_call("test-call-1@example.com")
        assert call is not None
        assert call.call_id == "test-call-1@example.com"

    def test_get_dialog(self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]) -> None:
        uas, transport, calls = uas_setup
        transport.inject(INVITE_RAW)

        dialog = uas.get_dialog("test-call-1@example.com")
        assert dialog is not None
        assert dialog.call_id == "test-call-1@example.com"

    def test_get_nonexistent_call(
        self, uas_setup: tuple[SipUAS, FakeTransport, list[IncomingCall]]
    ) -> None:
        uas, transport, calls = uas_setup
        assert uas.get_call("nonexistent") is None
        assert uas.get_dialog("nonexistent") is None


class TestIncomingCallResponses:
    @pytest.fixture()
    def call_setup(self) -> tuple[IncomingCall, FakeTransport]:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        uas.on_invite = lambda call: calls.append(call)
        transport.on_message = uas._on_message
        transport.inject(INVITE_RAW)
        return calls[0], transport

    def test_ringing(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        transport.sent.clear()

        call.ringing()
        assert len(transport.sent) == 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 180

    def test_accept(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        transport.sent.clear()

        call.accept()
        assert len(transport.sent) == 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200
        assert call.dialog.state == DialogState.CONFIRMED

    def test_accept_with_sdp(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        transport.sent.clear()

        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        call.accept(sdp)

        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200
        assert resp.content_type == "application/sdp"
        assert resp.body != ""

    def test_reject(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        transport.sent.clear()

        call.reject(486)
        assert len(transport.sent) == 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 486
        assert call.dialog.state == DialogState.TERMINATED

    def test_reject_custom_reason(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        transport.sent.clear()

        call.reject(603, "Decline")
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 603
        assert resp.reason_phrase == "Decline"

    def test_hangup(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        call.accept()
        transport.sent.clear()

        bye = call.hangup()
        assert bye is not None
        assert bye.method == "BYE"
        assert call.dialog.state == DialogState.TERMINATED

    def test_hangup_before_accept(self, call_setup: tuple[IncomingCall, FakeTransport]) -> None:
        call, transport = call_setup
        # Not accepted yet — hangup should return None
        result = call.hangup()
        assert result is None


class TestIncomingCallProperties:
    def test_x_headers(self) -> None:
        raw = (
            "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x-1;rport\r\n"
            "From: <sip:alice@example.com>;tag=xtag\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: x-call@example.com\r\n"
            "CSeq: 1 INVITE\r\n"
            "Contact: <sip:alice@10.0.0.1:5060>\r\n"
            "X-Room-ID: room-42\r\n"
            "X-Session-ID: sess-99\r\n"
            "X-Custom: custom-val\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        uas.on_invite = lambda call: calls.append(call)
        transport.on_message = uas._on_message
        transport.inject(raw)

        call = calls[0]
        assert call.room_id == "room-42"
        assert call.session_id == "sess-99"
        xh = call.x_headers
        assert xh["X-Room-ID"] == "room-42"
        assert xh["X-Session-ID"] == "sess-99"
        assert xh["X-Custom"] == "custom-val"


class TestSipUASBye:
    def test_bye_terminates_call(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        bye_calls: list[tuple[IncomingCall, SipRequest]] = []
        uas.on_invite = lambda call: calls.append(call)
        uas.on_bye = lambda call, req: bye_calls.append((call, req))
        transport.on_message = uas._on_message

        # INVITE
        transport.inject(INVITE_RAW)
        call = calls[0]
        call.accept()

        local_tag = call.dialog.local_tag
        transport.sent.clear()

        # BYE
        bye_raw = _make_bye("test-call-1@example.com", "from-tag-1", local_tag)
        transport.inject(bye_raw)

        # Should send 200 OK for BYE
        assert len(transport.sent) >= 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200

        # Dialog terminated
        assert call.dialog.state == DialogState.TERMINATED

        # Callback fired
        assert len(bye_calls) == 1

        # Call removed from active
        assert uas.get_call("test-call-1@example.com") is None

    def test_bye_no_dialog(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        bye_raw = _make_bye("nonexistent@example.com", "x", "y")
        transport.inject(bye_raw)

        # Should send 481
        assert len(transport.sent) >= 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 481


class TestSipUASCancel:
    def test_cancel_pending_invite(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        cancel_events: list[tuple[SipRequest, tuple[str, int]]] = []
        uas.on_invite = lambda call: calls.append(call)
        uas.on_cancel = lambda req, addr: cancel_events.append((req, addr))
        transport.on_message = uas._on_message

        # INVITE (not accepted)
        transport.inject(INVITE_RAW)
        transport.sent.clear()

        # CANCEL
        cancel_raw = _make_cancel("test-call-1@example.com", "from-tag-1")
        transport.inject(cancel_raw)

        # Should send 200 for CANCEL + 487 for INVITE
        status_codes = [m.status_code for m, _ in transport.sent if isinstance(m, SipResponse)]
        assert 200 in status_codes
        assert 487 in status_codes

        # Call removed
        assert uas.get_call("test-call-1@example.com") is None
        assert len(cancel_events) == 1


class TestSipUASOptions:
    def test_options_default_response(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        transport.inject(_make_options())

        assert len(transport.sent) >= 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200
        allow = resp.get_header("allow")
        assert allow is not None
        assert "INVITE" in allow

    def test_options_custom_handler(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        handled: list[SipRequest] = []
        uas.on_options = lambda req, addr: handled.append(req)
        transport.on_message = uas._on_message

        transport.inject(_make_options())

        assert len(handled) == 1
        # No default response sent when custom handler is set
        assert len(transport.sent) == 0


class TestSipUASUnsupportedMethod:
    def test_unknown_method_405(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        raw = (
            "INFO sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-info-1;rport\r\n"
            "From: <sip:alice@example.com>;tag=infotag\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: info-1@example.com\r\n"
            "CSeq: 1 INFO\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(raw)

        assert len(transport.sent) >= 1
        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 405


class TestFullCallFlow:
    """Integration test: INVITE → 100 → 180 → 200 → ACK → BYE → 200."""

    def test_full_invite_flow(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        calls: list[IncomingCall] = []
        bye_events: list[tuple[IncomingCall, SipRequest]] = []
        uas.on_invite = lambda call: calls.append(call)
        uas.on_bye = lambda call, req: bye_events.append((call, req))
        transport.on_message = uas._on_message

        # 1. INVITE
        transport.inject(INVITE_WITH_SDP)
        call = calls[0]

        # Auto 100 Trying was sent
        assert transport.sent[0][0].status_code == 100  # type: ignore[union-attr]

        # 2. 180 Ringing
        call.ringing()
        assert transport.sent[-1][0].status_code == 180  # type: ignore[union-attr]

        # 3. Negotiate SDP and accept
        assert call.sdp_offer is not None
        answer, chosen_pt = negotiate_sdp(call.sdp_offer, "10.0.0.2", 30000)
        call.accept(answer)
        resp_200 = transport.sent[-1][0]
        assert isinstance(resp_200, SipResponse)
        assert resp_200.status_code == 200
        assert resp_200.body != ""
        assert call.dialog.state == DialogState.CONFIRMED

        local_tag = call.dialog.local_tag

        # 4. ACK
        ack_raw = _make_ack("test-call-2@example.com", "from-tag-2", local_tag)
        transport.inject(ack_raw)
        assert call.dialog.state == DialogState.CONFIRMED

        # 5. BYE
        transport.sent.clear()
        bye_raw = _make_bye("test-call-2@example.com", "from-tag-2", local_tag)
        transport.inject(bye_raw)

        # Should send 200 for BYE
        assert len(transport.sent) >= 1
        bye_resp = transport.sent[0][0]
        assert isinstance(bye_resp, SipResponse)
        assert bye_resp.status_code == 200

        # Dialog terminated
        assert call.dialog.state == DialogState.TERMINATED
        assert len(bye_events) == 1
        assert uas.get_call("test-call-2@example.com") is None


class TestSipUASStartStop:
    @pytest.mark.asyncio()
    async def test_start_stop(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]

        await uas.start()
        assert transport._started
        assert transport.on_message is not None

        await uas.stop()
        assert not transport._started
