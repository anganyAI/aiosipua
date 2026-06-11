"""Tests for UPDATE support (RFC 3311)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from aiosipua.dialog import DialogState
from aiosipua.message import SipResponse
from aiosipua.sdp import build_sdp, parse_sdp
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS
from tests.support import FakeTransport

if TYPE_CHECKING:
    from aiosipua.incoming_call import IncomingCall


REMOTE_ADDR = ("10.0.0.1", 5060)

INVITE_RAW = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-upd-1;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: upd-call-1@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

SDP_OFFER = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)


def _make_update(call_id: str, from_tag: str, to_tag: str, *, sdp: str = "") -> str:
    lines = [
        "UPDATE sip:bob@10.0.0.2:5060 SIP/2.0",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-upd-u;rport",
        f"From: <sip:alice@example.com>;tag={from_tag}",
        f"To: <sip:bob@example.com>;tag={to_tag}",
        f"Call-ID: {call_id}",
        "CSeq: 2 UPDATE",
        "Max-Forwards: 70",
    ]
    if sdp:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(sdp)}")
    return "\r\n".join(lines) + "\r\n\r\n" + sdp


def _established_uas(transport: FakeTransport) -> tuple[SipUAS, IncomingCall]:
    uas = SipUAS(transport)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message
    transport.inject(INVITE_RAW)
    call = calls[0]
    call.accept()
    transport.sent.clear()
    return uas, call


def _last_response(transport: FakeTransport) -> SipResponse:
    resp, _ = transport.sent[-1]
    assert isinstance(resp, SipResponse)
    return resp


class TestUacSendUpdate:
    def test_bodyless_update(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)
        uac = SipUAC(transport)  # type: ignore[arg-type]

        update = uac.send_update(call.dialog, REMOTE_ADDR)

        assert update.method == "UPDATE"
        assert update.body == b""
        cseq = update.cseq
        assert cseq is not None
        assert cseq.method == "UPDATE"
        assert transport.sent[-1][1] == REMOTE_ADDR

    def test_update_with_sdp(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)
        uac = SipUAC(transport)  # type: ignore[arg-type]

        sdp = build_sdp("10.0.0.2", 30000, 0, "PCMU")
        update = uac.send_update(call.dialog, REMOTE_ADDR, sdp=sdp)

        assert update.content_type == "application/sdp"
        assert "m=audio 30000" in update.text

    def test_update_allowed_in_early_dialog(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)
        call.dialog.state = DialogState.EARLY
        uac = SipUAC(transport)  # type: ignore[arg-type]

        update = uac.send_update(call.dialog, REMOTE_ADDR)
        assert update.method == "UPDATE"

    def test_update_rejected_on_terminated_dialog(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)
        call.dialog.terminate()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="terminated"):
            uac.send_update(call.dialog, REMOTE_ADDR)


class TestUasUpdate:
    def test_bodyless_update_gets_200(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)

        transport.inject(
            _make_update("upd-call-1@example.com", "from-tag-1", call.dialog.local_tag)
        )

        resp = _last_response(transport)
        assert resp.status_code == 200

    def test_update_with_offer_no_handler_gets_488(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)

        transport.inject(
            _make_update(
                "upd-call-1@example.com", "from-tag-1", call.dialog.local_tag, sdp=SDP_OFFER
            )
        )

        resp = _last_response(transport)
        assert resp.status_code == 488

    def test_update_with_offer_answered_by_handler(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)
        uas.on_update = lambda c, req: build_sdp("10.0.0.2", 30000, 0, "PCMU")

        transport.inject(
            _make_update(
                "upd-call-1@example.com", "from-tag-1", call.dialog.local_tag, sdp=SDP_OFFER
            )
        )

        resp = _last_response(transport)
        assert resp.status_code == 200
        assert resp.content_type == "application/sdp"
        answer = parse_sdp(resp.text)
        assert answer.audio is not None
        assert answer.audio.port == 30000

    def test_update_with_wrong_tags_gets_481(self) -> None:
        transport = FakeTransport()
        uas, call = _established_uas(transport)

        transport.inject(_make_update("upd-call-1@example.com", "evil-tag", "wrong-tag"))

        resp = _last_response(transport)
        assert resp.status_code == 481

    def test_update_unknown_call_gets_481(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        transport.inject(_make_update("nonexistent@example.com", "x", "y"))

        resp = _last_response(transport)
        assert resp.status_code == 481

    def test_update_on_outbound_dialog_refresh(self) -> None:
        """A bodyless UPDATE on a dialog owned by the UAC gets an automatic 200."""
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        call = uac.send_invite("sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR)
        # Answer the INVITE so the dialog is confirmed with a remote tag
        invite = call.invite
        raw_200 = (
            "SIP/2.0 200 OK\r\n"
            f"Via: {invite.get_header('via')}\r\n"
            f"From: {invite.get_header('from')}\r\n"
            f"To: {invite.get_header('to')};tag=remote-tag\r\n"
            f"Call-ID: {invite.call_id}\r\n"
            f"CSeq: {invite.get_header('cseq')}\r\n"
            "Contact: <sip:alice@10.0.0.1:5060>\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(raw_200)
        assert call.dialog.state == DialogState.CONFIRMED
        transport.sent.clear()

        # Remote refresher sends UPDATE: From = their tag, To = our tag
        update_raw = (
            "UPDATE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-upd-out;rport\r\n"
            f"From: <sip:alice@example.com>;tag=remote-tag\r\n"
            f"To: <sip:bob@example.com>;tag={call.dialog.local_tag}\r\n"
            f"Call-ID: {call.dialog.call_id}\r\n"
            "CSeq: 1 UPDATE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(update_raw)

        resp = _last_response(transport)
        assert resp.status_code == 200


class TestAllowHeader:
    def test_options_allow_includes_update(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        options_raw = (
            "OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt-u;rport\r\n"
            "From: <sip:alice@example.com>;tag=opt-tag\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: options-upd@example.com\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(options_raw)

        resp = _last_response(transport)
        allow = resp.get_header("allow") or ""
        assert "UPDATE" in allow

    def test_unknown_method_still_405(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        raw = (
            "SUBSCRIBE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-sub-1\r\n"
            "From: <sip:alice@example.com>;tag=sub-tag\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: sub-1@example.com\r\n"
            "CSeq: 1 SUBSCRIBE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        transport.inject(raw)

        resp = _last_response(transport)
        assert resp.status_code == 405
