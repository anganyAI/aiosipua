"""Tests for blind transfer via REFER (RFC 3515)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from aiosipua.message import SipRequest, SipResponse
from aiosipua.refer import notify_refer
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS
from tests.support import FakeTransport

if TYPE_CHECKING:
    from aiosipua.incoming_call import IncomingCall


REMOTE_ADDR = ("10.0.0.1", 5060)

INVITE_RAW = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ref-1;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: ref-call-1@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


def _make_refer(call_id: str, from_tag: str, to_tag: str, *, refer_to: str | None) -> str:
    refer_line = f"Refer-To: <{refer_to}>\r\n" if refer_to else ""
    return (
        "REFER sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ref-r;rport\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 2 REFER\r\n"
        f"{refer_line}"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_notify(call_id: str, from_tag: str, to_tag: str, *, event: str, sipfrag: str) -> str:
    return (
        "NOTIFY sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ref-n;rport\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 3 NOTIFY\r\n"
        f"Event: {event}\r\n"
        "Subscription-State: active;expires=60\r\n"
        "Content-Type: message/sipfrag;version=2.0\r\n"
        f"Content-Length: {len(sipfrag)}\r\n"
        "\r\n"
        f"{sipfrag}"
    )


def _established(transport: FakeTransport) -> tuple[SipUAS, IncomingCall]:
    uas = SipUAS(transport)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message
    transport.inject(INVITE_RAW)
    call = calls[0]
    call.accept()
    transport.sent.clear()
    return uas, call


class TestUacSendRefer:
    def test_refer_request_format(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        uac = SipUAC(transport)  # type: ignore[arg-type]

        refer = uac.send_refer(call.dialog, "sip:agent@example.com", REMOTE_ADDR)

        assert refer.method == "REFER"
        assert refer.get_header("refer-to") == "<sip:agent@example.com>"
        cseq = refer.cseq
        assert cseq is not None
        assert cseq.method == "REFER"

    def test_refer_requires_confirmed_dialog(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        call.dialog.terminate()
        uac = SipUAC(transport)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="expected confirmed"):
            uac.send_refer(call.dialog, "sip:agent@example.com", REMOTE_ADDR)


class TestUasRefer:
    def test_refer_accepted_with_notify(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        refers: list[tuple[IncomingCall, str]] = []
        uas.on_refer = lambda c, uri: refers.append((c, uri))

        transport.inject(
            _make_refer(
                "ref-call-1@example.com",
                "from-tag-1",
                call.dialog.local_tag,
                refer_to="sip:agent@example.com",
            )
        )

        # 202 Accepted for the REFER
        responses = [m for m, _ in transport.sent if isinstance(m, SipResponse)]
        assert responses[0].status_code == 202

        # Immediate NOTIFY with sipfrag 100 Trying (RFC 3515 §2.4.4)
        notifies = [
            m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "NOTIFY"
        ]
        assert len(notifies) == 1
        notify = notifies[0]
        assert notify.get_header("event") == "refer"
        assert "active" in (notify.get_header("subscription-state") or "")
        assert notify.body.startswith("SIP/2.0 100")
        assert "sipfrag" in (notify.content_type or "")

        # Handler got the target URI
        assert refers == [(call, "sip:agent@example.com")]

    def test_refer_without_handler_501(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)

        transport.inject(
            _make_refer(
                "ref-call-1@example.com",
                "from-tag-1",
                call.dialog.local_tag,
                refer_to="sip:agent@example.com",
            )
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 501

    def test_refer_without_refer_to_400(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        uas.on_refer = lambda c, uri: None

        transport.inject(
            _make_refer(
                "ref-call-1@example.com", "from-tag-1", call.dialog.local_tag, refer_to=None
            )
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 400

    def test_refer_with_wrong_tags_481(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        uas.on_refer = lambda c, uri: None

        transport.inject(
            _make_refer(
                "ref-call-1@example.com", "evil", "wrong", refer_to="sip:agent@example.com"
            )
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 481

    def test_notify_refer_final(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)

        notify = notify_refer(call, 200, "OK")

        assert notify is not None
        assert notify.body == "SIP/2.0 200 OK\r\n"
        assert "terminated" in (notify.get_header("subscription-state") or "")

    def test_notify_refer_progress(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)

        notify = notify_refer(call, 180)

        assert notify is not None
        assert notify.body == "SIP/2.0 180 Ringing\r\n"
        assert "active" in (notify.get_header("subscription-state") or "")


class TestTransferProgress:
    def test_notify_feeds_transfer_progress(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)
        progress: list[tuple[str, int, str]] = []
        uas.on_transfer_progress = lambda cid, status, reason: progress.append(
            (cid, status, reason)
        )

        transport.inject(
            _make_notify(
                "ref-call-1@example.com",
                "from-tag-1",
                call.dialog.local_tag,
                event="refer",
                sipfrag="SIP/2.0 180 Ringing\r\n",
            )
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200
        assert progress == [("ref-call-1@example.com", 180, "Ringing")]

    def test_notify_with_unknown_event_489(self) -> None:
        transport = FakeTransport()
        uas, call = _established(transport)

        transport.inject(
            _make_notify(
                "ref-call-1@example.com",
                "from-tag-1",
                call.dialog.local_tag,
                event="presence",
                sipfrag="SIP/2.0 180 Ringing\r\n",
            )
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 489

    def test_notify_unknown_dialog_481(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        transport.inject(
            _make_notify("nope@example.com", "x", "y", event="refer", sipfrag="SIP/2.0 200 OK\r\n")
        )

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 481
