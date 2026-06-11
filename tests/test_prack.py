"""Tests for PRACK / 100rel support (RFC 3262)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiosipua import transaction
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS
from tests.support import FakeTransport

if TYPE_CHECKING:
    from aiosipua.incoming_call import IncomingCall


REMOTE_ADDR = ("10.0.0.1", 5060)


def _invite_raw(*, supported: str = "100rel") -> str:
    supported_line = f"Supported: {supported}\r\n" if supported else ""
    return (
        "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-prk-1;rport\r\n"
        "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: prk-call-1@example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@10.0.0.1:5060>\r\n"
        f"{supported_line}"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_prack(call_id: str, from_tag: str, to_tag: str, rack: str) -> str:
    return (
        "PRACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-prk-p;rport\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 2 PRACK\r\n"
        f"RAck: {rack}\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


@pytest.fixture()
def fast_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transaction, "T1", 0.01)
    monkeypatch.setattr(transaction, "T2", 0.02)
    monkeypatch.setattr(transaction, "TIMER_H", 0.06)


def _pending_call(
    transport: FakeTransport, *, supported: str = "100rel"
) -> tuple[SipUAS, IncomingCall]:
    uas = SipUAS(transport)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message
    transport.inject(_invite_raw(supported=supported))
    transport.sent.clear()
    return uas, calls[0]


def _count_180(transport: FakeTransport) -> int:
    return len(
        [m for m, _ in transport.sent if isinstance(m, SipResponse) and m.status_code == 180]
    )


class TestUasReliableProvisional:
    @pytest.mark.asyncio()
    async def test_reliable_180_carries_rseq_and_require(self) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)

        call.ringing(reliable=True)

        resp, _ = transport.sent[0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 180
        assert resp.get_header("rseq") == "1"
        assert resp.get_header("require") == "100rel"
        call._stop_retransmissions()

    def test_reliable_requires_caller_support(self) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport, supported="")

        with pytest.raises(ValueError, match="100rel"):
            call.ringing(reliable=True)

    @pytest.mark.asyncio()
    async def test_reliable_180_retransmitted_until_prack(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)

        call.ringing(reliable=True)
        await asyncio.sleep(0.035)
        assert _count_180(transport) > 1

        transport.inject(
            _make_prack(
                "prk-call-1@example.com", "from-tag-1", call.dialog.local_tag, "1 1 INVITE"
            )
        )
        assert call._reliable_task is None
        # 200 OK answered to the PRACK itself
        prack_200 = [
            m for m, _ in transport.sent if isinstance(m, SipResponse) and m.status_code == 200
        ]
        assert len(prack_200) == 1

        sent_after = _count_180(transport)
        await asyncio.sleep(0.05)
        assert _count_180(transport) == sent_after

    @pytest.mark.asyncio()
    async def test_prack_with_wrong_rack_rejected(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)

        call.ringing(reliable=True)
        transport.inject(
            _make_prack(
                "prk-call-1@example.com", "from-tag-1", call.dialog.local_tag, "99 1 INVITE"
            )
        )

        statuses = [m.status_code for m, _ in transport.sent if isinstance(m, SipResponse)]
        assert 481 in statuses
        assert call._pending_rseq == 1  # still waiting
        call._stop_retransmissions()

    @pytest.mark.asyncio()
    async def test_prack_timeout_rejects_invite(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)
        timeouts: list[IncomingCall] = []
        uas.on_prack_timeout = lambda c: timeouts.append(c)

        call.ringing(reliable=True)
        await asyncio.sleep(0.15)

        assert timeouts == [call]
        statuses = [m.status_code for m, _ in transport.sent if isinstance(m, SipResponse)]
        assert 504 in statuses
        assert uas.get_call("prk-call-1@example.com") is None

    @pytest.mark.asyncio()
    async def test_accept_blocked_while_prack_pending(self) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)

        call.ringing(reliable=True)
        with pytest.raises(ValueError, match="PRACK"):
            call.accept()
        call._stop_retransmissions()

    @pytest.mark.asyncio()
    async def test_accept_works_after_prack(self) -> None:
        transport = FakeTransport()
        uas, call = _pending_call(transport)

        call.ringing(reliable=True)
        transport.inject(
            _make_prack(
                "prk-call-1@example.com", "from-tag-1", call.dialog.local_tag, "1 1 INVITE"
            )
        )
        call.accept()

        statuses = [m.status_code for m, _ in transport.sent if isinstance(m, SipResponse)]
        assert statuses[-1] == 200


class TestUacPrack:
    def _ringing_response(self, invite: SipRequest, rseq: int) -> str:
        return (
            "SIP/2.0 180 Ringing\r\n"
            f"Via: {invite.get_header('via')}\r\n"
            f"From: {invite.get_header('from')}\r\n"
            f"To: {invite.get_header('to')};tag=remote-tag\r\n"
            f"Call-ID: {invite.call_id}\r\n"
            f"CSeq: {invite.get_header('cseq')}\r\n"
            f"RSeq: {rseq}\r\n"
            "Require: 100rel\r\n"
            "Contact: <sip:alice@10.0.0.1:5060>\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )

    def test_invite_advertises_100rel(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite("sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR)
        assert call.invite.get_header("supported") == "100rel"

    def test_reliable_180_triggers_prack(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite("sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR)
        transport.sent.clear()

        resp = SipMessage.parse(self._ringing_response(call.invite, rseq=7))
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        pracks = [
            m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "PRACK"
        ]
        assert len(pracks) == 1
        assert pracks[0].get_header("rack") == "7 1 INVITE"
        prack_cseq = pracks[0].cseq
        assert prack_cseq is not None
        assert prack_cseq.method == "PRACK"

    def test_retransmitted_reliable_180_pracked_once(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite("sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR)
        transport.sent.clear()

        raw = self._ringing_response(call.invite, rseq=7)
        for _ in range(3):
            resp = SipMessage.parse(raw)
            assert isinstance(resp, SipResponse)
            uac.handle_response(resp, REMOTE_ADDR)

        pracks = [
            m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "PRACK"
        ]
        assert len(pracks) == 1

    def test_unreliable_180_not_pracked(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite("sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR)
        transport.sent.clear()

        raw = (
            "SIP/2.0 180 Ringing\r\n"
            f"Via: {call.invite.get_header('via')}\r\n"
            f"From: {call.invite.get_header('from')}\r\n"
            f"To: {call.invite.get_header('to')};tag=remote-tag\r\n"
            f"Call-ID: {call.invite.call_id}\r\n"
            f"CSeq: {call.invite.get_header('cseq')}\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        assert transport.sent == []
