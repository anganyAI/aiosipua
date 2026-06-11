"""Tests for session timers (RFC 4028)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiosipua import session_timer as st_mod
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.session_timer import parse_session_expires, watchdog_delay
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS
from tests.support import FakeTransport

if TYPE_CHECKING:
    from aiosipua.incoming_call import IncomingCall
    from aiosipua.outgoing_call import OutgoingCall


REMOTE_ADDR = ("10.0.0.1", 5060)


def _invite_raw(*, session_expires: str | None, supported: str = "timer") -> str:
    se_line = f"Session-Expires: {session_expires}\r\n" if session_expires else ""
    supported_line = f"Supported: {supported}\r\n" if supported else ""
    return (
        "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-1;rport\r\n"
        "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: st-call-1@example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@10.0.0.1:5060>\r\n"
        f"{se_line}{supported_line}"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_ack(call_id: str, from_tag: str, to_tag: str) -> str:
    return (
        "ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-ack\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def _make_update(call_id: str, from_tag: str, to_tag: str, cseq: int) -> str:
    return (
        "UPDATE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-u;rport\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} UPDATE\r\n"
        "Session-Expires: 1;refresher=uac\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


@pytest.fixture()
def fast_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st_mod, "REFRESH_FRACTION", 0.02)
    monkeypatch.setattr(st_mod, "watchdog_delay", lambda interval: 0.04)


class TestParsing:
    def test_parse_session_expires(self) -> None:
        assert parse_session_expires("1800") == (1800, None)
        assert parse_session_expires("1800;refresher=uac") == (1800, "uac")
        assert parse_session_expires("90 ; refresher=UAS") == (90, "uas")
        assert parse_session_expires("garbage") == (0, None)

    def test_watchdog_delay(self) -> None:
        assert watchdog_delay(1800) == 1768.0  # 1800 - 32
        assert watchdog_delay(90) == 60.0  # 90 - 90/3


def _uas_call(
    transport: FakeTransport, raw: str, **uas_kwargs: object
) -> tuple[SipUAS, IncomingCall]:
    uas = SipUAS(transport, **uas_kwargs)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message
    transport.inject(raw)
    return uas, calls[0]


class TestUasNegotiation:
    def test_honours_offered_interval_and_refresher(self) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(
            transport, _invite_raw(session_expires="1800;refresher=uac"), session_expires=900
        )
        transport.sent.clear()
        call.accept()

        assert call.session_interval == 1800
        assert call.session_refresher_us is False
        resp = transport.sent[0][0]
        assert isinstance(resp, SipResponse)
        assert resp.get_header("session-expires") == "1800;refresher=uac"
        assert resp.get_header("require") == "timer"

    def test_applies_local_default_without_offer(self) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(
            transport, _invite_raw(session_expires=None, supported=""), session_expires=900
        )
        transport.sent.clear()
        call.accept()

        assert call.session_interval == 900
        assert call.session_refresher_us is True
        resp = transport.sent[0][0]
        assert isinstance(resp, SipResponse)
        assert resp.get_header("session-expires") == "900;refresher=uas"
        # Caller never advertised timer support: no Require
        assert resp.get_header("require") is None

    def test_too_small_interval_rejected_422(self) -> None:
        transport = FakeTransport()
        uas = SipUAS(transport, session_expires=1800, min_se=90)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        transport.inject(_invite_raw(session_expires="30"))

        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 422
        assert resp.get_header("min-se") == "90"
        assert uas.get_call("st-call-1@example.com") is None

    def test_disabled_by_default(self) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(transport, _invite_raw(session_expires="1800"))
        transport.sent.clear()
        call.accept()

        assert call.session_interval is None
        resp = transport.sent[0][0]
        assert isinstance(resp, SipResponse)
        assert resp.get_header("session-expires") is None


class TestUasTimers:
    @pytest.mark.asyncio()
    async def test_refresher_sends_updates(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(
            transport, _invite_raw(session_expires="1"), session_expires=1, min_se=1
        )
        call.accept()
        transport.inject(_make_ack("st-call-1@example.com", "from-tag-1", call.dialog.local_tag))
        transport.sent.clear()

        await asyncio.sleep(0.05)

        updates = [
            m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "UPDATE"
        ]
        assert updates
        assert "refresher=uas" in (updates[0].get_header("session-expires") or "")
        call._stop_retransmissions()

    @pytest.mark.asyncio()
    async def test_watchdog_hangs_up_without_refresh(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(
            transport, _invite_raw(session_expires="1;refresher=uac"), session_expires=1, min_se=1
        )
        expired: list[IncomingCall] = []
        uas.on_session_expired = lambda c: expired.append(c)
        call.accept()
        transport.inject(_make_ack("st-call-1@example.com", "from-tag-1", call.dialog.local_tag))
        transport.sent.clear()

        await asyncio.sleep(0.08)

        assert expired == [call]
        byes = [m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "BYE"]
        assert len(byes) == 1
        assert uas.get_call("st-call-1@example.com") is None

    @pytest.mark.asyncio()
    async def test_incoming_update_rearms_watchdog(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uas, call = _uas_call(
            transport, _invite_raw(session_expires="1;refresher=uac"), session_expires=1, min_se=1
        )
        expired: list[IncomingCall] = []
        uas.on_session_expired = lambda c: expired.append(c)
        call.accept()
        transport.inject(_make_ack("st-call-1@example.com", "from-tag-1", call.dialog.local_tag))

        # Refresh twice before each deadline (deadline 0.04)
        for cseq, delay in ((2, 0.025), (3, 0.025)):
            await asyncio.sleep(delay)
            transport.inject(
                _make_update("st-call-1@example.com", "from-tag-1", call.dialog.local_tag, cseq)
            )

        assert not expired  # watchdog was re-armed each time
        await asyncio.sleep(0.06)
        assert expired == [call]  # then fired once refreshes stopped

    def test_refresher_falls_back_to_peer_without_update_support(self) -> None:
        raw = _invite_raw(session_expires="1800").replace(
            "Max-Forwards: 70\r\n", "Allow: INVITE, ACK, BYE, CANCEL\r\nMax-Forwards: 70\r\n"
        )
        transport = FakeTransport()
        uas, call = _uas_call(transport, raw, session_expires=1800)

        # We would have refreshed, but the peer cannot take UPDATEs
        assert call.session_refresher_us is False


def _answer_invite(
    transport: FakeTransport,
    uac: SipUAC,
    call: OutgoingCall,
    *,
    session_expires: str | None,
    allow: str | None = None,
) -> None:
    invite = call.invite
    se_line = f"Session-Expires: {session_expires}\r\n" if session_expires else ""
    allow_line = f"Allow: {allow}\r\n" if allow else ""
    raw = (
        "SIP/2.0 200 OK\r\n"
        f"Via: {invite.get_header('via')}\r\n"
        f"From: {invite.get_header('from')}\r\n"
        f"To: {invite.get_header('to')};tag=remote-tag\r\n"
        f"Call-ID: {invite.call_id}\r\n"
        f"CSeq: {invite.get_header('cseq')}\r\n"
        f"{se_line}{allow_line}"
        "Contact: <sip:alice@10.0.0.1:5060>\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    resp = SipMessage.parse(raw)
    assert isinstance(resp, SipResponse)
    uac.handle_response(resp, REMOTE_ADDR)


class TestUacSessionTimers:
    def test_invite_carries_session_headers(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR, session_expires=1800
        )
        assert call.invite.get_header("session-expires") == "1800"
        assert "timer" in (call.invite.get_header("supported") or "")

    def test_422_retries_with_min_se(self) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR, session_expires=90
        )
        transport.sent.clear()

        invite = call.invite
        raw = (
            "SIP/2.0 422 Session Interval Too Small\r\n"
            f"Via: {invite.get_header('via')}\r\n"
            f"From: {invite.get_header('from')}\r\n"
            f"To: {invite.get_header('to')}\r\n"
            f"Call-ID: {invite.call_id}\r\n"
            f"CSeq: {invite.get_header('cseq')}\r\n"
            "Min-SE: 600\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        resp = SipMessage.parse(raw)
        assert isinstance(resp, SipResponse)
        uac.handle_response(resp, REMOTE_ADDR)

        retry = transport.sent[0][0]
        assert isinstance(retry, SipRequest)
        assert retry.method == "INVITE"
        assert retry.get_header("session-expires") == "600"
        assert retry.get_header("min-se") == "600"
        assert not call._rejected.is_set()

    @pytest.mark.asyncio()
    async def test_uac_refresher_sends_updates(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR, session_expires=1
        )
        _answer_invite(transport, uac, call, session_expires="1;refresher=uac")
        transport.sent.clear()

        await asyncio.sleep(0.05)

        updates = [
            m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "UPDATE"
        ]
        assert updates
        call._cancel_session_timer()

    @pytest.mark.asyncio()
    async def test_uac_watchdog_sends_bye(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR, session_expires=1
        )
        expired: list[OutgoingCall] = []
        call.on_session_expired = lambda c: expired.append(c)
        _answer_invite(transport, uac, call, session_expires="1;refresher=uas")
        transport.sent.clear()

        await asyncio.sleep(0.08)

        assert expired == [call]
        byes = [m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "BYE"]
        assert len(byes) == 1

    @pytest.mark.asyncio()
    async def test_uac_refresh_falls_back_to_reinvite(self, fast_timers: None) -> None:
        from aiosipua.sdp import build_sdp

        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com",
            "sip:alice@example.com",
            REMOTE_ADDR,
            sdp_offer=build_sdp("10.0.0.2", 30000, 0, "PCMU"),
            session_expires=1,
        )
        _answer_invite(
            transport,
            uac,
            call,
            session_expires="1;refresher=uac",
            allow="INVITE, ACK, BYE, CANCEL",
        )
        transport.sent.clear()

        await asyncio.sleep(0.05)

        refreshes = [m for m, _ in transport.sent if isinstance(m, SipRequest)]
        assert refreshes
        assert refreshes[0].method == "INVITE"  # re-INVITE, not UPDATE
        call._cancel_session_timer()

    @pytest.mark.asyncio()
    async def test_no_timer_without_session_expires_in_answer(self, fast_timers: None) -> None:
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite(
            "sip:bob@example.com", "sip:alice@example.com", REMOTE_ADDR, session_expires=1
        )
        _answer_invite(transport, uac, call, session_expires=None)

        assert call._session_timer is None


class TestShutdownLifecycle:
    @pytest.mark.asyncio()
    async def test_uas_stop_cancels_uac_session_timers(self, fast_timers: None) -> None:
        """Stopping the UAS releases the timers of outbound calls too."""
        transport = FakeTransport()
        uac = SipUAC(transport)  # type: ignore[arg-type]
        uas = SipUAS(transport, uac=uac)  # type: ignore[arg-type]
        transport.on_message = uas._on_message

        call = uac.send_invite(
            "sip:caller@example.com", "sip:callee@example.com", REMOTE_ADDR, session_expires=1
        )
        _answer_invite(transport, uac, call, session_expires="1;refresher=uac")
        assert call._session_timer is not None

        await uas.stop()

        assert call._session_timer is None
