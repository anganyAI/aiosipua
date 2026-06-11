"""Tests for 2xx retransmission until ACK (RFC 3261 §13.3.1.4)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiosipua import transaction
from aiosipua.message import SipResponse
from aiosipua.transport import TcpSipTransport, UdpSipTransport
from aiosipua.uas import SipUAS
from tests.support import FakeTransport

if TYPE_CHECKING:
    from aiosipua.incoming_call import IncomingCall


INVITE_RAW = (
    "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-rtx-1;rport\r\n"
    "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: rtx-call-1@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


def _make_ack(call_id: str, from_tag: str, to_tag: str) -> str:
    return (
        "ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-rtx-ack\r\n"
        f"From: <sip:alice@example.com>;tag={from_tag}\r\n"
        f"To: <sip:bob@example.com>;tag={to_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


@pytest.fixture()
def fast_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transaction, "T1", 0.01)
    monkeypatch.setattr(transaction, "T2", 0.02)
    monkeypatch.setattr(transaction, "TIMER_H", 0.06)


def _accepted_call(transport: FakeTransport, **uas_kwargs: object) -> tuple[SipUAS, IncomingCall]:
    uas = SipUAS(transport, **uas_kwargs)  # type: ignore[arg-type]
    calls: list[IncomingCall] = []
    uas.on_invite = lambda call: calls.append(call)
    transport.on_message = uas._on_message
    transport.inject(INVITE_RAW)
    call = calls[0]
    call.accept()
    return uas, call


def _count_200(transport: FakeTransport) -> int:
    return len(
        [m for m, _ in transport.sent if isinstance(m, SipResponse) and m.status_code == 200]
    )


@pytest.mark.asyncio()
async def test_200_retransmitted_until_ack(fast_timers: None) -> None:
    transport = FakeTransport()
    uas, call = _accepted_call(transport, retransmit_2xx=True)

    await asyncio.sleep(0.035)
    assert _count_200(transport) > 1  # initial send + retransmissions

    transport.inject(_make_ack("rtx-call-1@example.com", "from-tag-1", call.dialog.local_tag))
    assert call._retrans_task is None

    sent_after_ack = _count_200(transport)
    await asyncio.sleep(0.05)
    assert _count_200(transport) == sent_after_ack  # silence after ACK


@pytest.mark.asyncio()
async def test_ack_timeout_releases_call(fast_timers: None) -> None:
    transport = FakeTransport()
    timeouts: list[IncomingCall] = []
    uas, call = _accepted_call(transport, retransmit_2xx=True)
    uas.on_ack_timeout = lambda c: timeouts.append(c)

    await asyncio.sleep(0.15)

    assert timeouts == [call]
    assert call.dialog.state.value == "terminated"
    assert uas.get_call("rtx-call-1@example.com") is None


@pytest.mark.asyncio()
async def test_no_retransmission_when_disabled(fast_timers: None) -> None:
    transport = FakeTransport()
    uas, call = _accepted_call(transport, retransmit_2xx=False)

    assert call._retrans_task is None
    await asyncio.sleep(0.05)
    assert _count_200(transport) == 1  # only the initial 200


@pytest.mark.asyncio()
async def test_bye_stops_retransmission(fast_timers: None) -> None:
    transport = FakeTransport()
    uas, call = _accepted_call(transport, retransmit_2xx=True)

    bye_raw = (
        "BYE sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-rtx-bye\r\n"
        "From: <sip:alice@example.com>;tag=from-tag-1\r\n"
        f"To: <sip:bob@example.com>;tag={call.dialog.local_tag}\r\n"
        "Call-ID: rtx-call-1@example.com\r\n"
        "CSeq: 2 BYE\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    transport.inject(bye_raw)

    assert call._retrans_task is None


@pytest.mark.asyncio()
async def test_stop_cancels_retransmission(fast_timers: None) -> None:
    transport = FakeTransport()
    uas, call = _accepted_call(transport, retransmit_2xx=True)
    task = call._retrans_task
    assert task is not None

    await uas.stop()

    assert call._retrans_task is None
    await asyncio.sleep(0)
    assert task.cancelled()


def test_default_follows_transport_reliability() -> None:
    assert SipUAS(UdpSipTransport()).retransmit_2xx is True
    assert SipUAS(TcpSipTransport()).retransmit_2xx is False
    # Explicit override wins
    assert SipUAS(UdpSipTransport(), retransmit_2xx=False).retransmit_2xx is False
    # Duck-typed transports without a reliable flag default to no retransmission
    assert SipUAS(FakeTransport()).retransmit_2xx is False  # type: ignore[arg-type]
