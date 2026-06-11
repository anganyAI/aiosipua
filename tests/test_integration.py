"""End-to-end integration: two endpoints over real UDP loopback sockets.

Caller (UAC + UAS for responses) talks to callee (UAS) on 127.0.0.1.
Covers the full call lifecycle: INVITE/180/200/ACK with rport-routed
responses, 2xx retransmission stopping on ACK, session-timer negotiation
(RFC 4028), blind transfer with REFER + NOTIFY progress (RFC 3515),
and BYE teardown.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from aiosipua.refer import notify_refer
from aiosipua.sdp import build_sdp, negotiate_sdp
from aiosipua.transport import UdpSipTransport
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS

if TYPE_CHECKING:
    from collections.abc import Callable

    from aiosipua.incoming_call import IncomingCall


async def _wait_for(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError("condition not met in time")
        await asyncio.sleep(0.005)


def _port(transport: UdpSipTransport) -> int:
    assert transport._udp_transport is not None
    sock = transport._udp_transport.get_extra_info("socket")
    return int(sock.getsockname()[1])


@pytest.mark.asyncio()
async def test_full_call_with_transfer_over_udp() -> None:
    # Callee: UAS with session timers enabled
    callee_transport = UdpSipTransport(local_addr=("127.0.0.1", 0))
    callee = SipUAS(callee_transport, user_agent="callee", session_expires=90)
    callee_calls: list[IncomingCall] = []
    callee_byes: list[str] = []
    callee_refers: list[str] = []

    def on_invite(call: IncomingCall) -> None:
        callee_calls.append(call)
        call.ringing()
        assert call.sdp_offer is not None
        answer, _pt = negotiate_sdp(call.sdp_offer, "127.0.0.1", 40002)
        call.accept(answer)

    callee.on_invite = on_invite
    callee.on_bye = lambda call, req: callee_byes.append(call.call_id)
    callee.on_refer = lambda call, uri: callee_refers.append(uri)
    await callee.start()

    # Caller: UAC plus a UAS to route responses and NOTIFYs
    caller_transport = UdpSipTransport(local_addr=("127.0.0.1", 0))
    caller_uac = SipUAC(caller_transport)
    caller = SipUAS(caller_transport, user_agent="caller", uac=caller_uac)
    progress: list[tuple[int, str]] = []
    caller.on_transfer_progress = lambda cid, status, reason: progress.append((status, reason))
    await caller.start()

    callee_addr = ("127.0.0.1", _port(callee_transport))

    try:
        # --- Call setup ---
        offer = build_sdp("127.0.0.1", 40000, 0, "PCMU")
        call = caller_uac.send_invite(
            "sip:caller@127.0.0.1",
            "sip:callee@127.0.0.1",
            callee_addr,
            sdp_offer=offer,
            session_expires=90,
        )
        await call.wait_answered(timeout=2.0)

        assert call.sdp_answer is not None
        audio = call.sdp_answer.audio
        assert audio is not None
        assert audio.port == 40002

        # Session timers negotiated on both sides
        assert call._session_timer is not None
        callee_call = callee_calls[0]
        assert callee_call.session_interval == 90

        # The ACK reaches the callee: dialog confirmed, 2xx retransmission stopped
        await _wait_for(lambda: callee_call.dialog.state.value == "confirmed")
        await _wait_for(lambda: callee_call._retrans_task is None)
        # Session timer armed on the callee once confirmed
        assert callee_call._session_timer is not None

        # --- Blind transfer ---
        caller_uac.send_refer(call.dialog, "sip:agent@127.0.0.1", callee_addr)

        # Callee got the REFER target; caller got the implicit NOTIFY 100
        await _wait_for(lambda: callee_refers == ["sip:agent@127.0.0.1"])
        await _wait_for(lambda: (100, "Trying") in progress)

        # Callee reports the transfer outcome
        notify_refer(callee_call, 200, "OK")
        await _wait_for(lambda: (200, "OK") in progress)

        # --- Teardown ---
        caller_uac.send_bye(call.dialog, callee_addr)
        await _wait_for(lambda: callee_byes == [callee_call.call_id])
        assert callee.get_call(callee_call.call_id) is None
        assert call._session_timer is None  # cancelled by the BYE
    finally:
        await caller.stop()
        await callee.stop()


@pytest.mark.asyncio()
async def test_lost_200_is_retransmitted_over_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    """The callee keeps retransmitting its 200 until the caller's ACK lands."""
    from aiosipua import transaction

    monkeypatch.setattr(transaction, "T1", 0.02)
    monkeypatch.setattr(transaction, "T2", 0.04)
    monkeypatch.setattr(transaction, "TIMER_H", 0.5)

    callee_transport = UdpSipTransport(local_addr=("127.0.0.1", 0))
    callee = SipUAS(callee_transport, user_agent="callee")
    accepted: list[IncomingCall] = []

    def on_invite(call: IncomingCall) -> None:
        accepted.append(call)
        call.accept()

    callee.on_invite = on_invite
    await callee.start()

    caller_transport = UdpSipTransport(local_addr=("127.0.0.1", 0))
    caller_uac = SipUAC(caller_transport)
    caller = SipUAS(caller_transport, uac=caller_uac)
    await caller.start()

    try:
        call = caller_uac.send_invite(
            "sip:caller@127.0.0.1",
            "sip:callee@127.0.0.1",
            ("127.0.0.1", _port(callee_transport)),
        )
        await call.wait_answered(timeout=2.0)

        # Retransmissions were armed on the callee and stopped by our ACK
        callee_call = accepted[0]
        await _wait_for(lambda: callee_call._retrans_task is None)
        assert callee.retransmit_2xx is True  # UDP default
    finally:
        await caller.stop()
        await callee.stop()
