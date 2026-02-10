#!/usr/bin/env python3
"""DTMF IVR example — collect digits from caller.

Listens for incoming SIP calls, establishes media, and collects
DTMF digits.  Demonstrates the on_dtmf callback and basic IVR flow.

Requirements:
    pip install aiosipua aiortp

Usage:
    python examples/dtmf_ivr.py
"""

from __future__ import annotations

import asyncio
import logging

from aiosipua import IncomingCall, SipUAS
from aiosipua.rtp_bridge import CallSession
from aiosipua.transport import UdpSipTransport
from aiosipua.uac import SipUAC

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("dtmf_ivr")

LOCAL_IP = "0.0.0.0"
SIP_PORT = 5080
RTP_PORT_START = 22000

_next_rtp_port = RTP_PORT_START

active_sessions: dict[str, CallSession] = {}
active_calls: dict[str, IncomingCall] = {}
digit_buffers: dict[str, list[str]] = {}


def _allocate_rtp_port() -> int:
    global _next_rtp_port  # noqa: PLW0603
    port = _next_rtp_port
    _next_rtp_port += 2
    return port


async def handle_invite(call: IncomingCall) -> None:
    """Handle incoming call — set up DTMF collection."""
    logger.info("IVR call: %s -> %s", call.caller, call.callee)

    if call.sdp_offer is None:
        call.reject(488, "Not Acceptable Here")
        return

    rtp_port = _allocate_rtp_port()

    try:
        session = CallSession(
            local_ip=LOCAL_IP,
            rtp_port=rtp_port,
            offer=call.sdp_offer,
        )
    except Exception:
        logger.exception("SDP negotiation failed")
        call.reject(488, "Not Acceptable Here")
        return

    call.ringing()
    call.accept(session.sdp_answer)

    await session.start()

    call_id = call.call_id
    active_sessions[call_id] = session
    active_calls[call_id] = call
    digit_buffers[call_id] = []

    def on_dtmf(digit: str, duration: int) -> None:
        logger.info("DTMF digit received: %s (duration=%dms) on call %s", digit, duration, call_id)
        digit_buffers[call_id].append(digit)

        # Example: hang up after '#' is pressed
        if digit == "#":
            collected = "".join(digit_buffers[call_id][:-1])  # exclude '#'
            logger.info("Collected digits: %s", collected)
            # Trigger hangup
            asyncio.get_running_loop().create_task(_hangup(call_id))

    session.on_dtmf = on_dtmf
    logger.info("IVR ready on call %s — press digits, # to finish", call_id)


async def _hangup(call_id: str) -> None:
    """Hang up a call and clean up."""
    call = active_calls.pop(call_id, None)
    session = active_sessions.pop(call_id, None)
    digit_buffers.pop(call_id, None)

    if session is not None:
        await session.close()
    if call is not None:
        call.hangup()

    logger.info("Call %s hung up", call_id)


def handle_bye(call: IncomingCall, request: object) -> None:
    """Handle remote BYE."""
    call_id = call.call_id
    logger.info("Remote hangup: %s", call_id)

    session = active_sessions.pop(call_id, None)
    active_calls.pop(call_id, None)
    digit_buffers.pop(call_id, None)

    if session is not None:
        asyncio.get_running_loop().create_task(session.close())


async def main() -> None:
    transport = UdpSipTransport(local_addr=(LOCAL_IP, SIP_PORT))
    uas = SipUAS(transport)
    uas.on_invite = lambda call: asyncio.get_running_loop().create_task(handle_invite(call))
    uas.on_bye = handle_bye

    await uas.start()
    logger.info("DTMF IVR listening on %s:%d", LOCAL_IP, SIP_PORT)

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
