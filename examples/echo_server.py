#!/usr/bin/env python3
"""Echo server example — receives audio and sends it back.

Listens for incoming SIP calls on port 5080, negotiates the codec,
creates an RTP session, and echoes back any received audio.

Requirements:
    pip install aiosipua aiortp

Usage:
    python examples/echo_server.py
"""

from __future__ import annotations

import asyncio
import logging

from aiosipua import IncomingCall, SipUAS, negotiate_sdp
from aiosipua.rtp_bridge import CallSession
from aiosipua.transport import UdpSipTransport

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("echo_server")

LOCAL_IP = "0.0.0.0"
SIP_PORT = 5080
RTP_PORT_START = 20000

# Simple port counter (for demo; use aiortp.PortAllocator in production)
_next_rtp_port = RTP_PORT_START


def _allocate_rtp_port() -> int:
    global _next_rtp_port  # noqa: PLW0603
    port = _next_rtp_port
    _next_rtp_port += 2  # RTP + RTCP
    return port


# Track active sessions for cleanup
active_sessions: dict[str, CallSession] = {}


async def handle_invite(call: IncomingCall) -> None:
    """Handle an incoming INVITE — set up echo."""
    logger.info("Incoming call: %s -> %s", call.caller, call.callee)

    if call.sdp_offer is None:
        logger.warning("No SDP offer in INVITE, rejecting")
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

    # Accept the call with the SDP answer
    call.ringing()
    call.accept(session.sdp_answer)

    # Start RTP session
    await session.start()

    # Echo: send received audio back
    def on_audio(pcm: bytes, timestamp: int) -> None:
        session.send_audio_pcm(pcm, timestamp)

    session.on_audio = on_audio

    active_sessions[call.call_id] = session
    logger.info("Call %s established (codec PT=%d)", call.call_id, session.chosen_payload_type)


def handle_bye(call: IncomingCall, request: object) -> None:
    """Handle BYE — clean up RTP session."""
    call_id = call.call_id
    logger.info("Call ended: %s", call_id)

    session = active_sessions.pop(call_id, None)
    if session is not None:
        asyncio.get_running_loop().create_task(session.close())


async def main() -> None:
    transport = UdpSipTransport(local_addr=(LOCAL_IP, SIP_PORT))
    uas = SipUAS(transport)
    uas.on_invite = lambda call: asyncio.get_running_loop().create_task(handle_invite(call))
    uas.on_bye = handle_bye

    await uas.start()
    logger.info("Echo server listening on %s:%d", LOCAL_IP, SIP_PORT)

    # Run forever
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
