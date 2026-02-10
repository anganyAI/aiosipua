#!/usr/bin/env python3
"""RoomKit VoiceBackend integration prototype.

Shows how aiosipua + aiortp integrate with a voice AI backend:
SIP signaling → SDP negotiation → RTP session → audio pipeline
(ASR, TTS, LLM, room orchestration).

This is a prototype/skeleton — the actual VoiceBackend is not included.
It demonstrates the integration pattern and X-header extraction for
application metadata (room ID, session ID, tenant, language).

Requirements:
    pip install aiosipua aiortp

Usage:
    python examples/roomkit_prototype.py
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from aiosipua import IncomingCall, SipUAS
from aiosipua.rtp_bridge import CallSession
from aiosipua.transport import UdpSipTransport

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("roomkit")

LOCAL_IP = "0.0.0.0"
SIP_PORT = 5080
RTP_PORT_START = 24000

_next_rtp_port = RTP_PORT_START


def _allocate_rtp_port() -> int:
    global _next_rtp_port  # noqa: PLW0603
    port = _next_rtp_port
    _next_rtp_port += 2
    return port


# --- Placeholder VoiceBackend ---


@dataclass
class VoiceRoom:
    """Placeholder for a voice AI room."""

    room_id: str
    session_id: str
    tenant_id: str
    language: str
    rtp_session: CallSession
    audio_chunks: list[bytes] = field(default_factory=list, repr=False)

    async def process_audio(self, pcm: bytes, timestamp: int) -> None:
        """Process incoming audio (send to ASR, etc.)."""
        self.audio_chunks.append(pcm)
        # In production: stream to ASR, get transcript, feed to LLM,
        # generate TTS response, send back via rtp_session.send_audio_pcm()

    async def close(self) -> None:
        """Shut down the room."""
        logger.info("Room %s closed (%d audio chunks received)", self.room_id, len(self.audio_chunks))


# --- Active rooms ---

active_rooms: dict[str, VoiceRoom] = {}
active_calls: dict[str, IncomingCall] = {}


async def handle_invite(call: IncomingCall) -> None:
    """Handle incoming call with RoomKit metadata."""
    logger.info("Incoming call: %s -> %s", call.caller, call.callee)

    # Extract application metadata from X-headers
    room_id = call.room_id or "default"
    session_id = call.session_id or "unknown"
    x_headers = call.x_headers
    tenant_id = x_headers.get("X-RoomKit-Tenant-ID", "default")
    language = x_headers.get("X-RoomKit-Language", "fr")

    logger.info(
        "Room: %s, Session: %s, Tenant: %s, Language: %s",
        room_id, session_id, tenant_id, language,
    )

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

    # Accept the call
    call.ringing()
    call.accept(session.sdp_answer)
    await session.start()

    # Create voice room
    room = VoiceRoom(
        room_id=room_id,
        session_id=session_id,
        tenant_id=tenant_id,
        language=language,
        rtp_session=session,
    )

    # Wire audio to room processing
    def on_audio(pcm: bytes, timestamp: int) -> None:
        asyncio.get_running_loop().create_task(room.process_audio(pcm, timestamp))

    def on_dtmf(digit: str, duration: int) -> None:
        logger.info("DTMF in room %s: %s", room_id, digit)

    session.on_audio = on_audio
    session.on_dtmf = on_dtmf

    call_id = call.call_id
    active_rooms[call_id] = room
    active_calls[call_id] = call

    logger.info("Room %s active on call %s", room_id, call_id)


def handle_bye(call: IncomingCall, request: object) -> None:
    """Handle remote BYE — clean up room."""
    call_id = call.call_id
    logger.info("Call ended: %s", call_id)

    room = active_rooms.pop(call_id, None)
    active_calls.pop(call_id, None)

    if room is not None:
        asyncio.get_running_loop().create_task(_cleanup_room(room))


async def _cleanup_room(room: VoiceRoom) -> None:
    """Clean up RTP session and voice room."""
    await room.rtp_session.close()
    await room.close()


async def main() -> None:
    transport = UdpSipTransport(local_addr=(LOCAL_IP, SIP_PORT))
    uas = SipUAS(transport)
    uas.on_invite = lambda call: asyncio.get_running_loop().create_task(handle_invite(call))
    uas.on_bye = handle_bye

    await uas.start()
    logger.info("RoomKit prototype listening on %s:%d", LOCAL_IP, SIP_PORT)

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
