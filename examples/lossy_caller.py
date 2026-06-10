#!/usr/bin/env python3
"""Lossy SIP caller — dials an agent and streams a tone with controlled packet loss.

The mirror of echo_server.py: instead of answering calls, it places one.
Outbound RTP datagrams are dropped at the transport layer according to
configurable patterns (random rate plus periodic bursts).  Sequence
numbers and timestamps advance normally — the datagrams simply never
leave — so the receiver sees genuine wire loss, reproducibly and
without any OS network tricks (tc/dummynet).

Built to exercise packet loss concealment (PLC) in the receiving agent,
e.g. roomkit's ``examples/voice_sip_packet_loss.py``:

    # terminal 1 — the agent under test (roomkit)
    uv run python examples/voice_sip_packet_loss.py

    # terminal 2 — this caller (5% random loss + a 100 ms burst every 10 s)
    python examples/lossy_caller.py --host 127.0.0.1 --port 5060

The receiver's ``concealed=N`` stats should track this script's
``dropped`` counter (tail losses right before hangup may go unconfirmed).

Two properties the receiver must honour, both exercised here:

- bursts longer than the concealment fade (100 ms > 60 ms) are filled
  with silence, not synthetic audio — listen for the fade-outs
- DTMF digits pause the tone (timestamp jump, no sequence gap) and the
  digits themselves are never dropped — ``concealed`` must NOT increase
  during digits

Requirements:
    pip install aiosipua aiortp

Usage:
    python examples/lossy_caller.py [--host H] [--port P] [--rate 0.05]
        [--burst-every 10] [--burst-packets 5] [--dtmf-every 10]
        [--duration 30]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import math
import random
import struct
import time

from aiosipua import SipUAC, SipUAS, build_sdp
from aiosipua.rtp_bridge import CallSession
from aiosipua.transport import UdpSipTransport

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("lossy_caller")

LOCAL_SIP_PORT = 5082
LOCAL_RTP_PORT = 21000
PT_PCMU = 0
DTMF_PT = 101
SAMPLE_RATE = 8000
FRAME_SAMPLES = 160  # 20 ms
TONE_HZ = 440
TONE_AMPLITUDE = 12000


class PacketDropper:
    """Decides which outbound RTP datagrams to drop.

    Random loss at *rate*, plus a burst of *burst_packets* consecutive
    drops every *burst_every* seconds.  DTMF packets are never dropped.
    """

    def __init__(self, rate: float, burst_every: float, burst_packets: int) -> None:
        self._rate = rate
        self._burst_every = burst_every
        self._burst_packets = burst_packets
        self._burst_left = 0
        self._next_burst = time.monotonic() + burst_every if burst_every > 0 else None
        self.sent = 0
        self.dropped = 0

    def should_drop(self, data: bytes) -> bool:
        if (data[1] & 0x7F) == DTMF_PT:
            return False
        now = time.monotonic()
        if self._next_burst is not None and now >= self._next_burst:
            self._burst_left = self._burst_packets
            self._next_burst = now + self._burst_every
        if self._burst_left > 0:
            self._burst_left -= 1
            return True
        return random.random() < self._rate  # noqa: S311 — test tool


def install_loss(session: CallSession, dropper: PacketDropper) -> None:
    """Wrap the aiortp RTP transport so selected datagrams never leave.

    Reaches into the RTPSession internals — acceptable for a test tool.
    """
    transport = session.rtp_session._rtp_transport  # noqa: SLF001
    real_send = transport.send

    def lossy_send(data: bytes, addr: tuple[str, int] | None = None) -> None:
        if dropper.should_drop(data):
            dropper.dropped += 1
            return
        dropper.sent += 1
        real_send(data, addr)

    transport.send = lossy_send  # type: ignore[method-assign]


def tone_frame(frame_index: int) -> bytes:
    """One 20 ms frame of a continuous sine tone (s16le, phase-exact)."""
    base = frame_index * FRAME_SAMPLES
    step = 2 * math.pi * TONE_HZ / SAMPLE_RATE
    return struct.pack(
        f"<{FRAME_SAMPLES}h",
        *(int(TONE_AMPLITUDE * math.sin((base + i) * step)) for i in range(FRAME_SAMPLES)),
    )


async def stream_tone(
    session: CallSession,
    dropper: PacketDropper,
    duration: float,
    dtmf_every: float,
    stop: asyncio.Event,
) -> None:
    """Stream the tone for *duration* seconds, paced at 20 ms wall-clock."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    next_dtmf = dtmf_every if dtmf_every > 0 else None
    pause_until = 0.0
    frame_index = 0
    digit = 0

    while not stop.is_set():
        elapsed = loop.time() - start
        if elapsed >= duration:
            break

        if next_dtmf is not None and elapsed >= next_dtmf:
            digit = (digit % 9) + 1
            logger.info("Sending DTMF %d (tone paused — must NOT be concealed)", digit)
            session.send_dtmf(str(digit))
            pause_until = elapsed + 0.4
            next_dtmf += dtmf_every

        # During the DTMF pause the timestamp keeps advancing but nothing
        # is sent: a sender pause, not packet loss.
        if elapsed >= pause_until:
            session.send_audio_pcm(tone_frame(frame_index), frame_index * FRAME_SAMPLES)

        frame_index += 1
        target = start + frame_index * 0.02
        await asyncio.sleep(max(0.0, target - loop.time()))

        if frame_index % 250 == 0:  # every 5 s
            logger.info("RTP sent=%d dropped=%d", dropper.sent, dropper.dropped)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="SIP host of the agent under test")
    parser.add_argument("--port", type=int, default=5060, help="SIP port of the agent")
    parser.add_argument("--local-ip", default="127.0.0.1", help="local IP for SDP/RTP")
    parser.add_argument("--rate", type=float, default=0.05, help="random loss rate (0-1)")
    parser.add_argument("--burst-every", type=float, default=10.0, help="seconds between bursts")
    parser.add_argument("--burst-packets", type=int, default=5, help="packets per burst (5=100ms)")
    parser.add_argument("--dtmf-every", type=float, default=10.0, help="seconds between digits")
    parser.add_argument("--duration", type=float, default=30.0, help="call duration in seconds")
    args = parser.parse_args()

    transport = UdpSipTransport(local_addr=(args.local_ip, LOCAL_SIP_PORT))
    uac = SipUAC(transport)
    uas = SipUAS(transport, uac=uac)  # routes responses to the UAC, handles BYE

    stop = asyncio.Event()
    uas.on_bye = lambda call, request: stop.set()
    await uas.start()

    offer = build_sdp(
        local_ip=args.local_ip,
        rtp_port=LOCAL_RTP_PORT,
        payload_type=PT_PCMU,
        codec_name="PCMU",
        sample_rate=SAMPLE_RATE,
    )
    to_uri = f"sip:agent@{args.host}:{args.port}"
    from_uri = f"sip:lossy-caller@{args.local_ip}:{LOCAL_SIP_PORT}"

    logger.info("Dialing %s (loss=%.0f%%, burst=%d pkts every %.0fs)",
                to_uri, args.rate * 100, args.burst_packets, args.burst_every)
    call = uac.send_invite(from_uri, to_uri, (args.host, args.port), sdp_offer=offer)
    await call.wait_answered()

    session = CallSession(
        local_ip=args.local_ip,
        rtp_port=LOCAL_RTP_PORT,
        offer=call.sdp_answer,
        supported_codecs=[PT_PCMU],
    )
    await session.start()

    dropper = PacketDropper(args.rate, args.burst_every, args.burst_packets)
    install_loss(session, dropper)
    logger.info("Call established — streaming %d Hz tone for %.0fs", TONE_HZ, args.duration)

    try:
        await stream_tone(session, dropper, args.duration, args.dtmf_every, stop)
    finally:
        call.hangup(uac)
        await session.close()
        await uas.stop()

    total = dropper.sent + dropper.dropped
    logger.info(
        "Done — sent=%d dropped=%d (%.1f%%).  The receiver's concealed counter "
        "should be close to %d (tail losses before hangup may go unconfirmed).",
        dropper.sent, dropper.dropped,
        100 * dropper.dropped / total if total else 0.0,
        dropper.dropped,
    )


if __name__ == "__main__":
    asyncio.run(main())
