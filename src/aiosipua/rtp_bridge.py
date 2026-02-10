"""Bridge between SIP signaling (aiosipua) and RTP media (aiortp).

Provides :class:`CallSession` which manages the full lifecycle of a call:
SDP negotiation, RTP session creation, audio/DTMF callbacks, and cleanup.

Requires the optional ``aiortp`` dependency::

    pip install aiortp
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from .sdp import SdpMessage, negotiate_sdp

logger = logging.getLogger(__name__)


def _import_aiortp() -> Any:
    """Lazily import aiortp, raising a clear error if not installed."""
    try:
        import aiortp  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "aiortp is required for RTP integration. Install it with: pip install aiortp"
        ) from exc
    return aiortp


class CallSession:
    """Manages a single call's RTP session alongside its SIP dialog.

    Bridges the output of :func:`negotiate_sdp` to ``aiortp.RTPSession.create()``,
    providing a unified interface for audio and DTMF handling.

    Usage::

        session = CallSession(
            local_ip="10.0.0.5",
            rtp_port=20000,
            offer=call.sdp_offer,
        )
        await session.start()

        session.on_audio = lambda pcm, ts: process_audio(pcm, ts)
        session.on_dtmf = lambda digit, duration: handle_digit(digit, duration)

        # Later...
        await session.close()
    """

    def __init__(
        self,
        local_ip: str,
        rtp_port: int,
        offer: SdpMessage,
        *,
        supported_codecs: list[int] | None = None,
        dtmf_payload_type: int = 101,
        ptime: int = 20,
        session_id: str | None = None,
    ) -> None:
        self._local_ip = local_ip
        self._rtp_port = rtp_port
        self._offer = offer

        # Negotiate SDP upfront
        self._sdp_answer, self._chosen_pt = negotiate_sdp(
            offer=offer,
            local_ip=local_ip,
            rtp_port=rtp_port,
            supported_codecs=supported_codecs,
            dtmf_payload_type=dtmf_payload_type,
            ptime=ptime,
            session_id=session_id,
        )

        # Extract remote RTP address from the offer
        rtp_addr = offer.rtp_address
        if rtp_addr is None:
            raise ValueError("SDP offer has no RTP address (missing c= or m= audio)")
        self._remote_addr = rtp_addr

        # RTP session (created in start())
        self._rtp_session: Any = None
        self._clock_rate: int = 8000
        self._dtmf_payload_type = dtmf_payload_type
        self._closed = False

        # User callbacks
        self.on_audio: Callable[[bytes, int], None] | None = None
        self.on_dtmf: Callable[[str, int], None] | None = None

    @property
    def sdp_answer(self) -> SdpMessage:
        """The negotiated SDP answer to include in the 200 OK."""
        return self._sdp_answer

    @property
    def chosen_payload_type(self) -> int:
        """The chosen codec payload type from negotiation."""
        return self._chosen_pt

    @property
    def remote_addr(self) -> tuple[str, int]:
        """The remote RTP address from the SDP offer."""
        return self._remote_addr

    @property
    def rtp_session(self) -> Any:
        """The underlying ``aiortp.RTPSession``, or ``None`` before :meth:`start`."""
        return self._rtp_session

    @property
    def stats(self) -> dict[str, Any]:
        """RTP session statistics, or empty dict if not started."""
        if self._rtp_session is not None:
            return self._rtp_session.stats  # type: ignore[no-any-return]
        return {}

    @property
    def codec_sample_rate(self) -> int:
        """Actual audio sample rate of the negotiated codec.

        For G.722, this returns 16000 (not the 8000 RTP clock rate).
        Only available after start().
        """
        if self._rtp_session is not None and self._rtp_session.codec is not None:
            return self._rtp_session.codec.sample_rate  # type: ignore[no-any-return]
        return 8000

    @property
    def clock_rate(self) -> int:
        """RTP clock rate from SDP negotiation.

        For G.722, this returns 8000 (historical RFC 3551 quirk).
        """
        return self._clock_rate

    async def start(self) -> None:
        """Create and bind the aiortp RTPSession.

        Raises:
            ImportError: If ``aiortp`` is not installed.
        """
        aiortp = _import_aiortp()

        # Determine clock rate from the chosen codec
        clock_rate = 8000
        audio = self._sdp_answer.audio
        if audio is not None:
            for codec in audio.codecs:
                if codec.payload_type == self._chosen_pt and codec.clock_rate > 0:
                    clock_rate = codec.clock_rate
                    break

        self._clock_rate = clock_rate

        self._rtp_session = await aiortp.RTPSession.create(
            local_addr=(self._local_ip, self._rtp_port),
            remote_addr=self._remote_addr,
            payload_type=self._chosen_pt,
            clock_rate=clock_rate,
            dtmf_payload_type=self._dtmf_payload_type,
        )

        # Wire up callbacks
        self._rtp_session.on_audio = self._handle_audio
        self._rtp_session.on_dtmf = self._handle_dtmf

    def _handle_audio(self, pcm: bytes, timestamp: int) -> None:
        """Forward decoded audio to user callback."""
        if self.on_audio is not None:
            self.on_audio(pcm, timestamp)

    def _handle_dtmf(self, digit: str, duration: int) -> None:
        """Forward DTMF event to user callback."""
        if self.on_dtmf is not None:
            self.on_dtmf(digit, duration)

    def send_audio(self, payload: bytes, timestamp: int) -> None:
        """Send encoded audio payload via RTP."""
        if self._rtp_session is not None and not self._closed:
            self._rtp_session.send_audio(payload, timestamp)

    def send_audio_pcm(self, pcm: bytes, timestamp: int) -> None:
        """Send raw PCM audio, encoding with the negotiated codec."""
        if self._rtp_session is not None and not self._closed:
            self._rtp_session.send_audio_pcm(pcm, timestamp)

    def send_dtmf(self, digit: str, duration_ms: int = 160) -> None:
        """Send a DTMF digit via RTP telephone-event."""
        if self._rtp_session is not None and not self._closed:
            self._rtp_session.send_dtmf(digit, duration_ms)

    def update_remote(self, addr: tuple[str, int]) -> None:
        """Update the remote RTP address (e.g. after re-INVITE)."""
        self._remote_addr = addr
        if self._rtp_session is not None:
            self._rtp_session.update_remote(addr)

    async def close(self) -> None:
        """Close the RTP session and release resources."""
        if self._closed:
            return
        self._closed = True

        if self._rtp_session is not None:
            await self._rtp_session.close()
            self._rtp_session = None
