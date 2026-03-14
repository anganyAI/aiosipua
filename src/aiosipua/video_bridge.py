"""Bridge between SIP signaling (aiosipua) and video RTP media (aiortp).

Provides :class:`VideoCallSession` which manages the full lifecycle of a
video call: SDP negotiation, video RTP session creation, frame handling,
and cleanup.

Requires the optional ``aiortp`` dependency::

    pip install aiortp
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from .rtp_bridge import _BaseCallSession, _import_aiortp
from .sdp_video import negotiate_video_sdp

if TYPE_CHECKING:
    from .sdp import SdpMessage


class VideoCallSession(_BaseCallSession):
    """Manages a single call's video RTP session alongside its SIP dialog.

    Bridges :func:`negotiate_video_sdp` to ``aiortp.VideoRTPSession.create()``,
    providing a unified interface for video frame handling.

    Usage::

        session = VideoCallSession(
            local_ip="10.0.0.5",
            rtp_port=20002,
            offer=call.sdp_offer,
        )
        await session.start()

        session.on_frame = lambda nal, ts, kf: process_video(nal, ts, kf)
        session.on_keyframe_needed = lambda: encoder.force_keyframe()

        # Later...
        await session.close()
    """

    def __init__(
        self,
        local_ip: str,
        rtp_port: int,
        offer: SdpMessage,
        *,
        supported_video_codecs: list[str] | None = None,
        session_id: str | None = None,
        session_name: str = "-",
        jitter_capacity: int = 128,
    ) -> None:
        sdp_answer, chosen_pt = negotiate_video_sdp(
            offer=offer,
            local_ip=local_ip,
            video_rtp_port=rtp_port,
            supported_video_codecs=supported_video_codecs,
            session_id=session_id,
            session_name=session_name,
        )

        rtp_addr = offer.video_rtp_address
        if rtp_addr is None:
            raise ValueError("SDP offer has no video RTP address (missing c= or m= video)")

        super().__init__(local_ip, rtp_port, rtp_addr, sdp_answer, chosen_pt)

        self._clock_rate: int = 90000
        self._jitter_capacity = jitter_capacity

        self.on_frame: Callable[[bytes, int, bool], None] | None = None
        """Called with (nal_data, timestamp, is_keyframe)."""

        self.on_keyframe_needed: Callable[[], None] | None = None
        """Called when remote requests a keyframe via RTCP PLI."""

    @property
    def video_session(self) -> Any:
        """The underlying ``aiortp.VideoRTPSession``, or ``None`` before start."""
        return self._session

    @property
    def clock_rate(self) -> int:
        """RTP clock rate (90000 for H.264/VP8/VP9)."""
        return self._clock_rate

    async def start(self) -> None:
        """Create and bind the aiortp VideoRTPSession."""
        aiortp = _import_aiortp()

        # Determine clock rate and codec name from SDP answer
        clock_rate = 90000
        codec_name = "h264"
        video = self._sdp_answer.video
        if video is not None:
            for codec in video.codecs:
                if codec.payload_type == self._chosen_pt:
                    if codec.clock_rate > 0:
                        clock_rate = codec.clock_rate
                    codec_name = codec.encoding_name.lower()
                    break

        self._clock_rate = clock_rate

        self._session = await aiortp.VideoRTPSession.create(
            local_addr=(self._local_ip, self._rtp_port),
            remote_addr=self._remote_addr,
            payload_type=self._chosen_pt,
            clock_rate=clock_rate,
            jitter_capacity=self._jitter_capacity,
            codec=codec_name,
        )

        # Wire callbacks
        self._session.on_frame = self._handle_frame
        self._session.on_keyframe_needed = self._handle_keyframe_needed

    def _handle_frame(self, nal_data: bytes, timestamp: int, is_keyframe: bool) -> None:
        if self.on_frame is not None:
            self.on_frame(nal_data, timestamp, is_keyframe)

    def _handle_keyframe_needed(self) -> None:
        if self.on_keyframe_needed is not None:
            self.on_keyframe_needed()

    def send_frame(self, nal_units: list[bytes], timestamp: int, keyframe: bool = False) -> None:
        """Packetize and send video NAL units via RTP."""
        if self._session is not None and not self._closed:
            self._session.send_frame(nal_units, timestamp, keyframe)

    def request_keyframe(self) -> None:
        """Request a keyframe from the remote via RTCP PLI."""
        if self._session is not None and not self._closed:
            self._session.request_keyframe()
