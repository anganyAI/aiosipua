"""Tests for VideoCallSession."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aiosipua.sdp import SdpNegotiationError, parse_sdp
from aiosipua.video_bridge import VideoCallSession

# --- Test SDP offers ---

VIDEO_SDP = (
    "v=0\r\n"
    "o=- 1234 1234 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=video 20002 RTP/AVP 96 97\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 profile-level-id=42e01f\r\n"
    "a=rtpmap:97 VP8/90000\r\n"
    "a=sendrecv\r\n"
)

AV_SDP = (
    "v=0\r\n"
    "o=- 5678 5678 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
    "m=video 20002 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=sendrecv\r\n"
)


class TestVideoCallSessionNegotiation:
    def test_basic_negotiation(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(
            local_ip="10.0.0.5",
            rtp_port=30002,
            offer=offer,
        )

        assert session.chosen_payload_type == 96  # H264
        assert session.remote_addr == ("10.0.0.1", 20002)

        answer = session.sdp_answer
        assert answer.video is not None
        assert answer.video.port == 30002

    def test_custom_supported_codecs(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(
            local_ip="10.0.0.5",
            rtp_port=30002,
            offer=offer,
            supported_video_codecs=["VP8"],
        )
        assert session.chosen_payload_type == 97  # VP8

    def test_no_video_raises(self) -> None:
        audio_only = parse_sdp(
            "v=0\r\n"
            "o=- 1 1 IN IP4 10.0.0.1\r\n"
            "s=-\r\n"
            "c=IN IP4 10.0.0.1\r\n"
            "t=0 0\r\n"
            "m=audio 20000 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        with pytest.raises(SdpNegotiationError):
            VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=audio_only)

    def test_no_rtp_address_raises(self) -> None:
        sdp = parse_sdp(
            "v=0\r\n"
            "o=- 1 1 IN IP4 0.0.0.0\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "m=video 20002 RTP/AVP 96\r\n"
            "a=rtpmap:96 H264/90000\r\n"
        )
        with pytest.raises(ValueError, match="no video RTP address"):
            VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=sdp)


class TestVideoCallSessionProperties:
    def test_video_session_none_before_start(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)
        assert session.video_session is None

    def test_stats_empty_before_start(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)
        assert session.stats == {}

    def test_clock_rate_default(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)
        assert session.clock_rate == 90000


class TestVideoCallSessionCallbacks:
    def test_frame_callback(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        received: list[tuple[bytes, int, bool]] = []
        session.on_frame = lambda nal, ts, kf: received.append((nal, ts, kf))

        session._handle_frame(b"\x65\x00", 90000, True)
        assert len(received) == 1
        assert received[0] == (b"\x65\x00", 90000, True)

    def test_keyframe_needed_callback(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        called = []
        session.on_keyframe_needed = lambda: called.append(True)

        session._handle_keyframe_needed()
        assert len(called) == 1

    def test_no_callback_no_error(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        session._handle_frame(b"\x00", 0, False)
        session._handle_keyframe_needed()


class TestVideoCallSessionSendMethods:
    def test_send_frame_before_start(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)
        session.send_frame([b"\x65\x00"], 90000)  # no-op, no raise

    def test_request_keyframe_before_start(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)
        session.request_keyframe()  # no-op, no raise

    def test_update_remote(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        assert session.remote_addr == ("10.0.0.1", 20002)
        session.update_remote(("10.0.0.99", 25002))
        assert session.remote_addr == ("10.0.0.99", 25002)


class TestVideoCallSessionUpdateRemoteActive:
    @pytest.mark.asyncio()
    async def test_update_remote_forwards_to_video_session(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        mock_video = MagicMock()
        mock_video.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.VideoRTPSession.create = AsyncMock(return_value=mock_video)

        with patch("aiosipua.video_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        session.update_remote(("10.0.0.99", 25002))
        assert session.remote_addr == ("10.0.0.99", 25002)
        mock_video.update_remote.assert_called_once_with(("10.0.0.99", 25002))


class TestVideoCallSessionWithMockedAiortp:
    @pytest.mark.asyncio()
    async def test_start_creates_video_session(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        mock_video = MagicMock()
        mock_video.stats = {"ssrc": 54321, "packets_sent": 0}

        mock_aiortp = MagicMock()
        mock_aiortp.VideoRTPSession.create = AsyncMock(return_value=mock_video)

        with patch("aiosipua.video_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        assert session.video_session is mock_video
        mock_aiortp.VideoRTPSession.create.assert_awaited_once()

        call_kwargs = mock_aiortp.VideoRTPSession.create.call_args
        assert call_kwargs.kwargs["local_addr"] == ("10.0.0.5", 30002)
        assert call_kwargs.kwargs["remote_addr"] == ("10.0.0.1", 20002)
        assert call_kwargs.kwargs["payload_type"] == 96
        assert call_kwargs.kwargs["clock_rate"] == 90000

    @pytest.mark.asyncio()
    async def test_close_closes_video_session(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        mock_video = MagicMock()
        mock_video.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.VideoRTPSession.create = AsyncMock(return_value=mock_video)

        with patch("aiosipua.video_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()
            await session.close()

        mock_video.close.assert_awaited_once()
        assert session.video_session is None

    @pytest.mark.asyncio()
    async def test_double_close_safe(self) -> None:
        offer = parse_sdp(VIDEO_SDP)
        session = VideoCallSession(local_ip="10.0.0.5", rtp_port=30002, offer=offer)

        mock_video = MagicMock()
        mock_video.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.VideoRTPSession.create = AsyncMock(return_value=mock_video)

        with patch("aiosipua.video_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()
            await session.close()
            await session.close()

        mock_video.close.assert_awaited_once()
