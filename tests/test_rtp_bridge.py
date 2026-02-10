"""Tests for aiosipua.rtp_bridge.

These tests verify the CallSession bridge logic (SDP negotiation, state
management, callback wiring) without requiring aiortp to be installed.
The RTPSession.create() call is mocked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aiosipua.rtp_bridge import CallSession, _import_aiortp
from aiosipua.sdp import SdpMessage, parse_sdp

# --- Test SDP offers ---

BASIC_SDP = (
    "v=0\r\n"
    "o=- 1234 1234 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)

DTMF_SDP = (
    "v=0\r\n"
    "o=- 5678 5678 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)


class TestCallSessionNegotiation:
    def test_basic_negotiation(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(
            local_ip="10.0.0.5",
            rtp_port=30000,
            offer=offer,
        )

        assert session.chosen_payload_type == 0  # PCMU preferred
        assert session.remote_addr == ("10.0.0.1", 20000)

        answer = session.sdp_answer
        assert answer.audio is not None
        assert answer.audio.port == 30000

    def test_custom_supported_codecs(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(
            local_ip="10.0.0.5",
            rtp_port=30000,
            offer=offer,
            supported_codecs=[8],  # Only PCMA
        )

        assert session.chosen_payload_type == 8

    def test_dtmf_in_answer(self) -> None:
        offer = parse_sdp(DTMF_SDP)
        session = CallSession(
            local_ip="10.0.0.5",
            rtp_port=30000,
            offer=offer,
        )

        answer = session.sdp_answer
        audio = answer.audio
        assert audio is not None
        # Should have DTMF in formats
        assert "101" in audio.formats

    def test_no_audio_raises(self) -> None:
        """Offer without audio media should raise during negotiation."""
        from aiosipua.sdp import SdpNegotiationError

        sdp = SdpMessage()  # empty, no media
        with pytest.raises(SdpNegotiationError):
            CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=sdp)

    def test_no_rtp_address_raises(self) -> None:
        """Offer without c= line should raise."""
        sdp = parse_sdp(
            "v=0\r\n"
            "o=- 1 1 IN IP4 0.0.0.0\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "m=audio 20000 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        # No c= line at session or media level
        with pytest.raises(ValueError, match="no RTP address"):
            CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=sdp)


class TestCallSessionProperties:
    def test_sdp_answer_property(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        assert isinstance(session.sdp_answer, SdpMessage)

    def test_rtp_session_none_before_start(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        assert session.rtp_session is None

    def test_stats_empty_before_start(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        assert session.stats == {}


class TestCallSessionCallbacks:
    def test_audio_callback_wiring(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        received: list[tuple[bytes, int]] = []
        session.on_audio = lambda pcm, ts: received.append((pcm, ts))

        # Simulate internal audio callback
        session._handle_audio(b"\x00\x01\x02", 160)
        assert len(received) == 1
        assert received[0] == (b"\x00\x01\x02", 160)

    def test_dtmf_callback_wiring(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        received: list[tuple[str, int]] = []
        session.on_dtmf = lambda d, dur: received.append((d, dur))

        session._handle_dtmf("1", 160)
        assert len(received) == 1
        assert received[0] == ("1", 160)

    def test_no_callback_no_error(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        # Should not raise even with no callbacks set
        session._handle_audio(b"\x00", 0)
        session._handle_dtmf("1", 100)


class TestCallSessionSendMethods:
    def test_send_audio_before_start(self) -> None:
        """send_audio before start() should be a no-op."""
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        # Should not raise
        session.send_audio(b"\x00\x01", 160)

    def test_send_audio_pcm_before_start(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        session.send_audio_pcm(b"\x00\x01", 160)

    def test_send_dtmf_before_start(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        session.send_dtmf("1")

    def test_update_remote(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        assert session.remote_addr == ("10.0.0.1", 20000)
        session.update_remote(("10.0.0.99", 25000))
        assert session.remote_addr == ("10.0.0.99", 25000)


class TestCallSessionWithMockedAiortp:
    """Tests that mock aiortp.RTPSession to verify start/close lifecycle."""

    @pytest.mark.asyncio()
    async def test_start_creates_rtp_session(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.stats = {"ssrc": 12345, "packets_sent": 0}

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        assert session.rtp_session is mock_rtp
        mock_aiortp.RTPSession.create.assert_awaited_once()

        # Verify create was called with correct params
        call_kwargs = mock_aiortp.RTPSession.create.call_args
        assert call_kwargs.kwargs["local_addr"] == ("10.0.0.5", 30000)
        assert call_kwargs.kwargs["remote_addr"] == ("10.0.0.1", 20000)
        assert call_kwargs.kwargs["payload_type"] == 0

    @pytest.mark.asyncio()
    async def test_close_closes_rtp_session(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()
            await session.close()

        mock_rtp.close.assert_awaited_once()
        assert session.rtp_session is None

    @pytest.mark.asyncio()
    async def test_double_close_is_safe(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()
            await session.close()
            await session.close()  # Should not raise

        mock_rtp.close.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_send_after_close_is_noop(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()
            await session.close()

        # Should not raise or call mock methods
        session.send_audio(b"\x00", 0)
        session.send_audio_pcm(b"\x00", 0)
        session.send_dtmf("1")

    @pytest.mark.asyncio()
    async def test_stats_after_start(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.stats = {"ssrc": 12345, "packets_sent": 42}

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        assert session.stats["packets_sent"] == 42

    @pytest.mark.asyncio()
    async def test_update_remote_forwards_to_rtp(self) -> None:
        offer = parse_sdp(BASIC_SDP)
        session = CallSession(local_ip="10.0.0.5", rtp_port=30000, offer=offer)

        mock_rtp = MagicMock()
        mock_rtp.close = AsyncMock()

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        session.update_remote(("10.0.0.99", 25000))
        mock_rtp.update_remote.assert_called_once_with(("10.0.0.99", 25000))


class TestCallSessionFullFlow:
    """Integration-style test: negotiation + mock RTP + callbacks."""

    @pytest.mark.asyncio()
    async def test_full_call_lifecycle(self) -> None:
        offer = parse_sdp(DTMF_SDP)
        session = CallSession(
            local_ip="10.0.0.5",
            rtp_port=30000,
            offer=offer,
        )

        # Verify negotiation
        assert session.chosen_payload_type == 0
        assert session.remote_addr == ("10.0.0.1", 20000)

        # Set up callbacks
        audio_received: list[tuple[bytes, int]] = []
        dtmf_received: list[tuple[str, int]] = []
        session.on_audio = lambda pcm, ts: audio_received.append((pcm, ts))
        session.on_dtmf = lambda d, dur: dtmf_received.append((d, dur))

        # Mock aiortp and start
        mock_rtp = MagicMock()
        mock_rtp.close = AsyncMock()
        mock_rtp.stats = {"ssrc": 999}

        mock_aiortp = MagicMock()
        mock_aiortp.RTPSession.create = AsyncMock(return_value=mock_rtp)

        with patch("aiosipua.rtp_bridge._import_aiortp", return_value=mock_aiortp):
            await session.start()

        # Simulate receiving audio and DTMF
        session._handle_audio(b"\x80\x00" * 160, 160)
        session._handle_dtmf("5", 200)

        assert len(audio_received) == 1
        assert len(dtmf_received) == 1
        assert dtmf_received[0] == ("5", 200)

        # Clean up
        await session.close()
        mock_rtp.close.assert_awaited_once()


class TestImportAiortp:
    def test_import_missing_raises(self) -> None:
        """_import_aiortp raises ImportError with helpful message when aiortp not installed."""
        with (
            patch.dict("sys.modules", {"aiortp": None}),
            pytest.raises(ImportError, match="aiortp is required"),
        ):
            _import_aiortp()
