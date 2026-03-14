"""Tests for video SDP negotiation and combined A/V negotiation."""

from __future__ import annotations

import pytest

from aiosipua.sdp import (
    SdpNegotiationError,
    parse_sdp,
    serialize_sdp,
)
from aiosipua.sdp_video import (
    build_video_sdp,
    negotiate_av_sdp,
    negotiate_video_sdp,
)

# --- SDP samples ---

# Audio + video offer (typical SIP video phone)
AV_OFFER = (
    "v=0\r\n"
    "o=- 1234 1234 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 8 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
    "m=video 20002 RTP/AVP 96 97\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 profile-level-id=42e01f\r\n"
    "a=rtpmap:97 VP8/90000\r\n"
    "a=sendrecv\r\n"
)

# Video-only offer
VIDEO_ONLY_OFFER = (
    "v=0\r\n"
    "o=- 4000 4000 IN IP4 10.0.0.4\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.4\r\n"
    "t=0 0\r\n"
    "m=video 18000 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n"
    "a=sendrecv\r\n"
)

# VP8-only offer
VP8_ONLY_OFFER = (
    "v=0\r\n"
    "o=- 5000 5000 IN IP4 10.0.0.5\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.5\r\n"
    "t=0 0\r\n"
    "m=video 19000 RTP/AVP 97\r\n"
    "a=rtpmap:97 VP8/90000\r\n"
    "a=sendrecv\r\n"
)

# Sendonly video
VIDEO_SENDONLY = (
    "v=0\r\n"
    "o=- 6000 6000 IN IP4 10.0.0.6\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.6\r\n"
    "t=0 0\r\n"
    "m=video 19000 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=sendonly\r\n"
)

# Audio-only offer (no video)
AUDIO_ONLY_OFFER = (
    "v=0\r\n"
    "o=- 7000 7000 IN IP4 10.0.0.7\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.7\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)


class TestNegotiateVideoBasic:
    def test_choose_h264(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)
        answer, chosen_pt = negotiate_video_sdp(
            offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
        )
        assert chosen_pt == 96
        assert answer.video is not None
        assert answer.video.port == 30002

    def test_answer_structure(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)
        answer, _ = negotiate_video_sdp(
            offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
        )
        assert answer.version == 0
        assert answer.origin.address == "10.0.0.5"
        assert answer.connection is not None
        assert answer.connection.address == "10.0.0.5"
        assert answer.video_rtp_address == ("10.0.0.5", 30002)

    def test_fmtp_preserved(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)
        answer, _ = negotiate_video_sdp(
            offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
        )
        video = answer.video
        assert video is not None
        fmtps = video.attributes.get("fmtp", [])
        assert any("profile-level-id" in f for f in fmtps)


class TestVideoCodecPreference:
    def test_offerer_preference_wins(self) -> None:
        """H264 offered first, so H264 chosen even if we support both."""
        offer = parse_sdp(AV_OFFER)
        answer, chosen_pt = negotiate_video_sdp(
            offer,
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            supported_video_codecs=["H264", "VP8"],
            session_id="99999",
        )
        assert chosen_pt == 96  # H264

    def test_restrict_to_vp8(self) -> None:
        offer = parse_sdp(AV_OFFER)
        answer, chosen_pt = negotiate_video_sdp(
            offer,
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            supported_video_codecs=["VP8"],
            session_id="99999",
        )
        assert chosen_pt == 97  # VP8


class TestVideoNoMatch:
    def test_no_matching_video_codec(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)  # only H264
        with pytest.raises(SdpNegotiationError, match="No matching video"):
            negotiate_video_sdp(
                offer,
                local_ip="10.0.0.5",
                video_rtp_port=30002,
                supported_video_codecs=["VP9"],
                session_id="99999",
            )

    def test_no_video_media(self) -> None:
        offer = parse_sdp(AUDIO_ONLY_OFFER)
        with pytest.raises(SdpNegotiationError, match="no video"):
            negotiate_video_sdp(
                offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
            )


class TestVideoDirection:
    def test_sendrecv(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)
        answer, _ = negotiate_video_sdp(
            offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
        )
        assert answer.video is not None
        assert answer.video.direction == "sendrecv"

    def test_sendonly_to_recvonly(self) -> None:
        offer = parse_sdp(VIDEO_SENDONLY)
        answer, _ = negotiate_video_sdp(
            offer, local_ip="10.0.0.5", video_rtp_port=30002, session_id="99999"
        )
        assert answer.video is not None
        assert answer.video.direction == "recvonly"


class TestNegotiateAvSdp:
    def test_audio_video_combined(self) -> None:
        offer = parse_sdp(AV_OFFER)
        answer, audio_pt, video_pt = negotiate_av_sdp(
            offer,
            local_ip="10.0.0.5",
            audio_rtp_port=30000,
            video_rtp_port=30002,
            session_id="99999",
        )
        assert audio_pt == 0  # PCMU
        assert video_pt == 96  # H264
        assert answer.audio is not None
        assert answer.video is not None
        assert answer.audio.port == 30000
        assert answer.video.port == 30002

    def test_audio_only_offer(self) -> None:
        """Audio-only offer returns None for video PT."""
        offer = parse_sdp(AUDIO_ONLY_OFFER)
        answer, audio_pt, video_pt = negotiate_av_sdp(
            offer,
            local_ip="10.0.0.5",
            audio_rtp_port=30000,
            video_rtp_port=30002,
            session_id="99999",
        )
        assert audio_pt == 0
        assert video_pt is None
        assert answer.audio is not None
        assert answer.video is None

    def test_av_serialization_roundtrip(self) -> None:
        offer = parse_sdp(AV_OFFER)
        answer, _, _ = negotiate_av_sdp(
            offer,
            local_ip="10.0.0.5",
            audio_rtp_port=30000,
            video_rtp_port=30002,
            session_id="99999",
        )
        text = serialize_sdp(answer)
        reparsed = parse_sdp(text)

        assert reparsed.audio is not None
        assert reparsed.video is not None
        assert reparsed.rtp_address == ("10.0.0.5", 30000)
        assert reparsed.video_rtp_address == ("10.0.0.5", 30002)


class TestBuildVideoSdp:
    def test_build_h264(self) -> None:
        sdp = build_video_sdp(
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            session_id="12345",
        )
        assert sdp.video is not None
        assert sdp.video.port == 30002
        assert sdp.video.direction == "sendrecv"
        assert sdp.video_rtp_address == ("10.0.0.5", 30002)

    def test_build_with_fmtp(self) -> None:
        sdp = build_video_sdp(
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            fmtp="profile-level-id=42e01f;packetization-mode=1",
            session_id="12345",
        )
        video = sdp.video
        assert video is not None
        fmtps = video.attributes.get("fmtp", [])
        assert any("profile-level-id" in f for f in fmtps)

    def test_build_serializes(self) -> None:
        sdp = build_video_sdp(
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            session_id="12345",
        )
        text = serialize_sdp(sdp)
        assert "m=video 30002 RTP/AVP 96\r\n" in text
        assert "a=rtpmap:96 H264/90000\r\n" in text

    def test_build_roundtrip(self) -> None:
        sdp = build_video_sdp(
            local_ip="10.0.0.5",
            video_rtp_port=30002,
            session_id="12345",
        )
        text = serialize_sdp(sdp)
        reparsed = parse_sdp(text)
        assert reparsed.video is not None
        assert reparsed.video.port == 30002
        assert reparsed.video_rtp_address == ("10.0.0.5", 30002)
