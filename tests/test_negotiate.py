"""Tests for SDP negotiation and high-level builder (Phase 1)."""

import pytest

from aiosipua.sdp import (
    SdpNegotiationError,
    build_sdp,
    negotiate_sdp,
    parse_sdp,
    serialize_sdp,
)

# --- Realistic carrier SDP samples ---

# Typical PSTN gateway offer: PCMU + PCMA + telephone-event
CARRIER_OFFER_BASIC = (
    "v=0\r\n"
    "o=FreeSWITCH 1234567890 1234567891 IN IP4 203.0.113.10\r\n"
    "s=FreeSWITCH\r\n"
    "c=IN IP4 203.0.113.10\r\n"
    "t=0 0\r\n"
    "m=audio 18000 RTP/AVP 0 8 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)

# Offer with PCMA preferred first
CARRIER_OFFER_PCMA_FIRST = (
    "v=0\r\n"
    "o=- 5000 5000 IN IP4 198.51.100.5\r\n"
    "s=-\r\n"
    "c=IN IP4 198.51.100.5\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 8 0 101\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=sendrecv\r\n"
)

# WebRTC-style offer: opus + telephone-event, no legacy codecs
WEBRTC_OFFER = (
    "v=0\r\n"
    "o=- 9999 9999 IN IP4 0.0.0.0\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.100\r\n"
    "t=0 0\r\n"
    "m=audio 30000 RTP/AVP 96 97\r\n"
    "a=rtpmap:96 opus/48000/2\r\n"
    "a=fmtp:96 minptime=10;useinbandfec=1\r\n"
    "a=rtpmap:97 telephone-event/8000\r\n"
    "a=fmtp:97 0-16\r\n"
    "a=sendrecv\r\n"
)

# Offer without telephone-event
OFFER_NO_DTMF = (
    "v=0\r\n"
    "o=- 1000 1000 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 15000 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=ptime:30\r\n"
    "a=sendrecv\r\n"
)

# Offer with sendonly direction
OFFER_SENDONLY = (
    "v=0\r\n"
    "o=- 2000 2000 IN IP4 10.0.0.2\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.2\r\n"
    "t=0 0\r\n"
    "m=audio 16000 RTP/AVP 0 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=sendonly\r\n"
)

# Offer with only well-known static PTs (no rtpmap lines)
OFFER_STATIC_ONLY = (
    "v=0\r\n"
    "o=- 3000 3000 IN IP4 10.0.0.3\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.3\r\n"
    "t=0 0\r\n"
    "m=audio 17000 RTP/AVP 0 8\r\n"
    "a=sendrecv\r\n"
)

# Video-only offer (no audio)
VIDEO_ONLY_OFFER = (
    "v=0\r\n"
    "o=- 4000 4000 IN IP4 10.0.0.4\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.4\r\n"
    "t=0 0\r\n"
    "m=video 18000 RTP/AVP 97\r\n"
    "a=rtpmap:97 H264/90000\r\n"
)

# Offer with bandwidth
OFFER_WITH_BANDWIDTH = (
    "v=0\r\n"
    "o=- 6000 6000 IN IP4 10.0.0.6\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.6\r\n"
    "b=AS:256\r\n"
    "t=0 0\r\n"
    "m=audio 22000 RTP/AVP 0 8 101\r\n"
    "b=TIAS:64000\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=sendrecv\r\n"
)

# Twilio-style offer with multiple codecs
TWILIO_OFFER = (
    "v=0\r\n"
    "o=root 1234 1234 IN IP4 54.172.60.0\r\n"
    "s=Twilio Media Gateway\r\n"
    "c=IN IP4 54.172.60.0\r\n"
    "t=0 0\r\n"
    "m=audio 10000 RTP/AVP 0 8 18 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:18 G729/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)


class TestNegotiateBasic:
    def test_choose_pcmu(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert chosen_pt == 0
        assert answer.audio is not None
        assert answer.audio.port == 30000
        assert "0" in answer.audio.formats
        # Verify answer includes rtpmap for chosen codec
        rtpmaps = answer.audio.attributes.get("rtpmap", [])
        assert any("PCMU" in r for r in rtpmaps)

    def test_answer_structure(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert answer.version == 0
        assert answer.origin.address == "10.0.0.5"
        assert answer.origin.session_id == "99999"
        assert answer.connection is not None
        assert answer.connection.address == "10.0.0.5"
        assert answer.rtp_address == ("10.0.0.5", 30000)


class TestCodecPreference:
    def test_offerer_preference_wins(self) -> None:
        """When offer lists PCMA first, PCMA should be chosen."""
        offer = parse_sdp(CARRIER_OFFER_PCMA_FIRST)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert chosen_pt == 8  # PCMA

    def test_restrict_supported_codecs(self) -> None:
        """When we only support PCMA, choose PCMA even if PCMU is offered first."""
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, chosen_pt = negotiate_sdp(
            offer,
            local_ip="10.0.0.5",
            rtp_port=30000,
            supported_codecs=[8],
            session_id="99999",
        )
        assert chosen_pt == 8

    def test_twilio_first_match(self) -> None:
        offer = parse_sdp(TWILIO_OFFER)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert chosen_pt == 0  # PCMU (first in offer, in default supported)

    def test_g729_supported(self) -> None:
        offer = parse_sdp(TWILIO_OFFER)
        answer, chosen_pt = negotiate_sdp(
            offer,
            local_ip="10.0.0.5",
            rtp_port=30000,
            supported_codecs=[18],
            session_id="99999",
        )
        assert chosen_pt == 18  # G729

    def test_answer_only_includes_chosen_codec(self) -> None:
        """Answer should only include the chosen codec, not all offered codecs."""
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        # formats should be chosen codec + dtmf only
        assert audio.formats[0] == "0"
        assert len(audio.formats) <= 2  # codec + optional dtmf


class TestNoMatch:
    def test_no_matching_codec(self) -> None:
        offer = parse_sdp(WEBRTC_OFFER)
        with pytest.raises(SdpNegotiationError, match="No matching codec"):
            negotiate_sdp(
                offer,
                local_ip="10.0.0.5",
                rtp_port=30000,
                supported_codecs=[0, 8],
                session_id="99999",
            )

    def test_no_audio_media(self) -> None:
        offer = parse_sdp(VIDEO_ONLY_OFFER)
        with pytest.raises(SdpNegotiationError, match="no audio"):
            negotiate_sdp(
                offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
            )


class TestDtmfNegotiation:
    def test_dtmf_included_when_offered(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        # Should include telephone-event
        rtpmaps = audio.attributes.get("rtpmap", [])
        assert any("telephone-event" in r for r in rtpmaps)
        # fmtp for DTMF
        fmtps = audio.attributes.get("fmtp", [])
        assert any("0-16" in f for f in fmtps)

    def test_dtmf_omitted_when_not_offered(self) -> None:
        offer = parse_sdp(OFFER_NO_DTMF)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        # Should NOT include telephone-event
        rtpmaps = audio.attributes.get("rtpmap", [])
        assert not any("telephone-event" in r for r in rtpmaps)
        # Only the chosen codec in formats
        assert len(audio.formats) == 1

    def test_dtmf_disabled_by_caller(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer,
            local_ip="10.0.0.5",
            rtp_port=30000,
            dtmf_payload_type=0,
            session_id="99999",
        )
        audio = answer.audio
        assert audio is not None
        rtpmaps = audio.attributes.get("rtpmap", [])
        assert not any("telephone-event" in r for r in rtpmaps)

    def test_custom_dtmf_payload_type(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer,
            local_ip="10.0.0.5",
            rtp_port=30000,
            dtmf_payload_type=96,
            session_id="99999",
        )
        audio = answer.audio
        assert audio is not None
        assert "96" in audio.formats
        rtpmaps = audio.attributes.get("rtpmap", [])
        assert any("96 telephone-event/8000" in r for r in rtpmaps)


class TestPtimeHandling:
    def test_offer_ptime_respected(self) -> None:
        offer = parse_sdp(OFFER_NO_DTMF)  # has a=ptime:30
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        ptimes = audio.attributes.get("ptime", [])
        assert ptimes == ["30"]

    def test_default_ptime_when_absent(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_PCMA_FIRST)  # no ptime
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, ptime=20, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        ptimes = audio.attributes.get("ptime", [])
        assert ptimes == ["20"]

    def test_custom_default_ptime(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_PCMA_FIRST)  # no ptime
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, ptime=30, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        ptimes = audio.attributes.get("ptime", [])
        assert ptimes == ["30"]

    def test_offer_ptime_overrides_default(self) -> None:
        """Offer ptime:20 should be used even if caller passes ptime=30."""
        offer = parse_sdp(CARRIER_OFFER_BASIC)  # has a=ptime:20
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, ptime=30, session_id="99999"
        )
        audio = answer.audio
        assert audio is not None
        ptimes = audio.attributes.get("ptime", [])
        assert ptimes == ["20"]


class TestDirectionNegotiation:
    def test_sendrecv_to_sendrecv(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)  # sendrecv
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert answer.audio is not None
        assert answer.audio.direction == "sendrecv"

    def test_sendonly_to_recvonly(self) -> None:
        offer = parse_sdp(OFFER_SENDONLY)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert answer.audio is not None
        assert answer.audio.direction == "recvonly"


class TestSessionId:
    def test_explicit_session_id(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="42"
        )
        assert answer.origin.session_id == "42"
        assert answer.origin.session_version == "42"

    def test_auto_session_id(self) -> None:
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, _ = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000
        )
        # Should be a numeric timestamp string
        int(answer.origin.session_id)  # should not raise


class TestStaticPayloadTypes:
    def test_negotiate_static_only(self) -> None:
        """Offer with no rtpmap lines, only static PTs."""
        offer = parse_sdp(OFFER_STATIC_ONLY)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        assert chosen_pt == 0
        assert answer.audio is not None


class TestBuildSdp:
    def test_build_pcmu(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
            session_id="12345",
        )
        assert sdp.version == 0
        assert sdp.connection is not None
        assert sdp.connection.address == "10.0.0.5"
        assert sdp.origin.session_id == "12345"
        assert sdp.origin.address == "10.0.0.5"

        audio = sdp.audio
        assert audio is not None
        assert audio.port == 30000
        assert "0" in audio.formats
        assert "101" in audio.formats  # default DTMF PT
        assert audio.direction == "sendrecv"

    def test_build_serializes(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
            session_id="12345",
        )
        text = serialize_sdp(sdp)
        assert "v=0\r\n" in text
        assert "c=IN IP4 10.0.0.5\r\n" in text
        assert "m=audio 30000 RTP/AVP 0 101\r\n" in text
        assert "a=rtpmap:0 PCMU/8000\r\n" in text
        assert "a=rtpmap:101 telephone-event/8000\r\n" in text

    def test_build_no_dtmf(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=8,
            codec_name="PCMA",
            dtmf_payload_type=0,
            session_id="12345",
        )
        audio = sdp.audio
        assert audio is not None
        assert audio.formats == ["8"]
        rtpmaps = audio.attributes.get("rtpmap", [])
        assert not any("telephone-event" in r for r in rtpmaps)

    def test_build_custom_ptime(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
            ptime=30,
            session_id="12345",
        )
        audio = sdp.audio
        assert audio is not None
        assert audio.attributes.get("ptime") == ["30"]

    def test_build_auto_session_id(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
        )
        int(sdp.origin.session_id)  # should not raise

    def test_build_rtp_address(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
            session_id="12345",
        )
        assert sdp.rtp_address == ("10.0.0.5", 30000)

    def test_build_roundtrip(self) -> None:
        sdp = build_sdp(
            local_ip="10.0.0.5",
            rtp_port=30000,
            payload_type=0,
            codec_name="PCMU",
            session_id="12345",
        )
        text = serialize_sdp(sdp)
        sdp2 = parse_sdp(text)
        assert sdp2.connection is not None
        assert sdp2.connection.address == "10.0.0.5"
        assert sdp2.audio is not None
        assert sdp2.audio.port == 30000
        assert sdp2.rtp_address == ("10.0.0.5", 30000)


class TestNegotiateAndSerialize:
    def test_full_roundtrip(self) -> None:
        """Negotiate from carrier offer, serialize answer, re-parse."""
        offer = parse_sdp(CARRIER_OFFER_BASIC)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="10.0.0.5", rtp_port=30000, session_id="99999"
        )
        text = serialize_sdp(answer)
        answer2 = parse_sdp(text)

        assert answer2.audio is not None
        assert answer2.audio.port == 30000
        assert answer2.rtp_address == ("10.0.0.5", 30000)
        assert answer2.audio.direction == "sendrecv"
        assert chosen_pt == 0

    def test_twilio_roundtrip(self) -> None:
        offer = parse_sdp(TWILIO_OFFER)
        answer, chosen_pt = negotiate_sdp(
            offer, local_ip="172.16.0.1", rtp_port=40000, session_id="88888"
        )
        text = serialize_sdp(answer)
        answer2 = parse_sdp(text)

        assert answer2.rtp_address == ("172.16.0.1", 40000)
        assert chosen_pt == 0
