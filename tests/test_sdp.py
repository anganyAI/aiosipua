"""Tests for aiosipua.sdp."""

from aiosipua.sdp import SdpMessage, parse_sdp, serialize_sdp

SIMPLE_SDP = (
    "v=0\r\n"
    "o=- 12345 67890 IN IP4 192.168.1.100\r\n"
    "s=Session\r\n"
    "c=IN IP4 192.168.1.100\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8 96\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:96 opus/48000/2\r\n"
    "a=fmtp:96 minptime=10;useinbandfec=1\r\n"
    "a=sendrecv\r\n"
)

SDP_WITH_BANDWIDTH = (
    "v=0\r\n"
    "o=- 1000 1000 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "b=AS:256\r\n"
    "t=0 0\r\n"
    "m=video 51372 RTP/AVP 97\r\n"
    "b=TIAS:1024000\r\n"
    "a=rtpmap:97 H264/90000\r\n"
    "a=fmtp:97 profile-level-id=42e01f\r\n"
)

MULTI_MEDIA_SDP = (
    "v=0\r\n"
    "o=alice 2890844526 2890844526 IN IP4 host.atlanta.example.com\r\n"
    "s=-\r\n"
    "c=IN IP4 host.atlanta.example.com\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0\r\n"
    "a=sendrecv\r\n"
    "m=video 51372 RTP/AVP 31\r\n"
    "a=sendonly\r\n"
)


class TestParseSimpleSdp:
    def test_version(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert sdp.version == 0

    def test_origin(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert sdp.origin.username == "-"
        assert sdp.origin.session_id == "12345"
        assert sdp.origin.session_version == "67890"
        assert sdp.origin.net_type == "IN"
        assert sdp.origin.addr_type == "IP4"
        assert sdp.origin.address == "192.168.1.100"

    def test_session_name(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert sdp.session_name == "Session"

    def test_connection(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert sdp.connection is not None
        assert sdp.connection.address == "192.168.1.100"

    def test_timing(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert sdp.timing.start_time == 0
        assert sdp.timing.stop_time == 0

    def test_media_count(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        assert len(sdp.media) == 1

    def test_media_audio(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        m = sdp.media[0]
        assert m.media == "audio"
        assert m.port == 49170
        assert m.proto == "RTP/AVP"
        assert m.formats == ["0", "8", "96"]


class TestCodecExtraction:
    def test_rtpmap_codecs(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        codecs = sdp.media[0].codecs
        assert len(codecs) == 3
        assert codecs[0].encoding_name == "PCMU"
        assert codecs[0].clock_rate == 8000
        assert codecs[1].encoding_name == "PCMA"
        assert codecs[1].clock_rate == 8000
        assert codecs[2].encoding_name == "opus"
        assert codecs[2].clock_rate == 48000
        assert codecs[2].channels == 2

    def test_fmtp(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        opus = sdp.media[0].codecs[2]
        assert opus.fmtp == "minptime=10;useinbandfec=1"

    def test_well_known_codecs_fallback(self) -> None:
        raw = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0 8\r\n"
        sdp = parse_sdp(raw)
        codecs = sdp.media[0].codecs
        assert len(codecs) == 2
        assert codecs[0].encoding_name == "PCMU"
        assert codecs[0].payload_type == 0
        assert codecs[1].encoding_name == "PCMA"
        assert codecs[1].payload_type == 8


class TestBandwidthParsing:
    """The key bug fix: sip-parser has no 'b' handler and raises KeyError."""

    def test_session_level_bandwidth(self) -> None:
        sdp = parse_sdp(SDP_WITH_BANDWIDTH)
        assert len(sdp.bandwidths) == 1
        assert sdp.bandwidths[0].bwtype == "AS"
        assert sdp.bandwidths[0].bandwidth == 256

    def test_media_level_bandwidth(self) -> None:
        sdp = parse_sdp(SDP_WITH_BANDWIDTH)
        m = sdp.media[0]
        assert len(m.bandwidths) == 1
        assert m.bandwidths[0].bwtype == "TIAS"
        assert m.bandwidths[0].bandwidth == 1024000

    def test_bandwidth_does_not_crash(self) -> None:
        """This would KeyError in sip-parser."""
        raw = (
            "v=0\r\n"
            "o=- 0 0 IN IP4 0.0.0.0\r\n"
            "s=-\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "b=CT:1000\r\n"
            "t=0 0\r\n"
            "m=audio 8000 RTP/AVP 0\r\n"
            "b=AS:64\r\n"
        )
        sdp = parse_sdp(raw)
        assert len(sdp.bandwidths) == 1
        assert sdp.bandwidths[0].bwtype == "CT"
        assert sdp.media[0].bandwidths[0].bwtype == "AS"


class TestMultiMedia:
    def test_two_media_sections(self) -> None:
        sdp = parse_sdp(MULTI_MEDIA_SDP)
        assert len(sdp.media) == 2
        assert sdp.media[0].media == "audio"
        assert sdp.media[1].media == "video"

    def test_direction(self) -> None:
        sdp = parse_sdp(MULTI_MEDIA_SDP)
        assert sdp.media[0].direction == "sendrecv"
        assert sdp.media[1].direction == "sendonly"

    def test_default_direction(self) -> None:
        raw = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n"
        sdp = parse_sdp(raw)
        assert sdp.media[0].direction == "sendrecv"


class TestSerializeSdp:
    def test_serialize_simple(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        built = serialize_sdp(sdp)
        assert built.startswith("v=0\r\n")
        assert "o=- 12345 67890 IN IP4 192.168.1.100\r\n" in built
        assert "s=Session\r\n" in built
        assert "c=IN IP4 192.168.1.100\r\n" in built
        assert "m=audio 49170 RTP/AVP 0 8 96\r\n" in built

    def test_serialize_roundtrip(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        built = serialize_sdp(sdp)
        sdp2 = parse_sdp(built)
        assert sdp2.version == sdp.version
        assert sdp2.origin.session_id == sdp.origin.session_id
        assert sdp2.session_name == sdp.session_name
        assert len(sdp2.media) == len(sdp.media)
        assert sdp2.media[0].port == sdp.media[0].port

    def test_serialize_with_bandwidth(self) -> None:
        sdp = parse_sdp(SDP_WITH_BANDWIDTH)
        built = serialize_sdp(sdp)
        assert "b=AS:256\r\n" in built
        assert "b=TIAS:1024000\r\n" in built


class TestConvenienceProperties:
    def test_audio_property(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        audio = sdp.audio
        assert audio is not None
        assert audio.media == "audio"
        assert audio.port == 49170

    def test_audio_none_for_video_only(self) -> None:
        sdp = parse_sdp(SDP_WITH_BANDWIDTH)
        assert sdp.audio is None

    def test_rtp_address(self) -> None:
        sdp = parse_sdp(SIMPLE_SDP)
        addr = sdp.rtp_address
        assert addr is not None
        assert addr == ("192.168.1.100", 49170)

    def test_rtp_address_media_level_connection(self) -> None:
        raw = (
            "v=0\r\n"
            "o=- 0 0 IN IP4 0.0.0.0\r\n"
            "s=-\r\n"
            "c=IN IP4 10.0.0.1\r\n"
            "t=0 0\r\n"
            "m=audio 8000 RTP/AVP 0\r\n"
            "c=IN IP4 10.0.0.2\r\n"
        )
        sdp = parse_sdp(raw)
        addr = sdp.rtp_address
        assert addr is not None
        assert addr == ("10.0.0.2", 8000)

    def test_rtp_address_none(self) -> None:
        sdp = SdpMessage()
        assert sdp.rtp_address is None
