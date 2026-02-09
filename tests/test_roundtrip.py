"""Integration roundtrip tests: parse → modify → serialize → re-parse."""

from aiosipua import (
    Address,
    SipMessage,
    SipRequest,
    SipResponse,
    SipUri,
    Via,
    build_sdp,
    parse_sdp,
)

INVITE_WITH_SDP = (
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: Bob <sip:bob@biloxi.example.com>\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@pc33.atlanta.example.com>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 147\r\n"
    "\r\n"
    "v=0\r\n"
    "o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n"
    "s=-\r\n"
    "c=IN IP4 pc33.atlanta.example.com\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0\r\n"
    "a=sendrecv\r\n"
)

OK_200_WITH_SDP = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:bob@192.0.2.4>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 130\r\n"
    "\r\n"
    "v=0\r\n"
    "o=bob 2890844730 2890844730 IN IP4 192.0.2.4\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.4\r\n"
    "t=0 0\r\n"
    "m=audio 49172 RTP/AVP 0\r\n"
    "a=sendrecv\r\n"
)


class TestInviteRoundtrip:
    def test_parse_serialize_reparse(self) -> None:
        msg1 = SipMessage.parse(INVITE_WITH_SDP)
        assert isinstance(msg1, SipRequest)
        serialized = msg1.serialize()
        msg2 = SipMessage.parse(serialized)
        assert isinstance(msg2, SipRequest)

        # Compare all fields
        assert msg2.method == msg1.method
        assert msg2.uri == msg1.uri
        assert msg2.call_id == msg1.call_id

        cseq1 = msg1.cseq
        cseq2 = msg2.cseq
        assert cseq1 is not None and cseq2 is not None
        assert cseq2.seq == cseq1.seq
        assert cseq2.method == cseq1.method

        from1 = msg1.from_addr
        from2 = msg2.from_addr
        assert from1 is not None and from2 is not None
        assert from2.uri.user == from1.uri.user
        assert from2.tag == from1.tag

        to1 = msg1.to_addr
        to2 = msg2.to_addr
        assert to1 is not None and to2 is not None
        assert to2.uri.user == to1.uri.user

        assert len(msg2.via) == len(msg1.via)
        assert msg2.via[0].branch == msg1.via[0].branch

    def test_body_preserved(self) -> None:
        msg = SipMessage.parse(INVITE_WITH_SDP)
        assert msg.body.startswith("v=0")
        serialized = msg.serialize()
        msg2 = SipMessage.parse(serialized)
        assert msg2.body == msg.body


class TestResponseWithSdpRoundtrip:
    def test_200_ok_roundtrip(self) -> None:
        msg1 = SipMessage.parse(OK_200_WITH_SDP)
        assert isinstance(msg1, SipResponse)
        assert msg1.status_code == 200

        serialized = msg1.serialize()
        msg2 = SipMessage.parse(serialized)
        assert isinstance(msg2, SipResponse)
        assert msg2.status_code == 200
        assert msg2.reason_phrase == "OK"
        assert msg2.body == msg1.body

        # Verify SDP is parseable from roundtripped body
        sdp = parse_sdp(msg2.body)
        assert len(sdp.media) == 1
        assert sdp.media[0].port == 49172


class TestModifyAndRoundtrip:
    def test_add_via_change_contact_add_x_header(self) -> None:
        msg = SipMessage.parse(INVITE_WITH_SDP)
        assert isinstance(msg, SipRequest)

        # Add a Via
        new_via = Via(
            protocol="SIP/2.0",
            transport="UDP",
            host="proxy.example.com",
            port=5060,
            params={"branch": "z9hG4bKproxy1"},
        )
        msg.via = [new_via] + msg.via

        # Change Contact
        new_contact = Address(
            uri=SipUri(scheme="sip", user="alice", host="proxy.example.com", port=5060)
        )
        msg.contact = [new_contact]

        # Add X-header
        msg.add_header("X-Correlation-ID", "corr-12345")

        # Serialize and re-parse
        serialized = msg.serialize()
        msg2 = SipMessage.parse(serialized)
        assert isinstance(msg2, SipRequest)

        # Verify modifications
        assert len(msg2.via) == 2
        assert msg2.via[0].host == "proxy.example.com"
        assert msg2.via[0].branch == "z9hG4bKproxy1"
        assert msg2.via[1].host == "pc33.atlanta.example.com"

        contacts = msg2.contact
        assert len(contacts) == 1
        assert contacts[0].uri.host == "proxy.example.com"

        assert msg2.get_header("X-Correlation-ID") == "corr-12345"


class TestSdpInSipRoundtrip:
    def test_extract_modify_rebuild_sdp(self) -> None:
        msg = SipMessage.parse(INVITE_WITH_SDP)
        assert isinstance(msg, SipRequest)

        # Extract SDP
        sdp = parse_sdp(msg.body)
        assert sdp.media[0].port == 49170

        # Modify SDP
        sdp.media[0].port = 30000
        assert sdp.connection is not None
        sdp.connection.address = "10.0.0.1"

        # Rebuild SDP and replace body
        msg.body = build_sdp(sdp)
        msg.content_type = "application/sdp"

        # Serialize full message
        serialized = msg.serialize()

        # Re-parse and verify
        msg2 = SipMessage.parse(serialized)
        sdp2 = parse_sdp(msg2.body)
        assert sdp2.media[0].port == 30000
        assert sdp2.connection is not None
        assert sdp2.connection.address == "10.0.0.1"

        # Content-Length should match actual body
        body_bytes = msg2.body.encode("utf-8")
        assert msg2.content_length == len(body_bytes)
