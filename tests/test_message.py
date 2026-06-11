"""Tests for aiosipua.message."""

from aiosipua.headers import Address, CSeq, SipUri, Via
from aiosipua.message import SipMessage, SipRequest, SipResponse

INVITE = (
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: Bob <sip:bob@biloxi.example.com>\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@pc33.atlanta.example.com>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

OK_200 = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP server10.biloxi.example.com;branch=z9hG4bKnashds8\r\n"
    "Via: SIP/2.0/UDP bigbox3.site3.atlanta.example.com;branch=z9hG4bK77ef4c2312983.1\r\n"
    "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:bob@192.0.2.4>\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

TRYING_100 = (
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "To: Bob <sip:bob@biloxi.example.com>\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


class TestParseRequest:
    def test_invite_method(self) -> None:
        msg = SipMessage.parse(INVITE)
        assert isinstance(msg, SipRequest)
        assert msg.method == "INVITE"
        assert msg.uri == "sip:bob@biloxi.example.com"

    def test_invite_headers(self) -> None:
        msg = SipMessage.parse(INVITE)
        assert msg.get_header("Max-Forwards") == "70"
        assert msg.call_id == "a84b4c76e66710@pc33.atlanta.example.com"

    def test_invite_via(self) -> None:
        msg = SipMessage.parse(INVITE)
        vias = msg.via
        assert len(vias) == 1
        assert vias[0].host == "pc33.atlanta.example.com"
        assert vias[0].branch == "z9hG4bK776asdhds"

    def test_invite_from(self) -> None:
        msg = SipMessage.parse(INVITE)
        from_addr = msg.from_addr
        assert from_addr is not None
        assert from_addr.display_name == "Alice"
        assert from_addr.uri.user == "alice"
        assert from_addr.tag == "1928301774"

    def test_invite_to(self) -> None:
        msg = SipMessage.parse(INVITE)
        to_addr = msg.to_addr
        assert to_addr is not None
        assert to_addr.display_name == "Bob"
        assert to_addr.uri.user == "bob"

    def test_invite_cseq(self) -> None:
        msg = SipMessage.parse(INVITE)
        cseq = msg.cseq
        assert cseq is not None
        assert cseq.seq == 314159
        assert cseq.method == "INVITE"

    def test_invite_contact(self) -> None:
        msg = SipMessage.parse(INVITE)
        contacts = msg.contact
        assert len(contacts) == 1
        assert contacts[0].uri.user == "alice"

    def test_content_type(self) -> None:
        msg = SipMessage.parse(INVITE)
        assert msg.content_type == "application/sdp"


class TestParseResponse:
    def test_200_ok(self) -> None:
        msg = SipMessage.parse(OK_200)
        assert isinstance(msg, SipResponse)
        assert msg.status_code == 200
        assert msg.reason_phrase == "OK"

    def test_200_multiple_via(self) -> None:
        msg = SipMessage.parse(OK_200)
        vias = msg.via
        assert len(vias) == 2
        assert vias[0].host == "server10.biloxi.example.com"
        assert vias[1].host == "bigbox3.site3.atlanta.example.com"

    def test_200_to_tag(self) -> None:
        msg = SipMessage.parse(OK_200)
        to_addr = msg.to_addr
        assert to_addr is not None
        assert to_addr.tag == "a6c85cf"

    def test_100_trying(self) -> None:
        msg = SipMessage.parse(TRYING_100)
        assert isinstance(msg, SipResponse)
        assert msg.status_code == 100
        assert msg.reason_phrase == "Trying"


class TestCompactHeaders:
    def test_compact_via(self) -> None:
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
            "f: <sip:alice@example.com>;tag=abc\r\n"
            "t: <sip:bob@example.com>\r\n"
            "i: call123@example.com\r\n"
            "l: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipRequest)
        assert len(msg.via) == 1
        assert msg.via[0].branch == "z9hG4bK1"
        assert msg.from_addr is not None
        assert msg.from_addr.tag == "abc"
        assert msg.call_id == "call123@example.com"
        assert msg.content_length == 0


class TestMultiValueVia:
    def test_comma_separated_via(self) -> None:
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK1, "
            "SIP/2.0/UDP b.example.com;branch=z9hG4bK2\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        vias = msg.via
        assert len(vias) == 2
        assert vias[0].host == "a.example.com"
        assert vias[1].host == "b.example.com"


class TestLineFolding:
    def test_continuation(self) -> None:
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Subject: This is a\r\n"
            "  long subject line\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert msg.get_header("Subject") == "This is a long subject line"


class TestSerialize:
    def test_request_roundtrip(self) -> None:
        msg = SipMessage.parse(INVITE)
        serialized = msg.serialize()
        assert serialized.startswith("INVITE sip:bob@biloxi.example.com SIP/2.0\r\n")
        via_hdr = "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
        assert via_hdr in serialized
        assert "From:" in serialized
        assert "To:" in serialized

    def test_response_roundtrip(self) -> None:
        msg = SipMessage.parse(OK_200)
        serialized = msg.serialize()
        assert serialized.startswith("SIP/2.0 200 OK\r\n")

    def test_content_length_auto_set(self) -> None:
        msg = SipMessage.parse(INVITE)
        assert isinstance(msg, SipRequest)
        msg.text = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n"
        serialized = msg.serialize()
        body_len = len(msg.body)
        assert f"Content-Length: {body_len}" in serialized

    def test_bytes(self) -> None:
        msg = SipMessage.parse(INVITE)
        raw_bytes = bytes(msg)
        assert isinstance(raw_bytes, bytes)
        assert raw_bytes.startswith(b"INVITE")


class TestModifyAndReserialize:
    def test_add_via(self) -> None:
        msg = SipMessage.parse(INVITE)
        new_via = Via(
            protocol="SIP/2.0",
            transport="UDP",
            host="proxy.example.com",
            port=5060,
            params={"branch": "z9hG4bKnew"},
        )
        current_vias = msg.via
        msg.via = [new_via] + current_vias
        assert len(msg.via) == 2
        assert msg.via[0].host == "proxy.example.com"

    def test_change_contact(self) -> None:
        msg = SipMessage.parse(INVITE)
        new_contact = Address(
            uri=SipUri(scheme="sip", user="alice", host="newhost.example.com", port=5060)
        )
        msg.contact = [new_contact]
        contacts = msg.contact
        assert len(contacts) == 1
        assert contacts[0].uri.host == "newhost.example.com"

    def test_set_cseq(self) -> None:
        msg = SipMessage.parse(INVITE)
        msg.cseq = CSeq(seq=2, method="INVITE")
        assert msg.cseq is not None
        assert msg.cseq.seq == 2


class TestXHeaders:
    def test_x_header_roundtrip(self) -> None:
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "X-Custom-ID: my-custom-value\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert msg.get_header("X-Custom-ID") == "my-custom-value"
        assert msg.get_header("x-custom-id") == "my-custom-value"

    def test_add_x_header(self) -> None:
        msg = SipMessage.parse(INVITE)
        msg.add_header("X-Session-Info", "test-session")
        assert msg.get_header("X-Session-Info") == "test-session"
        serialized = msg.serialize()
        assert "X-Session-Info: test-session" in serialized

    def test_set_x_header(self) -> None:
        msg = SipMessage.parse(INVITE)
        msg.set_header("X-Debug", "true")
        msg.set_header("X-Debug", "false")
        assert msg.get_header("X-Debug") == "false"
        assert len(msg.get_header_values("X-Debug")) == 1


class TestBinaryBodies:
    """Bodies are raw bytes (RFC 3261 §7.4) — binary payloads must survive."""

    def test_binary_body_roundtrip(self) -> None:
        payload = bytes(range(256))  # includes invalid UTF-8 sequences
        msg = SipRequest(method="INFO", uri="sip:bob@example.com")
        msg.headers.set_single("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bin")
        msg.headers.set_single("Content-Type", "application/octet-stream")
        msg.body = payload

        reparsed = SipMessage.parse(bytes(msg))

        assert reparsed.body == payload
        assert reparsed.content_length == 256

    def test_parse_accepts_str(self) -> None:
        msg = SipMessage.parse("OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h\r\n\r\n")
        assert isinstance(msg, SipRequest)
        assert msg.body == b""

    def test_text_property_round_trips(self) -> None:
        msg = SipRequest(method="MESSAGE", uri="sip:a@b")
        msg.text = "héllo"
        assert msg.body == "héllo".encode()
        assert msg.text == "héllo"

    def test_body_trimmed_to_content_length(self) -> None:
        raw = b"INFO sip:a@b SIP/2.0\r\nContent-Length: 4\r\n\r\n1234TRAILING-GARBAGE"
        msg = SipMessage.parse(raw)
        assert msg.body == b"1234"

    def test_short_body_kept(self) -> None:
        raw = b"INFO sip:a@b SIP/2.0\r\nContent-Length: 100\r\n\r\nshort"
        msg = SipMessage.parse(raw)
        assert msg.body == b"short"

    def test_unparseable_content_length_ignored(self) -> None:
        raw = b"INFO sip:a@b SIP/2.0\r\nContent-Length: abc\r\n\r\nbody"
        msg = SipMessage.parse(raw)
        assert msg.body == b"body"

    def test_parse_sdp_rejects_bytes(self) -> None:
        import pytest

        from aiosipua.sdp import parse_sdp

        with pytest.raises(TypeError, match="message.text"):
            parse_sdp(b"v=0\r\n")  # type: ignore[arg-type]
