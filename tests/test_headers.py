"""Tests for aiosipua.headers."""

from aiosipua.headers import (
    Address,
    AuthChallenge,
    CaseInsensitiveDict,
    CSeq,
    SipUri,
    Via,
    expand_compact_header,
    parse_address,
    parse_auth,
    parse_cseq,
    parse_params,
    parse_uri,
    parse_via,
    prettify_header_name,
    stringify_address,
    stringify_cseq,
    stringify_uri,
    stringify_via,
)


class TestCaseInsensitiveDict:
    def test_set_and_get(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("Content-Type", "application/sdp")
        assert d.get_first("content-type") == "application/sdp"
        assert d.get_first("CONTENT-TYPE") == "application/sdp"

    def test_append(self) -> None:
        d = CaseInsensitiveDict()
        d.append("Via", "SIP/2.0/UDP a.example.com")
        d.append("Via", "SIP/2.0/UDP b.example.com")
        assert len(d.get("via")) == 2

    def test_contains(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("From", "sip:alice@example.com")
        assert "from" in d
        assert "FROM" in d
        assert "From" in d
        assert "X-Missing" not in d

    def test_remove(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("To", "sip:bob@example.com")
        d.remove("TO")
        assert "to" not in d

    def test_preserves_original_casing(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("Content-Type", "application/sdp")
        names = [name for name, _ in d.items()]
        assert "Content-Type" in names

    def test_len(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("a", "1")
        d.set_single("b", "2")
        assert len(d) == 2

    def test_copy(self) -> None:
        d = CaseInsensitiveDict()
        d.set_single("Via", "test")
        d2 = d.copy()
        d2.set_single("Via", "changed")
        assert d.get_first("Via") == "test"
        assert d2.get_first("Via") == "changed"

    def test_get_first_default(self) -> None:
        d = CaseInsensitiveDict()
        assert d.get_first("missing") is None
        assert d.get_first("missing", "fallback") == "fallback"


class TestCompactHeaders:
    def test_expand_known(self) -> None:
        assert expand_compact_header("v") == "via"
        assert expand_compact_header("f") == "from"
        assert expand_compact_header("t") == "to"
        assert expand_compact_header("i") == "call-id"
        assert expand_compact_header("m") == "contact"
        assert expand_compact_header("l") == "content-length"
        assert expand_compact_header("c") == "content-type"
        assert expand_compact_header("e") == "content-encoding"
        assert expand_compact_header("s") == "subject"
        assert expand_compact_header("k") == "supported"

    def test_expand_case_insensitive(self) -> None:
        assert expand_compact_header("V") == "via"
        assert expand_compact_header("F") == "from"

    def test_expand_unknown(self) -> None:
        assert expand_compact_header("X-Custom") == "X-Custom"
        assert expand_compact_header("Via") == "Via"


class TestPrettifyHeaderName:
    def test_known_headers(self) -> None:
        assert prettify_header_name("call-id") == "Call-ID"
        assert prettify_header_name("cseq") == "CSeq"
        assert prettify_header_name("www-authenticate") == "WWW-Authenticate"
        assert prettify_header_name("content-type") == "Content-Type"
        assert prettify_header_name("mime-version") == "MIME-Version"

    def test_unknown_title_case(self) -> None:
        assert prettify_header_name("x-custom-header") == "X-Custom-Header"
        assert prettify_header_name("x-foo") == "X-Foo"


class TestParseParams:
    def test_key_value(self) -> None:
        result = parse_params("transport=udp;branch=z9hG4bK1234")
        assert result["transport"] == "udp"
        assert result["branch"] == "z9hG4bK1234"

    def test_valueless(self) -> None:
        result = parse_params("lr;rport")
        assert result["lr"] is None
        assert result["rport"] is None

    def test_empty(self) -> None:
        result = parse_params("")
        assert result == {}


class TestSipUri:
    def test_basic(self) -> None:
        uri = parse_uri("sip:alice@example.com")
        assert uri.scheme == "sip"
        assert uri.user == "alice"
        assert uri.host == "example.com"
        assert uri.port is None

    def test_with_port(self) -> None:
        uri = parse_uri("sip:alice@example.com:5060")
        assert uri.host == "example.com"
        assert uri.port == 5060

    def test_sips(self) -> None:
        uri = parse_uri("sips:bob@secure.example.com")
        assert uri.scheme == "sips"
        assert uri.user == "bob"

    def test_no_user(self) -> None:
        uri = parse_uri("sip:example.com")
        assert uri.user is None
        assert uri.host == "example.com"

    def test_params(self) -> None:
        uri = parse_uri("sip:alice@example.com;transport=tcp;lr")
        assert uri.params["transport"] == "tcp"
        assert uri.params["lr"] is None

    def test_headers(self) -> None:
        uri = parse_uri("sip:alice@example.com?subject=hello&priority=urgent")
        assert uri.headers["subject"] == "hello"
        assert uri.headers["priority"] == "urgent"

    def test_stringify_roundtrip(self) -> None:
        original = "sip:alice@example.com:5060;transport=tcp"
        uri = parse_uri(original)
        result = stringify_uri(uri)
        assert result == original

    def test_stringify_no_user(self) -> None:
        uri = SipUri(scheme="sip", host="example.com", port=5060)
        assert stringify_uri(uri) == "sip:example.com:5060"


class TestAddress:
    def test_name_addr(self) -> None:
        addr = parse_address('"Alice" <sip:alice@example.com>;tag=abc123')
        assert addr.display_name == "Alice"
        assert addr.uri.user == "alice"
        assert addr.uri.host == "example.com"
        assert addr.tag == "abc123"

    def test_name_addr_no_quotes(self) -> None:
        addr = parse_address("Alice <sip:alice@example.com>")
        assert addr.display_name == "Alice"
        assert addr.uri.user == "alice"

    def test_addr_spec(self) -> None:
        addr = parse_address("sip:alice@example.com")
        assert addr.display_name is None
        assert addr.uri.user == "alice"

    def test_angle_brackets_no_display(self) -> None:
        addr = parse_address("<sip:alice@example.com>")
        assert addr.display_name is None
        assert addr.uri.user == "alice"

    def test_addr_spec_with_tag(self) -> None:
        addr = parse_address("sip:alice@example.com;tag=xyz")
        assert addr.tag == "xyz"
        assert addr.uri.user == "alice"

    def test_stringify_roundtrip(self) -> None:
        addr = Address(
            display_name="Alice",
            uri=SipUri(scheme="sip", user="alice", host="example.com"),
            params={"tag": "abc"},
        )
        s = stringify_address(addr)
        assert '"Alice" <sip:alice@example.com>' in s
        assert ";tag=abc" in s

    def test_tag_property(self) -> None:
        addr = Address()
        assert addr.tag is None
        addr.tag = "newtag"
        assert addr.tag == "newtag"
        addr.tag = None
        assert addr.tag is None


class TestVia:
    def test_basic(self) -> None:
        via = parse_via("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1234")
        assert via.protocol == "SIP/2.0"
        assert via.transport == "UDP"
        assert via.host == "192.168.1.1"
        assert via.port == 5060
        assert via.branch == "z9hG4bK1234"

    def test_tcp(self) -> None:
        via = parse_via("SIP/2.0/TCP example.com;branch=z9hG4bKabc")
        assert via.transport == "TCP"
        assert via.host == "example.com"
        assert via.port is None
        assert via.branch == "z9hG4bKabc"

    def test_rport(self) -> None:
        via = parse_via("SIP/2.0/UDP 10.0.0.1:5060;rport;branch=z9hG4bK1")
        assert via.rport is None  # valueless
        assert via.branch == "z9hG4bK1"

    def test_received(self) -> None:
        via = parse_via("SIP/2.0/UDP 10.0.0.1:5060;received=203.0.113.1;branch=z9hG4bK1")
        assert via.received == "203.0.113.1"

    def test_stringify_roundtrip(self) -> None:
        original = "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1234"
        via = parse_via(original)
        assert stringify_via(via) == original

    def test_branch_property(self) -> None:
        via = Via()
        via.branch = "z9hG4bKtest"
        assert via.branch == "z9hG4bKtest"
        via.branch = None
        assert via.branch is None


class TestCSeq:
    def test_parse(self) -> None:
        cseq = parse_cseq("1 INVITE")
        assert cseq.seq == 1
        assert cseq.method == "INVITE"

    def test_stringify(self) -> None:
        assert stringify_cseq(CSeq(seq=102, method="REGISTER")) == "102 REGISTER"

    def test_roundtrip(self) -> None:
        original = "42 BYE"
        assert stringify_cseq(parse_cseq(original)) == original


class TestAuth:
    def test_parse_challenge(self) -> None:
        s = 'Digest realm="example.com", nonce="abc123", algorithm=MD5'
        auth = parse_auth(s)
        assert isinstance(auth, AuthChallenge)
        assert auth.scheme == "Digest"
        assert auth.params["realm"] == "example.com"
        assert auth.params["nonce"] == "abc123"
        assert auth.params["algorithm"] == "MD5"

    def test_parse_credentials(self) -> None:
        s = 'Digest username="alice", realm="example.com", response="def456"'
        auth = parse_auth(s, credentials=True)
        assert auth.scheme == "Digest"
        assert auth.params["username"] == "alice"
        assert auth.params["response"] == "def456"
