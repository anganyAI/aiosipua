"""Torture tests from RFC 4475 — the parser must survive hostile-but-legal SIP.

Wellformed messages (§3.1.1) must parse with their key fields intact;
invalid ones (§3.1.2) must never crash the parser with anything but
ValueError. Fixtures are transcribed from the RFC (CRLF line endings,
folding preserved).
"""

from __future__ import annotations

import pytest

from aiosipua.message import SipMessage, SipRequest, SipResponse

# RFC 4475 §3.1.1.1 — "A Short Tortuous INVITE" (wsinv)
WSINV = (
    "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n"
    "TO :\r\n"
    " sip:vivekg@chair-dnrc.example.com ;   tag    = 1918181833n\r\n"
    'from   : "J Rosenberg \\\\\\""       <sip:jdrosen@example.com>\r\n'
    "  ;\r\n"
    "  tag = 98asjd8\r\n"
    "MaX-fOrWaRdS: 0068\r\n"
    "Call-ID: wsinv.ndaksdj@192.0.2.1\r\n"
    "Content-Length   : 150\r\n"
    "cseq: 0009\r\n"
    "  INVITE\r\n"
    "Via  : SIP  /   2.0\r\n"
    " /UDP\r\n"
    "    192.0.2.2;branch=390skdjuw\r\n"
    "s :\r\n"
    "NewFangledHeader:   newfangled value\r\n"
    " continued newfangled value\r\n"
    "UnknownHeaderWithUnusualValue: ;;,,;;,;\r\n"
    "Content-Type: application/sdp\r\n"
    "Route:\r\n"
    " <sip:services.example.com;lr;unknownwith=value;unknown-no-value>\r\n"
    "v:  SIP  / 2.0  / TCP     spindle.example.com   ;\r\n"
    "  branch  =   z9hG4bK9ikj8  ,\r\n"
    " SIP  /    2.0   / UDP  192.168.255.111   ; branch=\r\n"
    " z9hG4bK30239\r\n"
    'm:"Quoted string \\"\\"" <sip:jdrosen@example.com> ; newparam =\r\n'
    "      newvalue ;\r\n"
    "  secondparam ; q = 0.33\r\n"
    "\r\n"
    "v=0\r\n"
    "o=mhandley 29739 7272939 IN IP4 192.0.2.3\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.4\r\n"
    "t=0 0\r\n"
    "m=audio 49217 RTP/AVP 0 12\r\n"
    "m=video 3227 RTP/AVP 31\r\n"
    "a=rtpmap:31 LPC\r\n"
)

# RFC 4475 §3.1.1.6 — no LWS between display name and < (lwsdisp)
LWSDISP = (
    "OPTIONS sip:user@example.com SIP/2.0\r\n"
    "To: sip:user@example.com\r\n"
    "From: caller<sip:caller@example.com>;tag=323\r\n"
    "Max-Forwards: 70\r\n"
    "Call-ID: lwsdisp.1234abcd@funky.example.com\r\n"
    "CSeq: 60 OPTIONS\r\n"
    "Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw\r\n"
    "l: 0\r\n"
    "\r\n"
)

_SDP_BODY = (
    "v=0\r\n"
    "o=mhandley 29739 7272939 IN IP4 192.0.2.155\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.155\r\n"
    "t=0 0\r\n"
    "m=audio 49217 RTP/AVP 0 12\r\n"
    "m=video 3227 RTP/AVP 31\r\n"
    "a=rtpmap:31 LPC\r\n"
)

# RFC 4475 §3.1.2.2 — Content-Length larger than message (clerr)
CLERR = (
    "INVITE sip:user@example.com SIP/2.0\r\n"
    "Max-Forwards: 80\r\n"
    "To: sip:j.user@example.com\r\n"
    "From: sip:caller@example.net;tag=93942939o2\r\n"
    "Contact: <sip:caller@hungry.example.net>\r\n"
    "Call-ID: clerr.0ha0isndaksdjweiafasdk3\r\n"
    "CSeq: 8 INVITE\r\n"
    "Via: SIP/2.0/UDP host5.example.com;branch=z9hG4bK-39234-23523\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 9999\r\n"
    "\r\n" + _SDP_BODY
)

# RFC 4475 §3.1.2.3 — negative Content-Length (ncl)
NCL = (
    "INVITE sip:user@example.com SIP/2.0\r\n"
    "Max-Forwards: 254\r\n"
    "To: sip:j.user@example.com\r\n"
    "From: sip:caller@example.net;tag=32394234\r\n"
    "Call-ID: ncl.0ha0isndaksdj2193423r542w35\r\n"
    "CSeq: 0 INVITE\r\n"
    "Via: SIP/2.0/UDP 192.0.2.53;branch=z9hG4bKkdjuw\r\n"
    "Contact: <sip:caller@example53.example.net>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: -999\r\n"
    "\r\n" + _SDP_BODY
)

# Modeled on RFC 4475 §3.1.2.4 — scalar fields with overlarge values
SCALAR_OVERFLOW = (
    "REGISTER sip:example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP host129.example.com;branch=z9hG4bK-39562\r\n"
    "To: <sip:user@example.com>\r\n"
    "From: <sip:user@example.com>;tag=998\r\n"
    "Max-Forwards: 300\r\n"
    "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
    "CSeq: 36893488147419103232 REGISTER\r\n"
    "Expires: 1000000000000000000\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


class TestWellformed:
    def test_wsinv_parses_with_key_fields(self) -> None:
        msg = SipMessage.parse(WSINV)
        assert isinstance(msg, SipRequest)
        assert msg.method == "INVITE"
        assert msg.call_id == "wsinv.ndaksdj@192.0.2.1"

        cseq = msg.cseq
        assert cseq is not None
        assert (cseq.seq, cseq.method) == (9, "INVITE")

        assert msg.get_header("max-forwards") == "0068"

        to_addr = msg.to_addr
        assert to_addr is not None
        assert to_addr.tag == "1918181833n"
        assert to_addr.uri.user == "vivekg"

        from_addr = msg.from_addr
        assert from_addr is not None
        assert from_addr.tag == "98asjd8"

        # One folded Via plus two comma-separated on the compact "v:" line
        assert len(msg.headers.get("via")) == 3

        # Folded unknown header is unfolded
        assert "continued newfangled value" in (msg.get_header("NewFangledHeader") or "")

        # Body trimmed to the declared 150 bytes, still parseable SDP
        assert msg.content_length == 150
        assert msg.text.startswith("v=0")

    def test_lwsdisp_display_name_without_lws(self) -> None:
        msg = SipMessage.parse(LWSDISP)
        assert isinstance(msg, SipRequest)
        assert msg.method == "OPTIONS"
        from_addr = msg.from_addr
        assert from_addr is not None
        assert from_addr.tag == "323"
        assert from_addr.uri.user == "caller"
        assert msg.content_length == 0


class TestInvalid:
    """Invalid messages must never crash with anything but ValueError."""

    @pytest.mark.parametrize(
        "raw",
        [CLERR, NCL, SCALAR_OVERFLOW],
        ids=["clerr", "ncl", "scalar-overflow"],
    )
    def test_parse_does_not_crash(self, raw: str) -> None:
        try:
            msg = SipMessage.parse(raw)
        except ValueError:
            return
        assert isinstance(msg, SipRequest | SipResponse)

    def test_clerr_short_body_kept(self) -> None:
        msg = SipMessage.parse(CLERR)
        assert msg.body == _SDP_BODY.encode()

    def test_ncl_negative_length_ignored(self) -> None:
        msg = SipMessage.parse(NCL)
        assert msg.body == _SDP_BODY.encode()

    def test_scalar_overflow_fields_accessible(self) -> None:
        msg = SipMessage.parse(SCALAR_OVERFLOW)
        cseq = msg.cseq
        assert cseq is not None
        assert cseq.seq == 36893488147419103232

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "\r\n\r\n",
            "SIP/2.0\r\n\r\n",
            "SIP/2.0 abc Bogus\r\n\r\n",
            "INVITE\r\n\r\n",
            ";;;,,,\r\nVia;;;\r\n\r\n",
            "INVITE sip:a@b SIP/2.0\r\nVia\r\n: broken\r\n\r\n",
            "\x00\x01\x02\r\n\r\n",
        ],
        ids=[
            "empty",
            "blank",
            "bare-version",
            "non-numeric-status",
            "method-only",
            "separator-soup",
            "split-header-name",
            "binary-startline",
        ],
    )
    def test_garbage_raises_value_error_or_parses(self, raw: str) -> None:
        try:
            msg = SipMessage.parse(raw)
        except ValueError:
            return
        assert isinstance(msg, SipRequest | SipResponse)
