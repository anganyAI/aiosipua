"""Tests for IPv6 support: bracketed serialization, SDP IP6, ::1 transport."""

from __future__ import annotations

import socket

import pytest

from aiosipua.headers import SipUri, Via, parse_uri, parse_via, stringify_uri, stringify_via
from aiosipua.sdp import build_sdp, negotiate_sdp, parse_sdp, serialize_sdp
from aiosipua.transport import UdpSipTransport
from aiosipua.uac import SipUAC
from aiosipua.uas import SipUAS
from aiosipua.utils import format_addr
from tests.support import FakeTransport


def _ipv6_loopback_available() -> bool:
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(("::1", 0))
        sock.close()
        return True
    except OSError:
        return False


class TestFormatting:
    def test_format_addr(self) -> None:
        assert format_addr("10.0.0.1", 5060) == "10.0.0.1:5060"
        assert format_addr("::1", 5060) == "[::1]:5060"
        assert format_addr("[::1]", 5060) == "[::1]:5060"
        assert format_addr("host.example.com", 5060) == "host.example.com:5060"

    def test_stringify_via_brackets_bare_ipv6(self) -> None:
        via = Via(transport="UDP", host="2001:db8::1", port=5060, params={"branch": "z9hG4bK-x"})
        assert stringify_via(via) == "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK-x"

    def test_stringify_via_keeps_brackets_and_v4(self) -> None:
        assert "[::1]:5060" in stringify_via(Via(host="[::1]", port=5060))
        assert "10.0.0.1:5060" in stringify_via(Via(host="10.0.0.1", port=5060))

    def test_via_round_trip(self) -> None:
        via = parse_via(stringify_via(Via(host="2001:db8::1", port=5062)))
        assert via.host == "[2001:db8::1]"
        assert via.port == 5062

    def test_stringify_uri_brackets_bare_ipv6(self) -> None:
        uri = SipUri(scheme="sip", user="alice", host="2001:db8::1", port=5060)
        assert stringify_uri(uri) == "sip:alice@[2001:db8::1]:5060"

    def test_uri_round_trip(self) -> None:
        uri = parse_uri("sip:alice@[2001:db8::1]:5060")
        assert uri.host == "[2001:db8::1]"
        assert uri.port == 5060
        assert stringify_uri(uri) == "sip:alice@[2001:db8::1]:5060"


class TestSdpIpv6:
    def test_build_sdp_uses_ip6(self) -> None:
        sdp = build_sdp("2001:db8::5", 30000, 0, "PCMU")
        text = serialize_sdp(sdp)
        assert "c=IN IP6 2001:db8::5" in text
        assert "IN IP6 2001:db8::5" in text.split("\r\n")[1]  # o= line

    def test_build_sdp_keeps_ip4(self) -> None:
        sdp = build_sdp("10.0.0.5", 30000, 0, "PCMU")
        assert "c=IN IP4 10.0.0.5" in serialize_sdp(sdp)

    def test_negotiated_answer_uses_ip6(self) -> None:
        offer = parse_sdp(
            "v=0\r\n"
            "o=- 1 1 IN IP6 2001:db8::9\r\n"
            "s=-\r\n"
            "c=IN IP6 2001:db8::9\r\n"
            "t=0 0\r\n"
            "m=audio 20000 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        answer, _pt = negotiate_sdp(offer, "2001:db8::5", 30000)
        assert "c=IN IP6 2001:db8::5" in serialize_sdp(answer)
        assert offer.rtp_address == ("2001:db8::9", 20000)


class TestSignalingIpv6:
    def test_invite_via_and_contact_bracketed(self) -> None:
        transport = FakeTransport(local_addr=("2001:db8::5", 5060))
        uac = SipUAC(transport)  # type: ignore[arg-type]
        call = uac.send_invite("sip:a@example.com", "sip:b@example.com", ("2001:db8::9", 5060))

        via_raw = call.invite.get_header("via") or ""
        assert "[2001:db8::5]:5060" in via_raw
        contact = call.invite.get_header("contact") or ""
        assert "<sip:[2001:db8::5]:5060>" in contact


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback")
class TestIpv6Loopback:
    @pytest.mark.asyncio()
    async def test_call_over_ipv6_udp(self) -> None:
        callee_transport = UdpSipTransport(local_addr=("::1", 0))
        callee = SipUAS(callee_transport)
        callee.on_invite = lambda call: call.accept()
        await callee.start()
        assert callee_transport._udp_transport is not None
        port = callee_transport._udp_transport.get_extra_info("socket").getsockname()[1]

        caller_transport = UdpSipTransport(local_addr=("::1", 0))
        caller_uac = SipUAC(caller_transport)
        caller = SipUAS(caller_transport, uac=caller_uac)
        await caller.start()

        try:
            call = caller_uac.send_invite("sip:a@[::1]", "sip:b@[::1]", ("::1", port))
            await call.wait_answered(timeout=2.0)
            assert call.dialog.state.value == "confirmed"
        finally:
            await caller.stop()
            await callee.stop()
