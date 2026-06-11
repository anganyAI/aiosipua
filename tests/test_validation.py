"""Tests for boundary validation: header injection, required headers, size caps."""

from __future__ import annotations

import asyncio

import pytest

from aiosipua.headers import CaseInsensitiveDict
from aiosipua.message import MAX_HEADERS, SipMessage, SipRequest, SipResponse
from aiosipua.transport import MAX_HEADER_BYTES, TcpSipTransport
from aiosipua.uas import SipUAS
from tests.support import FakeTransport


class TestHeaderInjection:
    """set_single/append are the boundary where app data enters headers (CWE-93)."""

    def test_value_with_crlf_rejected(self) -> None:
        headers = CaseInsensitiveDict()
        with pytest.raises(ValueError, match="line breaks"):
            headers.set_single("X-Room-ID", "room-1\r\nX-Evil: injected")

    def test_value_with_bare_newline_rejected(self) -> None:
        headers = CaseInsensitiveDict()
        with pytest.raises(ValueError, match="line breaks"):
            headers.append("Subject", "hello\nVia: SIP/2.0/UDP evil")

    def test_name_with_newline_rejected(self) -> None:
        headers = CaseInsensitiveDict()
        with pytest.raises(ValueError, match="Invalid header name"):
            headers.set_single("X-Bad\r\nX-Evil", "x")

    def test_name_with_colon_rejected(self) -> None:
        headers = CaseInsensitiveDict()
        with pytest.raises(ValueError, match="Invalid header name"):
            headers.set_single("X-Bad: foo", "x")

    def test_extra_headers_path_is_protected(self) -> None:
        """User-supplied extra_headers in send_invite cannot inject lines."""
        from aiosipua.uac import SipUAC

        uac = SipUAC(FakeTransport())  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="line breaks"):
            uac.send_invite(
                "sip:a@x",
                "sip:b@x",
                ("10.0.0.1", 5060),
                extra_headers={"X-Room-ID": "r\r\nContact: <sip:evil@1.2.3.4>"},
            )


class TestRequiredHeaders:
    def _uas(self) -> tuple[FakeTransport, SipUAS]:
        transport = FakeTransport()
        uas = SipUAS(transport)  # type: ignore[arg-type]
        transport.on_message = uas._on_message
        return transport, uas

    def test_request_without_from_gets_400(self) -> None:
        transport, uas = self._uas()
        transport.inject(
            "OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vr-1\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: vr-1@example.com\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 400

    def test_request_without_via_is_dropped(self) -> None:
        transport, uas = self._uas()
        transport.inject(
            "OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "From: <sip:alice@example.com>;tag=t\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: vr-2@example.com\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        assert transport.sent == []  # nowhere to route a reply

    def test_complete_request_passes(self) -> None:
        transport, uas = self._uas()
        transport.inject(
            "OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vr-3\r\n"
            "From: <sip:alice@example.com>;tag=t\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: vr-3@example.com\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        resp = transport.sent[-1][0]
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200


class TestSizeCaps:
    def test_too_many_headers_rejected(self) -> None:
        raw = "OPTIONS sip:a@b SIP/2.0\r\n"
        raw += "".join(f"X-Pad-{i}: x\r\n" for i in range(MAX_HEADERS + 1))
        raw += "\r\n"
        with pytest.raises(ValueError, match="Too many headers"):
            SipMessage.parse(raw)

    def test_header_count_at_limit_accepted(self) -> None:
        raw = "OPTIONS sip:a@b SIP/2.0\r\n"
        raw += "".join(f"X-Pad-{i}: x\r\n" for i in range(MAX_HEADERS - 1))
        raw += "\r\n"
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipRequest)

    @pytest.mark.asyncio()
    async def test_tcp_oversized_headers_drop_connection(self) -> None:
        received: list[SipRequest | SipResponse] = []
        server = TcpSipTransport(local_addr=("127.0.0.1", 0))
        server.on_message = lambda msg, addr: received.append(msg)
        await server.start()
        assert server._server is not None
        port = server._server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"INVITE sip:a@b SIP/2.0\r\n")
        # Stream header lines past the cap — the server must hang up
        chunk = b"X-Pad: " + b"a" * 1000 + b"\r\n"
        for _ in range(MAX_HEADER_BYTES // len(chunk) + 2):
            writer.write(chunk)
        await writer.drain()

        eof = await asyncio.wait_for(reader.read(), timeout=2.0)
        assert eof == b""  # connection closed by the server
        assert received == []

        writer.close()
        await server.stop()

    @pytest.mark.asyncio()
    async def test_tcp_oversized_body_drops_connection(self) -> None:
        received: list[SipRequest | SipResponse] = []
        server = TcpSipTransport(local_addr=("127.0.0.1", 0))
        server.on_message = lambda msg, addr: received.append(msg)
        await server.start()
        assert server._server is not None
        port = server._server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"INVITE sip:a@b SIP/2.0\r\n"
            b"Via: SIP/2.0/TCP 127.0.0.1\r\n"
            b"Content-Length: 99999999\r\n"
            b"\r\n"
        )
        await writer.drain()

        eof = await asyncio.wait_for(reader.read(), timeout=2.0)
        assert eof == b""
        assert received == []

        writer.close()
        await server.stop()
