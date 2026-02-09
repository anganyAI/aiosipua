"""Tests for aiosipua.transport — UDP and TCP SIP transports."""

import asyncio

import pytest

from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.transport import (
    TcpSipTransport,
    UdpSipTransport,
    _read_sip_message,
    _response_destination,
)

INVITE_RAW = (
    "INVITE sip:bob@example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test1\r\n"
    "From: <sip:alice@example.com>;tag=aaa\r\n"
    "To: <sip:bob@example.com>\r\n"
    "Call-ID: test-call@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

OK_200_RAW = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test1\r\n"
    "From: <sip:alice@example.com>;tag=aaa\r\n"
    "To: <sip:bob@example.com>;tag=bbb\r\n"
    "Call-ID: test-call@example.com\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


class TestResponseDestination:
    def test_basic_via(self) -> None:
        msg = SipMessage.parse(OK_200_RAW)
        assert isinstance(msg, SipResponse)
        dest = _response_destination(msg)
        assert dest == ("10.0.0.1", 5060)

    def test_received_overrides_host(self) -> None:
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;received=203.0.113.5;branch=z9hG4bK1\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipResponse)
        dest = _response_destination(msg)
        assert dest is not None
        assert dest[0] == "203.0.113.5"
        assert dest[1] == 5060

    def test_rport_overrides_port(self) -> None:
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;rport=12345;branch=z9hG4bK1\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipResponse)
        dest = _response_destination(msg)
        assert dest is not None
        assert dest[1] == 12345

    def test_received_and_rport(self) -> None:
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060"
            ";received=203.0.113.5;rport=54321;branch=z9hG4bK1\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipResponse)
        dest = _response_destination(msg)
        assert dest == ("203.0.113.5", 54321)

    def test_no_via(self) -> None:
        raw = "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipResponse)
        assert _response_destination(msg) is None

    def test_default_port(self) -> None:
        raw = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK1\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipResponse)
        dest = _response_destination(msg)
        assert dest == ("proxy.example.com", 5060)


class TestUdpLoopback:
    @pytest.mark.asyncio
    async def test_send_receive(self) -> None:
        received: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        event = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append((msg, addr))
            event.set()

        server = UdpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        # Get the actual bound port
        assert server._udp_transport is not None
        sock = server._udp_transport.get_extra_info("socket")
        server_port = sock.getsockname()[1]

        client = UdpSipTransport(local_addr=("127.0.0.1", 0))
        await client.start()

        try:
            invite = SipMessage.parse(INVITE_RAW)
            assert isinstance(invite, SipRequest)
            client.send(invite, ("127.0.0.1", server_port))

            await asyncio.wait_for(event.wait(), timeout=2.0)
            assert len(received) == 1
            msg, addr = received[0]
            assert isinstance(msg, SipRequest)
            assert msg.method == "INVITE"
            assert addr[0] == "127.0.0.1"
        finally:
            await client.stop()
            await server.stop()

    @pytest.mark.asyncio
    async def test_send_response(self) -> None:
        received: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        event = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append((msg, addr))
            event.set()

        server = UdpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        assert server._udp_transport is not None
        sock = server._udp_transport.get_extra_info("socket")
        server_port = sock.getsockname()[1]

        client = UdpSipTransport(local_addr=("127.0.0.1", 0))
        await client.start()

        try:
            ok = SipMessage.parse(OK_200_RAW)
            assert isinstance(ok, SipResponse)
            client.send(ok, ("127.0.0.1", server_port))

            await asyncio.wait_for(event.wait(), timeout=2.0)
            assert len(received) == 1
            msg, _ = received[0]
            assert isinstance(msg, SipResponse)
            assert msg.status_code == 200
        finally:
            await client.stop()
            await server.stop()

    @pytest.mark.asyncio
    async def test_send_reply_via_routing(self) -> None:
        """Test send_reply uses Via-based routing."""
        received: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        event = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append((msg, addr))
            event.set()

        # This transport will receive the reply
        receiver = UdpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await receiver.start()

        assert receiver._udp_transport is not None
        sock = receiver._udp_transport.get_extra_info("socket")
        receiver_port = sock.getsockname()[1]

        sender = UdpSipTransport(local_addr=("127.0.0.1", 0))
        await sender.start()

        try:
            # Build a response whose Via points to the receiver
            raw = (
                "SIP/2.0 200 OK\r\n"
                f"Via: SIP/2.0/UDP 127.0.0.1:{receiver_port};branch=z9hG4bK-vr1\r\n"
                "From: <sip:alice@example.com>;tag=aaa\r\n"
                "To: <sip:bob@example.com>;tag=bbb\r\n"
                "Call-ID: viaroute@example.com\r\n"
                "CSeq: 1 INVITE\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            response = SipMessage.parse(raw)
            assert isinstance(response, SipResponse)
            sender.send_reply(response)

            await asyncio.wait_for(event.wait(), timeout=2.0)
            assert len(received) == 1
            msg, _ = received[0]
            assert isinstance(msg, SipResponse)
            assert msg.status_code == 200
        finally:
            await sender.stop()
            await receiver.stop()

    @pytest.mark.asyncio
    async def test_send_before_start_raises(self) -> None:
        transport = UdpSipTransport(local_addr=("127.0.0.1", 0))
        invite = SipMessage.parse(INVITE_RAW)
        assert isinstance(invite, SipRequest)
        with pytest.raises(RuntimeError, match="not started"):
            transport.send(invite, ("127.0.0.1", 5060))

    @pytest.mark.asyncio
    async def test_multiple_messages(self) -> None:
        received: list[SipRequest | SipResponse] = []
        all_received = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append(msg)
            if len(received) >= 3:
                all_received.set()

        server = UdpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        assert server._udp_transport is not None
        sock = server._udp_transport.get_extra_info("socket")
        server_port = sock.getsockname()[1]

        client = UdpSipTransport(local_addr=("127.0.0.1", 0))
        await client.start()

        try:
            invite = SipMessage.parse(INVITE_RAW)
            assert isinstance(invite, SipRequest)
            for _ in range(3):
                client.send(invite, ("127.0.0.1", server_port))

            await asyncio.wait_for(all_received.wait(), timeout=2.0)
            assert len(received) == 3
        finally:
            await client.stop()
            await server.stop()


class TestTcpLoopback:
    @pytest.mark.asyncio
    async def test_send_receive(self) -> None:
        received: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        event = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append((msg, addr))
            event.set()

        server = TcpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        assert server._server is not None
        server_port = server._server.sockets[0].getsockname()[1]

        client = TcpSipTransport(local_addr=("127.0.0.1", 0))
        await client.connect(("127.0.0.1", server_port))

        try:
            invite = SipMessage.parse(INVITE_RAW)
            assert isinstance(invite, SipRequest)
            client.send(invite, ("127.0.0.1", server_port))

            await asyncio.wait_for(event.wait(), timeout=2.0)
            assert len(received) == 1
            msg, _ = received[0]
            assert isinstance(msg, SipRequest)
            assert msg.method == "INVITE"
        finally:
            await client.stop()
            await server.stop()

    @pytest.mark.asyncio
    async def test_message_with_body(self) -> None:
        received: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        event = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append((msg, addr))
            event.set()

        server = TcpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        assert server._server is not None
        server_port = server._server.sockets[0].getsockname()[1]

        client = TcpSipTransport(local_addr=("127.0.0.1", 0))
        await client.connect(("127.0.0.1", server_port))

        try:
            sdp_body = "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\n"
            raw = (
                "INVITE sip:bob@example.com SIP/2.0\r\n"
                "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-tcp1\r\n"
                "From: <sip:alice@example.com>;tag=aaa\r\n"
                "To: <sip:bob@example.com>\r\n"
                "Call-ID: tcp-test@example.com\r\n"
                "CSeq: 1 INVITE\r\n"
                "Content-Type: application/sdp\r\n"
                f"Content-Length: {len(sdp_body)}\r\n"
                "\r\n"
                f"{sdp_body}"
            )
            invite = SipMessage.parse(raw)
            assert isinstance(invite, SipRequest)
            client.send(invite, ("127.0.0.1", server_port))

            await asyncio.wait_for(event.wait(), timeout=2.0)
            assert len(received) == 1
            msg, _ = received[0]
            assert isinstance(msg, SipRequest)
            assert msg.body == sdp_body
        finally:
            await client.stop()
            await server.stop()

    @pytest.mark.asyncio
    async def test_multiple_messages_on_same_connection(self) -> None:
        received: list[SipRequest | SipResponse] = []
        all_received = asyncio.Event()

        def on_msg(msg: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
            received.append(msg)
            if len(received) >= 3:
                all_received.set()

        server = TcpSipTransport(local_addr=("127.0.0.1", 0), on_message=on_msg)
        await server.start()

        assert server._server is not None
        server_port = server._server.sockets[0].getsockname()[1]

        client = TcpSipTransport(local_addr=("127.0.0.1", 0))
        await client.connect(("127.0.0.1", server_port))

        try:
            invite = SipMessage.parse(INVITE_RAW)
            assert isinstance(invite, SipRequest)
            for _ in range(3):
                client.send(invite, ("127.0.0.1", server_port))

            await asyncio.wait_for(all_received.wait(), timeout=2.0)
            assert len(received) == 3
            for msg in received:
                assert isinstance(msg, SipRequest)
                assert msg.method == "INVITE"
        finally:
            await client.stop()
            await server.stop()

    @pytest.mark.asyncio
    async def test_no_connection_raises(self) -> None:
        transport = TcpSipTransport(local_addr=("127.0.0.1", 0))
        invite = SipMessage.parse(INVITE_RAW)
        assert isinstance(invite, SipRequest)
        with pytest.raises(RuntimeError, match="No TCP connection"):
            transport.send(invite, ("127.0.0.1", 5060))


class TestReadSipMessage:
    @pytest.mark.asyncio
    async def test_read_no_body(self) -> None:
        raw = INVITE_RAW.encode()
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()

        data = await _read_sip_message(reader)
        assert data is not None
        msg = SipMessage.parse(data.decode())
        assert isinstance(msg, SipRequest)
        assert msg.method == "INVITE"

    @pytest.mark.asyncio
    async def test_read_with_body(self) -> None:
        body = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n"
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-t1\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        ).encode()
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()

        data = await _read_sip_message(reader)
        assert data is not None
        msg = SipMessage.parse(data.decode())
        assert isinstance(msg, SipRequest)
        assert msg.body == body

    @pytest.mark.asyncio
    async def test_read_eof_returns_none(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_eof()

        data = await _read_sip_message(reader)
        assert data is None

    @pytest.mark.asyncio
    async def test_read_compact_content_length(self) -> None:
        body = "v=0\r\n"
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-t2\r\n"
            f"l: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        ).encode()
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()

        data = await _read_sip_message(reader)
        assert data is not None
        assert body.encode() in data
