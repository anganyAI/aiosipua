"""Asyncio SIP transports: UDP (DatagramProtocol) and TCP (streams)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .message import SipMessage, SipRequest, SipResponse

logger = logging.getLogger(__name__)

# Type alias for the message callback: (message, sender_addr)
MessageCallback = Callable[[SipRequest | SipResponse, tuple[str, int]], None]


def _response_destination(msg: SipResponse) -> tuple[str, int] | None:
    """Determine where to send a response using Via-based routing (RFC 3261 §18.2.2).

    Uses the topmost Via header: ``received`` parameter overrides the host,
    ``rport`` parameter (with a value) overrides the port.
    """
    vias = msg.via
    if not vias:
        return None
    top_via = vias[0]

    host = top_via.received or top_via.host
    port_str = top_via.rport
    if port_str is not None and port_str != "":
        try:
            port = int(port_str)
        except ValueError:
            port = top_via.port or 5060
    else:
        port = top_via.port or 5060

    return (host, port)


# --- Base transport ---


@dataclass
class SipTransport:
    """Base class for SIP transports."""

    local_addr: tuple[str, int] = ("0.0.0.0", 5060)
    on_message: MessageCallback | None = None

    async def start(self) -> None:
        """Bind and start listening."""
        raise NotImplementedError

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        """Send a SIP message to the given address."""
        raise NotImplementedError

    def send_reply(self, response: SipResponse) -> None:
        """Send a SIP response using Via-based routing."""
        dest = _response_destination(response)
        if dest is None:
            raise ValueError("Cannot route response: no Via header")
        self.send(response, dest)

    async def stop(self) -> None:
        """Close the transport."""
        raise NotImplementedError

    def _dispatch(self, data: bytes, addr: tuple[str, int]) -> None:
        """Parse raw bytes and dispatch to callback."""
        try:
            text = data.decode("utf-8", errors="replace")
            msg = SipMessage.parse(text)
        except Exception:
            logger.warning("Failed to parse SIP message from %s", addr, exc_info=True)
            return

        if self.on_message is not None:
            try:
                self.on_message(msg, addr)
            except Exception:
                logger.exception("Error in message callback for %s", addr)


# --- UDP transport ---


class _UdpProtocol(asyncio.DatagramProtocol):
    """Internal DatagramProtocol that delegates to UdpSipTransport."""

    def __init__(self, transport_owner: UdpSipTransport) -> None:
        self._owner = transport_owner

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._owner._udp_transport = transport  # noqa: SLF001

    def datagram_received(self, data: bytes, addr: tuple[str, int] | Any) -> None:
        # addr may be (host, port) or (host, port, flow, scope) for IPv6
        remote = (str(addr[0]), int(addr[1]))
        self._owner._dispatch(data, remote)  # noqa: SLF001

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


@dataclass
class UdpSipTransport(SipTransport):
    """UDP SIP transport — each datagram is one complete SIP message."""

    _udp_transport: asyncio.DatagramTransport | None = field(default=None, init=False, repr=False)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self),
            local_addr=self.local_addr,
        )
        self._udp_transport = transport

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        if self._udp_transport is None:
            raise RuntimeError("Transport not started")
        raw = bytes(message)
        self._udp_transport.sendto(raw, addr)

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None


# --- TCP transport ---


@dataclass
class TcpSipTransport(SipTransport):
    """TCP SIP transport — Content-Length framing for message boundaries."""

    _server: asyncio.Server | None = field(default=None, init=False, repr=False)
    _connections: dict[tuple[str, int], tuple[asyncio.StreamReader, asyncio.StreamWriter]] = field(
        default_factory=dict, init=False, repr=False
    )

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self.local_addr[0],
            port=self.local_addr[1],
        )

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        addr = (str(peername[0]), int(peername[1])) if peername else ("0.0.0.0", 0)
        self._connections[addr] = (reader, writer)
        try:
            while True:
                data = await _read_sip_message(reader)
                if data is None:
                    break
                self._dispatch(data, addr)
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionError):
            pass
        finally:
            self._connections.pop(addr, None)
            writer.close()
            try:
                async with asyncio.timeout(5):
                    await writer.wait_closed()
            except (ConnectionError, BrokenPipeError, TimeoutError):
                pass

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        conn = self._connections.get(addr)
        if conn is None:
            raise RuntimeError(f"No TCP connection to {addr}")
        _, writer = conn
        writer.write(bytes(message))

    async def connect(
        self, remote_addr: tuple[str, int]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a TCP connection to a remote SIP endpoint.

        Returns the (reader, writer) pair and stores it for subsequent :meth:`send` calls.
        The connection is also read in the background for incoming messages.
        """
        reader, writer = await asyncio.open_connection(remote_addr[0], remote_addr[1])
        self._connections[remote_addr] = (reader, writer)
        # Read incoming messages in background
        asyncio.get_running_loop().create_task(self._handle_incoming(reader, writer, remote_addr))
        return reader, writer

    async def _handle_incoming(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: tuple[str, int],
    ) -> None:
        """Background task to read messages from a TCP connection."""
        try:
            while True:
                data = await _read_sip_message(reader)
                if data is None:
                    break
                self._dispatch(data, addr)
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionError):
            pass
        finally:
            self._connections.pop(addr, None)

    async def stop(self) -> None:
        # Close all connections
        for _, writer in self._connections.values():
            writer.close()
        self._connections.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None


async def _read_sip_message(reader: asyncio.StreamReader) -> bytes | None:
    """Read a complete SIP message from a TCP stream using Content-Length framing.

    Reads until ``\\r\\n\\r\\n`` to get the header section, parses Content-Length
    to determine how many body bytes to read.  Returns ``None`` on EOF.
    """
    header_buf = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            return None  # EOF
        header_buf.extend(line)
        # Detect end of headers: \r\n\r\n
        if header_buf.endswith(b"\r\n\r\n"):
            break

    # Parse Content-Length from headers
    content_length = 0
    header_text = header_buf.decode("utf-8", errors="replace")
    for hdr_line in header_text.split("\r\n"):
        lower = hdr_line.lower()
        if lower.startswith("content-length:") or lower.startswith("l:"):
            _, _, val = hdr_line.partition(":")
            with contextlib.suppress(ValueError):
                content_length = int(val.strip())
            break

    # Read body
    if content_length > 0:
        body = await reader.readexactly(content_length)
        return bytes(header_buf) + body
    return bytes(header_buf)
