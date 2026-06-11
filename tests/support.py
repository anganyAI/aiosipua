"""Shared test helpers."""

from __future__ import annotations

from aiosipua.message import SipMessage, SipRequest, SipResponse


class FakeTransport:
    """Minimal SipTransport stand-in that captures sent messages."""

    def __init__(self, local_addr: tuple[str, int] = ("10.0.0.2", 5060)) -> None:
        self.local_addr = local_addr
        self.on_message = None
        self.sent: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []
        self._started = False

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        self._started = False

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        self.sent.append((message, addr))

    def send_reply(self, response: SipResponse) -> None:
        # The real transport routes by Via; tests just need the capture
        self.sent.append((response, ("0.0.0.0", 0)))

    def inject(self, raw: str, addr: tuple[str, int] = ("10.0.0.1", 5060)) -> None:
        """Simulate receiving a SIP message."""
        msg = SipMessage.parse(raw)
        if self.on_message is not None:
            self.on_message(msg, addr)
