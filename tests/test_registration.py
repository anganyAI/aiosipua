"""Tests for aiosipua.registration (RFC 3261 §10 client registration)."""

from __future__ import annotations

import asyncio

import pytest

from aiosipua import registration as registration_mod
from aiosipua.auth import SipDigestAuth
from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.registration import Registration, RegistrationState
from aiosipua.uac import SipUAC


class FakeTransport:
    """Minimal SipTransport stand-in that captures sent messages."""

    def __init__(self, local_addr: tuple[str, int] = ("10.0.0.2", 5060)) -> None:
        self.local_addr = local_addr
        self.on_message = None
        self.sent: list[tuple[SipRequest | SipResponse, tuple[str, int]]] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def send(self, message: SipRequest | SipResponse, addr: tuple[str, int]) -> None:
        self.sent.append((message, addr))

    def send_reply(self, response: SipResponse) -> None:
        self.sent.append((response, ("0.0.0.0", 0)))


REGISTRAR = ("10.0.0.1", 5060)


def _make_response(
    request: SipRequest,
    status: int,
    reason: str,
    *,
    expires_header: int | None = None,
    contact_expires: int | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SipResponse:
    lines = [
        f"SIP/2.0 {status} {reason}",
        f"Via: {request.get_header('via')}",
        f"From: {request.get_header('from')}",
        f"To: {request.get_header('to')};tag=reg-tag",
        f"Call-ID: {request.call_id}",
        f"CSeq: {request.get_header('cseq')}",
    ]
    contact = request.get_header("contact") or ""
    if contact_expires is not None:
        lines.append(f"Contact: {contact};expires={contact_expires}")
    elif contact:
        lines.append(f"Contact: {contact}")
    if expires_header is not None:
        lines.append(f"Expires: {expires_header}")
    if extra_headers:
        for name, value in extra_headers.items():
            lines.append(f"{name}: {value}")
    lines.append("Content-Length: 0")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    msg = SipMessage.parse(raw)
    assert isinstance(msg, SipResponse)
    return msg


def _setup(**kwargs: object) -> tuple[FakeTransport, SipUAC, Registration]:
    transport = FakeTransport()
    uac = SipUAC(transport)  # type: ignore[arg-type]
    reg = Registration(
        uac,
        "sip:alice@example.com",
        REGISTRAR,
        **kwargs,  # type: ignore[arg-type]
    )
    return transport, uac, reg


def _registers(transport: FakeTransport) -> list[SipRequest]:
    return [m for m, _ in transport.sent if isinstance(m, SipRequest) and m.method == "REGISTER"]


@pytest.fixture()
def fast_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registration_mod, "REFRESH_FRACTION", 0.02)
    monkeypatch.setattr(registration_mod, "EXPIRY_FRACTION", 0.05)


class TestRegisterRequest:
    def test_request_format(self) -> None:
        transport, uac, reg = _setup(expires=300)
        request = reg.register()

        assert request.method == "REGISTER"
        assert request.uri == "sip:example.com"
        from_val = request.get_header("from") or ""
        assert "<sip:alice@example.com>" in from_val
        assert "tag=" in from_val
        to_val = request.get_header("to") or ""
        assert to_val == "<sip:alice@example.com>"
        assert request.get_header("expires") == "300"
        assert request.get_header("contact") == "<sip:alice@10.0.0.2:5060>"
        cseq = request.cseq
        assert cseq is not None
        assert (cseq.seq, cseq.method) == (1, "REGISTER")
        via = request.via[0]
        assert via.branch is not None
        assert ";rport" in (request.get_header("via") or "")
        assert reg.state == RegistrationState.REGISTERING
        assert transport.sent[0][1] == REGISTRAR

    def test_explicit_contact_and_registrar_uri(self) -> None:
        transport, uac, reg = _setup(
            contact_uri="sip:bot@203.0.113.9:5080",
            registrar_uri="sip:edge.example.com",
        )
        request = reg.register()
        assert request.uri == "sip:edge.example.com"
        assert request.get_header("contact") == "<sip:bot@203.0.113.9:5080>"


class TestSuccess:
    @pytest.mark.asyncio()
    async def test_200_registers_and_refreshes(self, fast_timers: None) -> None:
        transport, uac, reg = _setup(expires=1)
        registered: list[Registration] = []
        reg.on_registered = lambda r: registered.append(r)

        request = reg.register()
        uac.handle_response(_make_response(request, 200, "OK", expires_header=1), REGISTRAR)

        assert reg.state == RegistrationState.REGISTERED
        assert reg.granted_expires == 1
        assert registered == [reg]

        await asyncio.sleep(0.04)  # refresh fires at 0.02
        sent = _registers(transport)
        assert len(sent) == 2
        refresh = sent[1]
        assert refresh.call_id == reg.call_id
        refresh_cseq = refresh.cseq
        assert refresh_cseq is not None
        assert refresh_cseq.seq == 2
        reg._cancel_timers()

    @pytest.mark.asyncio()
    async def test_granted_expires_from_contact_param(self, fast_timers: None) -> None:
        transport, uac, reg = _setup(expires=300)
        request = reg.register()
        uac.handle_response(
            _make_response(request, 200, "OK", contact_expires=600, expires_header=300),
            REGISTRAR,
        )
        assert reg.granted_expires == 600  # contact param wins over Expires header
        reg._cancel_timers()

    @pytest.mark.asyncio()
    async def test_expiry_watchdog_fires(self, fast_timers: None) -> None:
        transport, uac, reg = _setup(expires=1)
        expired: list[Registration] = []
        reg.on_expired = lambda r: expired.append(r)

        request = reg.register()
        uac.handle_response(_make_response(request, 200, "OK", expires_header=1), REGISTRAR)

        # The 0.02 refresh is sent but never answered; expiry fires at 0.05
        await asyncio.sleep(0.09)
        assert expired == [reg]
        assert reg.state == RegistrationState.EXPIRED


class TestAuth:
    CHALLENGE = 'Digest realm="example.com", nonce="reg-nonce", algorithm=MD5, qop="auth"'

    def test_401_retries_with_authorization(self) -> None:
        transport, uac, reg = _setup(auth=SipDigestAuth("alice", "secret"))
        request = reg.register()
        uac.handle_response(
            _make_response(
                request, 401, "Unauthorized", extra_headers={"WWW-Authenticate": self.CHALLENGE}
            ),
            REGISTRAR,
        )

        sent = _registers(transport)
        assert len(sent) == 2
        retry = sent[1]
        auth_header = retry.get_header("authorization") or ""
        assert 'username="alice"' in auth_header
        assert "qop=auth" in auth_header
        retry_cseq = retry.cseq
        assert retry_cseq is not None
        assert retry_cseq.seq == 2

    def test_second_401_fails(self) -> None:
        transport, uac, reg = _setup(auth=SipDigestAuth("alice", "wrong"))
        failures: list[tuple[int, str]] = []
        reg.on_failed = lambda r, status, reason: failures.append((status, reason))

        request = reg.register()
        challenge = {"WWW-Authenticate": self.CHALLENGE}
        uac.handle_response(
            _make_response(request, 401, "Unauthorized", extra_headers=challenge), REGISTRAR
        )
        retry = _registers(transport)[1]
        uac.handle_response(
            _make_response(retry, 401, "Unauthorized", extra_headers=challenge), REGISTRAR
        )

        assert failures == [(401, "Unauthorized")]
        assert reg.state == RegistrationState.FAILED


class TestIntervalTooBrief:
    def test_423_bumps_expires_and_retries(self) -> None:
        transport, uac, reg = _setup(expires=60)
        request = reg.register()
        uac.handle_response(
            _make_response(
                request, 423, "Interval Too Brief", extra_headers={"Min-Expires": "600"}
            ),
            REGISTRAR,
        )

        sent = _registers(transport)
        assert len(sent) == 2
        assert sent[1].get_header("expires") == "600"
        assert reg.expires == 600

    def test_repeated_423_fails(self) -> None:
        transport, uac, reg = _setup(expires=60)
        failures: list[int] = []
        reg.on_failed = lambda r, status, reason: failures.append(status)

        request = reg.register()
        headers = {"Min-Expires": "600"}
        uac.handle_response(
            _make_response(request, 423, "Interval Too Brief", extra_headers=headers), REGISTRAR
        )
        retry = _registers(transport)[1]
        uac.handle_response(
            _make_response(retry, 423, "Interval Too Brief", extra_headers={"Min-Expires": "900"}),
            REGISTRAR,
        )

        assert failures == [423]
        assert reg.state == RegistrationState.FAILED


class TestUnregister:
    @pytest.mark.asyncio()
    async def test_unregister_sends_expires_zero_and_stops_refresh(
        self, fast_timers: None
    ) -> None:
        transport, uac, reg = _setup(expires=1)
        request = reg.register()
        uac.handle_response(_make_response(request, 200, "OK", expires_header=1), REGISTRAR)
        assert reg._refresh_task is not None

        unreg = reg.unregister()
        assert unreg.get_header("expires") == "0"
        assert reg._refresh_task is None
        assert reg._expiry_task is None

        uac.handle_response(_make_response(unreg, 200, "OK", expires_header=0), REGISTRAR)
        assert reg.state == RegistrationState.UNREGISTERED

        await asyncio.sleep(0.05)
        assert len(_registers(transport)) == 2  # no refresh after unregister


class TestFailure:
    def test_403_fires_on_failed(self) -> None:
        transport, uac, reg = _setup()
        failures: list[tuple[int, str]] = []
        reg.on_failed = lambda r, status, reason: failures.append((status, reason))

        request = reg.register()
        uac.handle_response(_make_response(request, 403, "Forbidden"), REGISTRAR)

        assert failures == [(403, "Forbidden")]
        assert reg.state == RegistrationState.FAILED

    def test_provisional_response_ignored(self) -> None:
        transport, uac, reg = _setup()
        request = reg.register()
        uac.handle_response(_make_response(request, 100, "Trying"), REGISTRAR)
        assert reg.state == RegistrationState.REGISTERING


class TestShutdownLifecycle:
    @pytest.mark.asyncio()
    async def test_uac_close_cancels_registration_timers(self, fast_timers: None) -> None:
        transport, uac, reg = _setup(expires=1)
        request = reg.register()
        uac.handle_response(_make_response(request, 200, "OK", expires_header=1), REGISTRAR)
        assert reg._refresh_task is not None
        assert reg._expiry_task is not None

        uac.close()

        assert reg._refresh_task is None
        assert reg._expiry_task is None
