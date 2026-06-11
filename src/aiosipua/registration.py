"""SIP client registration (RFC 3261 §10).

:class:`Registration` keeps an address-of-record bound at a registrar:
it sends REGISTER, refreshes before the granted interval expires, answers
digest challenges, honours 423 Interval Too Brief, and unregisters with
``Expires: 0``.  Responses are routed to it by
:meth:`aiosipua.uac.SipUAC.handle_response` (matched by Call-ID).

Usage::

    uac = SipUAC(transport)
    reg = Registration(uac, "sip:alice@example.com", ("registrar", 5060),
                       auth=SipDigestAuth("alice", "secret"))
    reg.on_registered = lambda r: print(f"registered for {r.granted_expires}s")
    reg.register()
    ...
    reg.unregister()
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
from typing import TYPE_CHECKING, Any

from .auth import answer_challenge
from .headers import CSeq, Via, parse_uri, stringify_cseq, stringify_via
from .message import SipRequest
from .utils import format_addr, generate_branch, generate_call_id, generate_tag

if TYPE_CHECKING:
    from collections.abc import Callable

    from .auth import SipDigestAuth
    from .message import SipResponse
    from .uac import SipUAC

logger = logging.getLogger(__name__)

# Refresh at 90 % of the granted interval; declare expiry at 100 % of it
REFRESH_FRACTION = 0.9
EXPIRY_FRACTION = 1.0


class RegistrationState(enum.Enum):
    """Registration lifecycle states."""

    UNREGISTERED = "unregistered"
    REGISTERING = "registering"
    REGISTERED = "registered"
    FAILED = "failed"
    EXPIRED = "expired"


class Registration:
    """One address-of-record binding at a registrar.

    All REGISTER requests of a registration share the same Call-ID and
    From tag with an incrementing CSeq (RFC 3261 §10.2).
    """

    def __init__(
        self,
        uac: SipUAC,
        aor: str,
        registrar: tuple[str, int],
        *,
        expires: int = 300,
        auth: SipDigestAuth | None = None,
        contact_uri: str | None = None,
        registrar_uri: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Args:
        uac: The UAC whose transport sends the REGISTERs and whose
            response dispatch feeds this registration.
        aor: Address-of-record (e.g. ``"sip:alice@example.com"``).
        registrar: Network address the REGISTERs are sent to.
        expires: Requested binding interval in seconds.
        auth: Digest credentials for automatic 401/407 retry.
        contact_uri: Contact to bind; derived from the UAC's signaling
            address (and the AOR user) if ``None``.
        registrar_uri: Request-URI; derived from the AOR host if ``None``.
        user_agent: Optional User-Agent header value.
        """
        self.uac = uac
        self.aor = aor
        self.registrar = registrar
        self.expires = expires
        self.auth = auth
        self.user_agent = user_agent

        addr = uac._local_addr()
        aor_uri = parse_uri(aor)
        userpart = f"{aor_uri.user}@" if aor_uri.user else ""
        self.contact_uri = contact_uri or f"sip:{userpart}{format_addr(*addr)}"
        self.registrar_uri = registrar_uri or f"sip:{aor_uri.host}"

        self.call_id = generate_call_id(addr[0])
        self.state = RegistrationState.UNREGISTERED
        self.granted_expires = 0

        # Callbacks
        self.on_registered: Callable[[Registration], Any] | None = None
        self.on_failed: Callable[[Registration, int, str], Any] | None = None
        self.on_expired: Callable[[Registration], Any] | None = None

        self._from_tag = generate_tag()
        self._cseq = 0
        self._auth_attempts = 0
        self._min_expires_attempts = 0
        self._unregistering = False
        self._refresh_task: asyncio.Task[None] | None = None
        self._expiry_task: asyncio.Task[None] | None = None

        uac._registrations[self.call_id] = self

    def register(self) -> SipRequest:
        """Send a REGISTER for the configured interval (initial or manual refresh)."""
        self._unregistering = False
        self._auth_attempts = 0
        self._min_expires_attempts = 0
        self.state = RegistrationState.REGISTERING
        return self._send_register(self.expires)

    def unregister(self) -> SipRequest:
        """Remove the binding (``Expires: 0``) and stop refreshing."""
        self._unregistering = True
        self._auth_attempts = 0
        self._cancel_timers()
        return self._send_register(0)

    # --- Request building ---

    def _send_register(
        self, expires: int, *, auth_header: tuple[str, str] | None = None
    ) -> SipRequest:
        self._cseq += 1
        addr = self.uac._local_addr()

        request = SipRequest(method="REGISTER", uri=self.registrar_uri)
        via = Via(
            transport="UDP",
            host=addr[0],
            port=addr[1],
            params={"branch": generate_branch(), "rport": None},
        )
        request.headers.append("Via", stringify_via(via))
        request.headers.set_single("From", f"<{self.aor}>;tag={self._from_tag}")
        request.headers.set_single("To", f"<{self.aor}>")
        request.headers.set_single("Call-ID", self.call_id)
        request.headers.set_single("CSeq", stringify_cseq(CSeq(seq=self._cseq, method="REGISTER")))
        request.headers.set_single("Max-Forwards", "70")
        request.headers.set_single("Contact", f"<{self.contact_uri}>")
        request.headers.set_single("Expires", str(expires))
        if self.user_agent:
            request.headers.set_single("User-Agent", self.user_agent)
        if auth_header is not None:
            request.headers.set_single(auth_header[0], auth_header[1])

        self.uac.transactions.create_client(request)
        self.uac.transport.send(request, self.registrar)
        return request

    # --- Response handling ---

    def _handle_response(self, response: SipResponse) -> None:
        """Process a REGISTER response (dispatched by the UAC)."""
        self.uac.transactions.match_response(response)
        status = response.status_code

        if status < 200:
            return
        if 200 <= status <= 299:
            self._on_success(response)
        elif status in (401, 407) and self.auth is not None and self._auth_attempts == 0:
            if not self._retry_with_auth(response, status):
                self._fail(status, response.reason_phrase)
        elif status == 423:
            self._on_interval_too_brief(response)
        else:
            self._fail(status, response.reason_phrase)

    def _on_success(self, response: SipResponse) -> None:
        if self._unregistering:
            self.state = RegistrationState.UNREGISTERED
            self.granted_expires = 0
            logger.info("Unregistered %s", self.aor)
            return

        granted = self._granted_expires(response)
        self.granted_expires = granted
        self.state = RegistrationState.REGISTERED
        self._schedule(granted)

        logger.info("Registered %s for %ds", self.aor, granted)
        if self.on_registered is not None:
            self.on_registered(self)

    def _granted_expires(self, response: SipResponse) -> int:
        """Granted interval: Contact ``expires`` param, else Expires header (RFC 3261 §10.3)."""
        for contact in response.contact:
            value = contact.params.get("expires")
            if value:
                with contextlib.suppress(ValueError):
                    return int(value)
        header = response.get_header("expires")
        if header:
            with contextlib.suppress(ValueError):
                return int(header)
        return self.expires

    def _retry_with_auth(self, response: SipResponse, status: int) -> bool:
        assert self.auth is not None  # guaranteed by caller
        auth_header = answer_challenge(self.auth, response, status, "REGISTER", self.registrar_uri)
        if auth_header is None:
            return False

        self._auth_attempts += 1
        expires = 0 if self._unregistering else self.expires
        self._send_register(expires, auth_header=auth_header)
        logger.info("Retrying REGISTER with %s for %s", auth_header[0], self.aor)
        return True

    def _on_interval_too_brief(self, response: SipResponse) -> None:
        raw = response.get_header("min-expires") or ""
        try:
            min_expires = int(raw)
        except ValueError:
            min_expires = 0

        if self._min_expires_attempts >= 1 or min_expires <= self.expires:
            self._fail(423, response.reason_phrase)
            return

        self._min_expires_attempts += 1
        self.expires = min_expires
        logger.info("Registrar requires Expires >= %d for %s — retrying", min_expires, self.aor)
        self._send_register(self.expires)

    def _fail(self, status: int, reason: str) -> None:
        self.state = RegistrationState.FAILED
        self._cancel_timers()
        logger.warning("REGISTER failed for %s: %d %s", self.aor, status, reason)
        if self.on_failed is not None:
            self.on_failed(self, status, reason)

    # --- Refresh / expiry timers ---

    def _schedule(self, granted: int) -> None:
        self._cancel_timers()
        loop = asyncio.get_running_loop()
        self._refresh_task = loop.create_task(self._refresh_after(granted * REFRESH_FRACTION))
        self._expiry_task = loop.create_task(self._expire_after(granted * EXPIRY_FRACTION))

    def _cancel_timers(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            self._refresh_task = None
        if self._expiry_task is not None:
            self._expiry_task.cancel()
            self._expiry_task = None

    async def _refresh_after(self, delay: float) -> None:
        await asyncio.sleep(delay)
        self._auth_attempts = 0
        self._min_expires_attempts = 0
        self.state = RegistrationState.REGISTERING
        self._send_register(self.expires)

    async def _expire_after(self, delay: float) -> None:
        await asyncio.sleep(delay)
        # The refresh got no 200 in time — the registrar no longer holds us
        self._expiry_task = None
        self._cancel_timers()
        self.state = RegistrationState.EXPIRED
        logger.warning("Registration for %s expired without refresh", self.aor)
        if self.on_expired is not None:
            self.on_expired(self)
