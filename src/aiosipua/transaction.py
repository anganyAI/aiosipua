"""Simplified SIP transaction layer (RFC 3261 §17).

Matches responses to requests by Via branch + CSeq method, and expires
stale transactions lazily on creation (no event-loop ownership).  The
RFC 3261 base timers (T1/T2) live here; 2xx retransmission itself is the
TU's job and is implemented by :class:`aiosipua.incoming_call.IncomingCall`.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .message import SipMessage, SipRequest, SipResponse

# RFC 3261 §17.1.1.1 base timers
T1 = 0.5
T2 = 4.0
TIMER_H = 64 * T1  # give up waiting for ACK after 32 s (§13.3.1.4)

# Lazy-expiry windows (seconds): linger covers Timers B/D/F/M-style cleanup;
# PROCEEDING is kept much longer because ringing can legitimately last minutes
LINGER = TIMER_H
PROCEEDING_MAX = 300.0


class TransactionState(enum.Enum):
    """SIP transaction states (simplified)."""

    TRYING = "trying"
    PROCEEDING = "proceeding"
    COMPLETED = "completed"
    TERMINATED = "terminated"


@dataclass
class Transaction:
    """A SIP transaction — a request and its associated responses."""

    branch: str
    method: str
    state: TransactionState = TransactionState.TRYING
    request: SipRequest | None = None
    response: SipResponse | None = None
    updated_at: float = field(default_factory=time.monotonic, repr=False)

    @property
    def key(self) -> tuple[str, str]:
        """Transaction key: ``(branch, method)``."""
        return (self.branch, self.method)

    def update_state(self, status_code: int) -> None:
        """Advance state based on response status code.

        - 100-199 → PROCEEDING
        - 200-299 → COMPLETED (for INVITE) / TERMINATED (for non-INVITE)
        - 300-699 → COMPLETED
        """
        if 100 <= status_code <= 199:
            self.state = TransactionState.PROCEEDING
        elif 200 <= status_code <= 299:
            if self.method == "INVITE":
                self.state = TransactionState.COMPLETED
            else:
                self.state = TransactionState.TERMINATED
        elif 300 <= status_code <= 699:
            self.state = TransactionState.COMPLETED
        self.updated_at = time.monotonic()

    def terminate(self) -> None:
        """Force-terminate the transaction."""
        self.state = TransactionState.TERMINATED
        self.updated_at = time.monotonic()


def _extract_branch(msg: SipMessage) -> str | None:
    """Extract the branch parameter from the topmost Via header."""
    vias = msg.headers.get("via")
    if not vias:
        return None
    # Parse the top Via to get the branch — use simple string search
    # to avoid re-parsing overhead for every match
    top = vias[0]
    for part in top.split(";"):
        part = part.strip()
        if part.lower().startswith("branch="):
            return part.split("=", 1)[1]
    return None


def _extract_cseq_method(msg: SipMessage) -> str | None:
    """Extract the method from the CSeq header."""
    raw = msg.headers.get_first("cseq")
    if not raw:
        return None
    parts = raw.strip().split(None, 1)
    return parts[1] if len(parts) >= 2 else None


class TransactionLayer:
    """Match responses to requests by Via branch + CSeq method.

    Client transactions are created with :meth:`create_client` when sending a
    request.  Server transactions are created with :meth:`create_server` when
    receiving a request.  Incoming responses are matched with :meth:`match_response`
    and incoming requests are matched with :meth:`match_request`.

    Stale transactions are expired lazily on every create: TERMINATED,
    COMPLETED, and TRYING entries are dropped after *linger* seconds
    (covering the RFC 3261 B/D/F/M timer roles), PROCEEDING entries after
    *proceeding_max* seconds (a ringing INVITE can legitimately stay
    PROCEEDING for minutes).
    """

    def __init__(self, *, linger: float = LINGER, proceeding_max: float = PROCEEDING_MAX) -> None:
        self._client: dict[tuple[str, str], Transaction] = {}
        self._server: dict[tuple[str, str], Transaction] = {}
        self._linger = linger
        self._proceeding_max = proceeding_max

    def _expired(self, txn: Transaction, now: float) -> bool:
        age = now - txn.updated_at
        if txn.state == TransactionState.PROCEEDING:
            return age > self._proceeding_max
        return age > self._linger

    def _prune_expired(self) -> None:
        now = time.monotonic()
        for store in (self._client, self._server):
            for key in [k for k, v in store.items() if self._expired(v, now)]:
                del store[key]

    # --- Client transactions ---

    def create_client(self, request: SipRequest) -> Transaction:
        """Create a client transaction for an outgoing request.

        The branch is extracted from the topmost Via header.

        Raises:
            ValueError: If the request has no Via branch.
        """
        self._prune_expired()
        branch = _extract_branch(request)
        if not branch:
            raise ValueError("Request has no Via branch parameter")
        method = request.method
        txn = Transaction(branch=branch, method=method, request=request)
        self._client[(branch, method)] = txn
        return txn

    def match_response(self, response: SipResponse) -> Transaction | None:
        """Find the client transaction that matches an incoming response.

        Matching is by topmost Via branch + CSeq method (RFC 3261 §17.1.3).
        If found, the transaction's response and state are updated.
        """
        branch = _extract_branch(response)
        if not branch:
            return None
        method = _extract_cseq_method(response)
        if not method:
            return None
        txn = self._client.get((branch, method))
        if txn is not None:
            txn.response = response
            txn.update_state(response.status_code)
        return txn

    # --- Server transactions ---

    def create_server(self, request: SipRequest) -> Transaction:
        """Create a server transaction for an incoming request.

        Raises:
            ValueError: If the request has no Via branch.
        """
        self._prune_expired()
        branch = _extract_branch(request)
        if not branch:
            raise ValueError("Request has no Via branch parameter")
        method = request.method
        txn = Transaction(branch=branch, method=method, request=request)
        self._server[(branch, method)] = txn
        return txn

    def match_request(self, request: SipRequest) -> Transaction | None:
        """Find an existing server transaction for a (re)transmitted request.

        Useful for detecting retransmissions.
        """
        branch = _extract_branch(request)
        if not branch:
            return None
        return self._server.get((branch, request.method))

    def get_server(self, branch: str, method: str) -> Transaction | None:
        """Look up a server transaction by Via branch and method.

        Used to match a CANCEL to the INVITE it cancels (RFC 3261 §9.2):
        same branch, method INVITE.
        """
        return self._server.get((branch, method))

    # --- Cleanup ---

    def remove(self, txn: Transaction) -> None:
        """Remove a transaction from tracking."""
        self._client.pop(txn.key, None)
        self._server.pop(txn.key, None)

    @property
    def client_transactions(self) -> dict[tuple[str, str], Transaction]:
        """Active client transactions (read-only view)."""
        return dict(self._client)

    @property
    def server_transactions(self) -> dict[tuple[str, str], Transaction]:
        """Active server transactions (read-only view)."""
        return dict(self._server)

    def prune_terminated(self) -> int:
        """Remove all terminated transactions. Returns count removed."""
        count = 0
        for store in (self._client, self._server):
            to_remove = [k for k, v in store.items() if v.state == TransactionState.TERMINATED]
            for k in to_remove:
                del store[k]
                count += 1
        return count
