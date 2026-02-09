"""SIP dialog state machine (RFC 3261 §12).

A dialog is a peer-to-peer SIP relationship established by an INVITE
transaction.  This module tracks the dialog lifecycle (Early → Confirmed →
Terminated) and provides helpers to create in-dialog requests and responses
with proper Route/Record-Route handling.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .headers import CSeq, Via, stringify_cseq, stringify_via
from .utils import generate_branch, generate_tag

if TYPE_CHECKING:
    from .message import SipRequest, SipResponse


class DialogState(enum.Enum):
    """Dialog lifecycle states (RFC 3261 §12)."""

    EARLY = "early"
    CONFIRMED = "confirmed"
    TERMINATED = "terminated"


@dataclass
class Dialog:
    """A SIP dialog — a persistent relationship between two UAs.

    Created from an INVITE transaction.  Tracks the call-id, local/remote
    tags, CSeq counters, and the route set derived from Record-Route headers.
    """

    call_id: str = ""
    local_tag: str = ""
    remote_tag: str = ""
    local_uri: str = ""
    remote_uri: str = ""
    remote_target: str = ""
    route_set: list[str] = field(default_factory=list)
    local_cseq: int = 0
    remote_cseq: int = 0
    state: DialogState = DialogState.EARLY
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def id(self) -> tuple[str, str, str]:
        """Dialog identifier: ``(call_id, local_tag, remote_tag)``."""
        return (self.call_id, self.local_tag, self.remote_tag)

    def confirm(self) -> None:
        """Transition from EARLY to CONFIRMED (on 2xx response)."""
        if self.state == DialogState.EARLY:
            self.state = DialogState.CONFIRMED

    def terminate(self) -> None:
        """Transition to TERMINATED."""
        self.state = DialogState.TERMINATED

    def next_cseq(self) -> int:
        """Increment and return the next local CSeq number."""
        self.local_cseq += 1
        return self.local_cseq

    def create_request(
        self,
        method: str,
        *,
        via_host: str = "0.0.0.0",
        via_port: int = 5060,
        via_transport: str = "UDP",
    ) -> SipRequest:
        """Create an in-dialog request with proper headers and Route set.

        Builds the request URI from the remote target, sets From/To/Call-ID
        from the dialog, and inserts Route headers from the route set.
        """
        from .message import SipRequest

        cseq_num = self.next_cseq()
        branch = generate_branch()

        req = SipRequest(method=method, uri=self.remote_target or self.remote_uri)

        # Via
        via = Via(
            transport=via_transport,
            host=via_host,
            port=via_port,
            params={"branch": branch},
        )
        req.headers.append("Via", stringify_via(via))

        # From (local)
        req.headers.set_single("From", f"<{self.local_uri}>;tag={self.local_tag}")

        # To (remote)
        to_val = f"<{self.remote_uri}>"
        if self.remote_tag:
            to_val += f";tag={self.remote_tag}"
        req.headers.set_single("To", to_val)

        # Call-ID
        req.headers.set_single("Call-ID", self.call_id)

        # CSeq
        req.headers.set_single("CSeq", stringify_cseq(CSeq(seq=cseq_num, method=method)))

        # Max-Forwards
        req.headers.set_single("Max-Forwards", "70")

        # Route set
        for route in self.route_set:
            req.headers.append("Route", route)

        return req

    def create_response(
        self,
        request: SipRequest,
        status_code: int,
        reason_phrase: str = "",
        *,
        contact: str | None = None,
    ) -> SipResponse:
        """Create a response to an in-dialog request.

        Copies Via, From, To (adding local tag), Call-ID, and CSeq from
        the request.
        """
        from .message import SipResponse

        if not reason_phrase:
            reason_phrase = _default_reason(status_code)

        resp = SipResponse(status_code=status_code, reason_phrase=reason_phrase)

        # Copy Via headers
        for v in request.headers.get("via"):
            resp.headers.append("Via", v)

        # From — copy from request
        from_val = request.headers.get_first("from")
        if from_val:
            resp.headers.set_single("From", from_val)

        # To — copy from request, add our tag
        to_val = request.headers.get_first("to")
        if to_val:
            if self.local_tag and f"tag={self.local_tag}" not in to_val:
                to_val += f";tag={self.local_tag}"
            resp.headers.set_single("To", to_val)

        # Call-ID
        resp.headers.set_single("Call-ID", self.call_id)

        # CSeq
        cseq_val = request.headers.get_first("cseq")
        if cseq_val:
            resp.headers.set_single("CSeq", cseq_val)

        # Contact
        if contact:
            resp.headers.set_single("Contact", contact)

        return resp


def create_dialog_from_request(
    request: SipRequest,
    *,
    local_tag: str | None = None,
    local_uri: str | None = None,
) -> Dialog:
    """Create a UAS dialog from an incoming INVITE request.

    Extracts Call-ID, From tag (remote), To URI (local), Contact (remote
    target), and Record-Route headers (reversed for UAS route set).

    Args:
        request: The incoming INVITE request.
        local_tag: Tag for our side; auto-generated if ``None``.
        local_uri: Our URI; derived from the To header if ``None``.
    """
    if local_tag is None:
        local_tag = generate_tag()

    # Extract From (remote) info
    from_addr = request.from_addr
    remote_tag = from_addr.tag if from_addr else ""
    # Extract remote URI from From header
    remote_uri = ""
    if from_addr and from_addr.uri:
        from .headers import stringify_uri

        remote_uri = stringify_uri(from_addr.uri)

    # Extract local URI from To header
    if local_uri is None:
        to_addr = request.to_addr
        if to_addr and to_addr.uri:
            from .headers import stringify_uri

            local_uri = stringify_uri(to_addr.uri)
        else:
            local_uri = request.uri

    # Remote target from Contact
    remote_target = ""
    contacts = request.contact
    if contacts:
        from .headers import stringify_uri

        remote_target = stringify_uri(contacts[0].uri)

    # Route set from Record-Route (reversed for UAS per RFC 3261 §12.1.1)
    route_set = list(reversed(request.headers.get("record-route")))

    # Extract CSeq
    cseq = request.cseq
    remote_cseq = cseq.seq if cseq else 1

    return Dialog(
        call_id=request.call_id or "",
        local_tag=local_tag,
        remote_tag=remote_tag or "",
        local_uri=local_uri,
        remote_uri=remote_uri,
        remote_target=remote_target,
        route_set=route_set,
        local_cseq=0,
        remote_cseq=remote_cseq,
        state=DialogState.EARLY,
    )


def _default_reason(status_code: int) -> str:
    """Return a default reason phrase for common status codes."""
    reasons: dict[int, str] = {
        100: "Trying",
        180: "Ringing",
        183: "Session Progress",
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        480: "Temporarily Unavailable",
        481: "Call/Transaction Does Not Exist",
        486: "Busy Here",
        487: "Request Terminated",
        488: "Not Acceptable Here",
        500: "Server Internal Error",
        503: "Service Unavailable",
        603: "Decline",
    }
    return reasons.get(status_code, "")
