"""Blind call transfer via REFER (RFC 3515).

Receiving side (dispatched by :class:`aiosipua.uas.SipUAS`):
:func:`handle_refer` answers an in-dialog REFER with 202 Accepted, sends
the immediate ``NOTIFY 100 Trying`` the implicit subscription requires
(RFC 3515 §2.4.4), and hands the Refer-To URI to ``uas.on_refer``.  The
application then reports transfer progress with :func:`notify_refer`.

:func:`handle_notify` processes ``Event: refer`` NOTIFYs (message/sipfrag
bodies) on the transferor side and feeds ``uas.on_transfer_progress``.

The implicit subscription is minimal by design: no RFC 6665 engine, no
subscription refresh — the NOTIFY stream lives as long as the dialog.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .headers import parse_address, stringify_uri
from .utils import format_addr

if TYPE_CHECKING:
    from .incoming_call import IncomingCall
    from .message import SipRequest
    from .uas import SipUAS

logger = logging.getLogger(__name__)


def handle_refer(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an in-dialog REFER: 202 + immediate NOTIFY + ``on_refer``."""
    call_id = request.call_id or ""
    call, dialog = uas._find_dialog(call_id)
    if dialog is None:
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return
    if not uas._validate_in_dialog(dialog, request):
        return

    refer_to_raw = request.get_header("refer-to")
    if not refer_to_raw:
        uas._send_error(request, 400, "Missing Refer-To")
        return

    if uas.on_refer is None:
        uas._send_error(request, 501, "Not Implemented")
        return

    if call is None:
        # REFER on an outbound call's dialog — wrap it so the handler can
        # report progress through the same interface
        call = uas._wrap_uac_dialog(request, addr)

    resp = dialog.create_response(request, 202, "Accepted")
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)

    # Immediate NOTIFY establishing the implicit subscription (RFC 3515 §2.4.4)
    notify_refer(call, 100, "Trying")

    refer_to = stringify_uri(parse_address(refer_to_raw).uri)
    logger.info("REFER on %s → %s", call_id, refer_to)
    uas.on_refer(call, refer_to)


def handle_notify(uas: SipUAS, request: SipRequest, addr: tuple[str, int]) -> None:
    """Handle an in-dialog NOTIFY carrying transfer progress (Event: refer)."""
    call_id = request.call_id or ""
    call, dialog = uas._find_dialog(call_id)
    if dialog is None:
        uas._send_error(request, 481, "Call/Transaction Does Not Exist")
        return
    if not uas._validate_in_dialog(dialog, request):
        return

    event = (request.get_header("event") or "").split(";")[0].strip().lower()
    if event != "refer":
        uas._send_error(request, 489, "Bad Event")
        return

    resp = dialog.create_response(request, 200, "OK")
    if uas.user_agent:
        resp.headers.set_single("User-Agent", uas.user_agent)
    uas.transport.send_reply(resp)

    status, reason = _parse_sipfrag(request.text)
    if status and uas.on_transfer_progress is not None:
        uas.on_transfer_progress(call_id, status, reason)


def notify_refer(
    call: IncomingCall,
    status_code: int,
    reason: str = "",
    *,
    final: bool | None = None,
) -> SipRequest | None:
    """Send a transfer-progress NOTIFY on *call*'s dialog (RFC 3515 §2.4.5).

    The body is a message/sipfrag status line (e.g. ``SIP/2.0 180 Ringing``).
    *final* defaults to ``status_code >= 200`` and terminates the implicit
    subscription.

    Returns the NOTIFY, or ``None`` if the call has no transport.
    """
    from .dialog import _default_reason

    if not reason:
        reason = _default_reason(status_code)
    if final is None:
        final = status_code >= 200

    addr = call._signaling_addr()
    notify = call.dialog.create_request("NOTIFY", via_host=addr[0], via_port=addr[1])
    notify.headers.set_single("Event", "refer")
    notify.headers.set_single(
        "Subscription-State", "terminated;reason=noresource" if final else "active;expires=60"
    )
    notify.headers.set_single("Contact", f"<sip:{format_addr(*addr)}>")
    notify.headers.set_single("Content-Type", "message/sipfrag;version=2.0")
    notify.text = f"SIP/2.0 {status_code} {reason}\r\n"

    if call.transport is None:
        return None
    call.transport.send(notify, call.source_addr)
    return notify


def _parse_sipfrag(body: str) -> tuple[int, str]:
    """Extract ``(status, reason)`` from a sipfrag status line, ``(0, "")`` if invalid."""
    line = body.strip().splitlines()[0] if body.strip() else ""
    parts = line.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("SIP/"):
        return 0, ""
    try:
        status = int(parts[1])
    except ValueError:
        return 0, ""
    return status, parts[2] if len(parts) > 2 else ""
