"""SIP User Agent Client (UAC) — backend-initiated actions.

Minimal UAC for sending requests within existing dialogs.  Supports
BYE (hangup), re-INVITE (session update / hold / unhold), CANCEL
(early dialog), and INFO (DTMF via SIP INFO).

All methods use the dialog's ``route_set`` for in-dialog routing
through the proxy chain (Kamailio / OpenSIPS).  No retransmission
timers — the proxy handles reliability.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .dialog import Dialog, DialogState
from .sdp import SdpMessage, serialize_sdp
from .transaction import TransactionLayer

if TYPE_CHECKING:
    from .message import SipRequest
    from .transport import SipTransport

logger = logging.getLogger(__name__)


class SipUAC:
    """Minimal UAC for sending requests within existing dialogs.

    Usage::

        uac = SipUAC(transport)
        await uac.send_bye(dialog, remote_addr)
    """

    def __init__(self, transport: SipTransport) -> None:
        self.transport = transport
        self.transactions = TransactionLayer()

    def _local_addr(self) -> tuple[str, int]:
        return self.transport.local_addr

    def send_bye(self, dialog: Dialog, remote_addr: tuple[str, int]) -> SipRequest:
        """Send a BYE to terminate an established call.

        Args:
            dialog: The confirmed dialog to terminate.
            remote_addr: Address to send the BYE to (proxy or remote UA).

        Returns:
            The BYE request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send BYE: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        bye = dialog.create_request("BYE", via_host=addr[0], via_port=addr[1])

        # Add Contact header
        bye.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        self.transport.send(bye, remote_addr)
        dialog.terminate()

        return bye

    def send_reinvite(
        self,
        dialog: Dialog,
        sdp: SdpMessage,
        remote_addr: tuple[str, int],
    ) -> SipRequest:
        """Send a re-INVITE to update the session (codec change, hold, etc.).

        Args:
            dialog: The confirmed dialog to update.
            sdp: The new SDP offer.
            remote_addr: Address to send the re-INVITE to.

        Returns:
            The re-INVITE request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send re-INVITE: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        invite = dialog.create_request("INVITE", via_host=addr[0], via_port=addr[1])

        # Contact
        invite.headers.set_single("Contact", f"<sip:{addr[0]}:{addr[1]}>")

        # SDP body
        invite.body = serialize_sdp(sdp)
        invite.headers.set_single("Content-Type", "application/sdp")

        self.transport.send(invite, remote_addr)

        return invite

    def send_cancel(self, dialog: Dialog, remote_addr: tuple[str, int]) -> SipRequest:
        """Send a CANCEL for a pending INVITE (early dialog).

        The CANCEL must match the original INVITE's branch and CSeq.
        Since we don't store the original INVITE here, this creates a
        new CANCEL request using the dialog's current state.

        Args:
            dialog: The early dialog to cancel.
            remote_addr: Address to send the CANCEL to.

        Returns:
            The CANCEL request that was sent.

        Raises:
            ValueError: If the dialog is not in EARLY state.
        """
        if dialog.state != DialogState.EARLY:
            raise ValueError(f"Cannot send CANCEL: dialog is {dialog.state.value}, expected early")

        addr = self._local_addr()
        cancel = dialog.create_request("CANCEL", via_host=addr[0], via_port=addr[1])

        self.transport.send(cancel, remote_addr)
        dialog.terminate()

        return cancel

    def send_info(
        self,
        dialog: Dialog,
        body: str,
        content_type: str,
        remote_addr: tuple[str, int],
    ) -> SipRequest:
        """Send an INFO request within a dialog (e.g. DTMF via SIP INFO).

        Args:
            dialog: The confirmed dialog.
            body: The INFO body (e.g. ``"Signal=1\\r\\nDuration=250\\r\\n"``).
            content_type: Content-Type for the body
                (e.g. ``"application/dtmf-relay"``).
            remote_addr: Address to send the INFO to.

        Returns:
            The INFO request that was sent.

        Raises:
            ValueError: If the dialog is not in CONFIRMED state.
        """
        if dialog.state != DialogState.CONFIRMED:
            raise ValueError(
                f"Cannot send INFO: dialog is {dialog.state.value}, expected confirmed"
            )

        addr = self._local_addr()
        info = dialog.create_request("INFO", via_host=addr[0], via_port=addr[1])

        info.body = body
        info.headers.set_single("Content-Type", content_type)

        self.transport.send(info, remote_addr)

        return info
