"""Tests for aiosipua.dialog."""

from aiosipua.dialog import Dialog, DialogState, _default_reason, create_dialog_from_request
from aiosipua.message import SipMessage, SipRequest, SipResponse


def _make_invite(
    *,
    call_id: str = "call1@example.com",
    from_tag: str = "aaa",
    contact: str = "<sip:alice@10.0.0.1:5060>",
    record_routes: list[str] | None = None,
    x_headers: dict[str, str] | None = None,
) -> SipRequest:
    lines = [
        "INVITE sip:bob@example.com SIP/2.0",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite-1",
        f"From: <sip:alice@example.com>;tag={from_tag}",
        "To: <sip:bob@example.com>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: {contact}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    if record_routes:
        for rr in record_routes:
            lines.append(f"Record-Route: {rr}")
    if x_headers:
        for k, v in x_headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    raw = "\r\n".join(lines) + "\r\n"
    msg = SipMessage.parse(raw)
    assert isinstance(msg, SipRequest)
    return msg


class TestDialogState:
    def test_initial_state(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1")
        assert d.state == DialogState.EARLY

    def test_confirm(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1")
        d.confirm()
        assert d.state == DialogState.CONFIRMED

    def test_confirm_only_from_early(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1")
        d.terminate()
        d.confirm()  # should not change from TERMINATED
        assert d.state == DialogState.TERMINATED

    def test_terminate(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1")
        d.confirm()
        d.terminate()
        assert d.state == DialogState.TERMINATED

    def test_id_property(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1")
        assert d.id == ("c1", "l1", "r1")


class TestDialogCSeq:
    def test_next_cseq(self) -> None:
        d = Dialog(call_id="c1", local_tag="l1", remote_tag="r1", local_cseq=0)
        assert d.next_cseq() == 1
        assert d.next_cseq() == 2
        assert d.local_cseq == 2


class TestCreateDialogFromRequest:
    def test_basic_dialog(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite)

        assert dialog.call_id == "call1@example.com"
        assert dialog.remote_tag == "aaa"
        assert dialog.local_tag  # auto-generated
        assert dialog.remote_uri == "sip:alice@example.com"
        assert dialog.local_uri == "sip:bob@example.com"
        assert dialog.remote_target == "sip:alice@10.0.0.1:5060"
        assert dialog.state == DialogState.EARLY
        assert dialog.remote_cseq == 1

    def test_custom_local_tag(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_tag="mylocal")
        assert dialog.local_tag == "mylocal"

    def test_custom_local_uri(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_uri="sip:me@myhost.com")
        assert dialog.local_uri == "sip:me@myhost.com"

    def test_record_route(self) -> None:
        invite = _make_invite(
            record_routes=[
                "<sip:proxy1@10.0.0.1;lr>",
                "<sip:proxy2@10.0.0.2;lr>",
            ]
        )
        dialog = create_dialog_from_request(invite)
        # UAS reverses Record-Route per RFC 3261 §12.1.1
        assert dialog.route_set == [
            "<sip:proxy2@10.0.0.2;lr>",
            "<sip:proxy1@10.0.0.1;lr>",
        ]

    def test_no_contact(self) -> None:
        """Dialog created without Contact header should have empty remote target."""
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n"
            "From: <sip:alice@example.com>;tag=aaa\r\n"
            "To: <sip:bob@example.com>\r\n"
            "Call-ID: no-contact@example.com\r\n"
            "CSeq: 1 INVITE\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipRequest)
        dialog = create_dialog_from_request(msg)
        assert dialog.remote_target == ""


class TestDialogCreateRequest:
    def test_bye_request(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_tag="bbb")
        dialog.confirm()

        bye = dialog.create_request("BYE", via_host="10.0.0.2", via_port=5060)
        assert bye.method == "BYE"
        assert bye.uri == "sip:alice@10.0.0.1:5060"

        # Check headers
        assert bye.call_id == "call1@example.com"
        from_val = bye.get_header("from")
        assert from_val is not None
        assert "tag=bbb" in from_val
        to_val = bye.get_header("to")
        assert to_val is not None
        assert "tag=aaa" in to_val

        # CSeq should be 1 (first in-dialog request)
        cseq = bye.cseq
        assert cseq is not None
        assert cseq.seq == 1
        assert cseq.method == "BYE"

        # Via should have branch
        vias = bye.via
        assert len(vias) == 1
        assert vias[0].branch is not None
        assert vias[0].branch.startswith("z9hG4bK")

    def test_route_set_in_request(self) -> None:
        invite = _make_invite(record_routes=["<sip:proxy1@10.0.0.1;lr>"])
        dialog = create_dialog_from_request(invite, local_tag="bbb")
        dialog.confirm()

        bye = dialog.create_request("BYE")
        routes = bye.get_header_values("route")
        assert routes == ["<sip:proxy1@10.0.0.1;lr>"]

    def test_cseq_increments(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_tag="bbb")
        dialog.confirm()

        bye1 = dialog.create_request("BYE")
        bye2 = dialog.create_request("BYE")
        c1 = bye1.cseq
        c2 = bye2.cseq
        assert c1 is not None and c2 is not None
        assert c2.seq == c1.seq + 1


class TestDialogCreateResponse:
    def test_200_ok(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_tag="bbb")

        resp = dialog.create_response(invite, 200, "OK", contact="<sip:10.0.0.2:5060>")
        assert isinstance(resp, SipResponse)
        assert resp.status_code == 200
        assert resp.reason_phrase == "OK"
        assert resp.call_id == "call1@example.com"

        # To should have our tag
        to_val = resp.get_header("to")
        assert to_val is not None
        assert "tag=bbb" in to_val

        # Via should match request
        resp_vias = resp.via
        assert len(resp_vias) == 1
        assert resp_vias[0].branch == "z9hG4bK-invite-1"

        # Contact
        assert resp.get_header("contact") == "<sip:10.0.0.2:5060>"

    def test_default_reason(self) -> None:
        invite = _make_invite()
        dialog = create_dialog_from_request(invite, local_tag="bbb")

        resp = dialog.create_response(invite, 486)
        assert resp.reason_phrase == "Busy Here"


class TestDefaultReason:
    def test_known_codes(self) -> None:
        assert _default_reason(100) == "Trying"
        assert _default_reason(180) == "Ringing"
        assert _default_reason(200) == "OK"
        assert _default_reason(486) == "Busy Here"
        assert _default_reason(487) == "Request Terminated"
        assert _default_reason(500) == "Server Internal Error"

    def test_unknown_code(self) -> None:
        assert _default_reason(299) == ""
