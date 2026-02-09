"""Tests for aiosipua.transaction."""

import pytest

from aiosipua.message import SipMessage, SipRequest, SipResponse
from aiosipua.transaction import Transaction, TransactionLayer, TransactionState


def _make_invite() -> SipRequest:
    raw = (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite-1\r\n"
        "From: <sip:alice@example.com>;tag=aaa\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: call1@example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    msg = SipMessage.parse(raw)
    assert isinstance(msg, SipRequest)
    return msg


def _make_register() -> SipRequest:
    raw = (
        "REGISTER sip:example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg-1\r\n"
        "From: <sip:alice@example.com>;tag=bbb\r\n"
        "To: <sip:alice@example.com>\r\n"
        "Call-ID: reg1@example.com\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    msg = SipMessage.parse(raw)
    assert isinstance(msg, SipRequest)
    return msg


def _make_response(status: int, reason: str, branch: str, method: str) -> SipResponse:
    raw = (
        f"SIP/2.0 {status} {reason}\r\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\r\n"
        "From: <sip:alice@example.com>;tag=aaa\r\n"
        "To: <sip:bob@example.com>;tag=bbb\r\n"
        "Call-ID: call1@example.com\r\n"
        f"CSeq: 1 {method}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    msg = SipMessage.parse(raw)
    assert isinstance(msg, SipResponse)
    return msg


class TestTransactionState:
    def test_initial_state(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        assert txn.state == TransactionState.TRYING

    def test_provisional_goes_to_proceeding(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        txn.update_state(100)
        assert txn.state == TransactionState.PROCEEDING
        txn.update_state(180)
        assert txn.state == TransactionState.PROCEEDING

    def test_2xx_invite_goes_to_completed(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        txn.update_state(200)
        assert txn.state == TransactionState.COMPLETED

    def test_2xx_non_invite_goes_to_terminated(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="REGISTER")
        txn.update_state(200)
        assert txn.state == TransactionState.TERMINATED

    def test_4xx_goes_to_completed(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        txn.update_state(404)
        assert txn.state == TransactionState.COMPLETED

    def test_force_terminate(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        txn.terminate()
        assert txn.state == TransactionState.TERMINATED

    def test_key(self) -> None:
        txn = Transaction(branch="z9hG4bK1", method="INVITE")
        assert txn.key == ("z9hG4bK1", "INVITE")


class TestTransactionLayerClient:
    def test_create_and_match(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        txn = layer.create_client(invite)
        assert txn.branch == "z9hG4bK-invite-1"
        assert txn.method == "INVITE"
        assert txn.request is invite

        resp_100 = _make_response(100, "Trying", "z9hG4bK-invite-1", "INVITE")
        matched = layer.match_response(resp_100)
        assert matched is txn
        assert txn.state == TransactionState.PROCEEDING
        assert txn.response is resp_100

    def test_match_200(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        txn = layer.create_client(invite)

        resp_200 = _make_response(200, "OK", "z9hG4bK-invite-1", "INVITE")
        matched = layer.match_response(resp_200)
        assert matched is txn
        assert txn.state == TransactionState.COMPLETED

    def test_no_match_wrong_branch(self) -> None:
        layer = TransactionLayer()
        _make_invite()
        layer.create_client(_make_invite())

        resp = _make_response(200, "OK", "z9hG4bK-wrong", "INVITE")
        assert layer.match_response(resp) is None

    def test_no_match_wrong_method(self) -> None:
        layer = TransactionLayer()
        layer.create_client(_make_invite())

        resp = _make_response(200, "OK", "z9hG4bK-invite-1", "BYE")
        assert layer.match_response(resp) is None

    def test_multiple_transactions(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        register = _make_register()
        txn1 = layer.create_client(invite)
        txn2 = layer.create_client(register)

        resp_inv = _make_response(200, "OK", "z9hG4bK-invite-1", "INVITE")
        resp_reg = _make_response(200, "OK", "z9hG4bK-reg-1", "REGISTER")

        assert layer.match_response(resp_inv) is txn1
        assert layer.match_response(resp_reg) is txn2
        assert txn1.state == TransactionState.COMPLETED  # INVITE
        assert txn2.state == TransactionState.TERMINATED  # non-INVITE

    def test_create_requires_branch(self) -> None:
        layer = TransactionLayer()
        raw = (
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "From: <sip:alice@example.com>\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        msg = SipMessage.parse(raw)
        assert isinstance(msg, SipRequest)
        with pytest.raises(ValueError, match="no Via branch"):
            layer.create_client(msg)


class TestTransactionLayerServer:
    def test_create_server_transaction(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        txn = layer.create_server(invite)
        assert txn.branch == "z9hG4bK-invite-1"
        assert txn.method == "INVITE"

    def test_match_retransmission(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        layer.create_server(invite)

        # Same request again (retransmission)
        invite2 = _make_invite()
        matched = layer.match_request(invite2)
        assert matched is not None
        assert matched.branch == "z9hG4bK-invite-1"

    def test_no_match_new_request(self) -> None:
        layer = TransactionLayer()
        layer.create_server(_make_invite())

        register = _make_register()
        assert layer.match_request(register) is None


class TestTransactionLayerCleanup:
    def test_remove(self) -> None:
        layer = TransactionLayer()
        txn = layer.create_client(_make_invite())
        assert len(layer.client_transactions) == 1
        layer.remove(txn)
        assert len(layer.client_transactions) == 0

    def test_prune_terminated(self) -> None:
        layer = TransactionLayer()
        invite = _make_invite()
        register = _make_register()
        txn1 = layer.create_client(invite)
        txn2 = layer.create_client(register)

        # Terminate one
        txn2.terminate()
        removed = layer.prune_terminated()
        assert removed == 1
        assert len(layer.client_transactions) == 1
        assert txn1.key in layer.client_transactions

    def test_prune_none_terminated(self) -> None:
        layer = TransactionLayer()
        layer.create_client(_make_invite())
        assert layer.prune_terminated() == 0
