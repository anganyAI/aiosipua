"""Property-based tests: the parsers are total over arbitrary network input.

Two invariants, checked with hypothesis:

1. No parser raises anything but :class:`ValueError`, whatever the input —
   a crafted packet must never surface an unexpected exception type.
2. The wire format is idempotent after one normalization pass:
   ``parse → serialize → parse → serialize`` is a fixed point.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aiosipua.headers import parse_address, parse_uri, parse_via
from aiosipua.message import SipMessage
from aiosipua.sdp import parse_sdp, serialize_sdp

_SETTINGS = settings(max_examples=200, deadline=None)


@_SETTINGS
@given(st.binary(max_size=2048))
def test_parse_bytes_total_and_idempotent(data: bytes) -> None:
    try:
        msg = SipMessage.parse(data)
    except ValueError:
        return

    wire = bytes(msg)
    assert bytes(SipMessage.parse(wire)) == wire


@_SETTINGS
@given(st.text(max_size=2048))
def test_parse_text_total(data: str) -> None:
    try:
        SipMessage.parse(data)
    except ValueError:
        pass


@_SETTINGS
@given(st.text(max_size=2048))
def test_parse_sdp_total_and_idempotent(data: str) -> None:
    try:
        sdp = parse_sdp(data)
    except ValueError:
        return

    out = serialize_sdp(sdp)
    assert serialize_sdp(parse_sdp(out)) == out


@_SETTINGS
@given(st.text(max_size=512))
def test_parse_via_total(data: str) -> None:
    try:
        parse_via(data)
    except ValueError:
        pass


@_SETTINGS
@given(st.text(max_size=512))
def test_parse_uri_total(data: str) -> None:
    try:
        parse_uri(data)
    except ValueError:
        pass


@_SETTINGS
@given(st.text(max_size=512))
def test_parse_address_total(data: str) -> None:
    try:
        parse_address(data)
    except ValueError:
        pass
