"""SDP offer building and offer/answer negotiation (RFC 3264).

The SDP data model, parser, and serializer live in :mod:`aiosipua.sdp`,
which re-exports the public entry points here (:func:`build_sdp`,
:func:`negotiate_sdp`).
"""

from __future__ import annotations

import contextlib
import time

from .sdp import (
    _WELL_KNOWN_CODECS,
    Codec,
    ConnectionData,
    MediaDescription,
    Origin,
    SdpMessage,
    TimingField,
    _extract_codecs,
)

# Direction answer mapping per RFC 3264 §6.1
_DIRECTION_ANSWER: dict[str, str] = {
    "sendrecv": "sendrecv",
    "sendonly": "recvonly",
    "recvonly": "sendonly",
    "inactive": "inactive",
}


# --- High-level builder ---


def build_sdp(
    local_ip: str,
    rtp_port: int,
    payload_type: int,
    codec_name: str,
    sample_rate: int = 8000,
    dtmf_payload_type: int = 101,
    ptime: int = 20,
    session_id: str | None = None,
    advertised_ip: str | None = None,
) -> SdpMessage:
    """Build a complete :class:`SdpMessage` from scratch (for outgoing calls).

    Args:
        local_ip: Local IP address for ``c=`` and ``o=`` lines.
        rtp_port: RTP port for the ``m=`` line.
        payload_type: RTP payload type number for the chosen codec.
        codec_name: Codec encoding name (e.g. ``"PCMU"``, ``"PCMA"``).
        sample_rate: Codec clock rate in Hz (default 8000).
        dtmf_payload_type: Payload type for telephone-event (default 101).
        ptime: Packetization time in ms (default 20).
        session_id: SDP session ID; auto-generated from timestamp if ``None``.
        advertised_ip: If set, overrides *local_ip* in SDP ``c=``/``o=``
            lines for NAT traversal.
    """
    if session_id is None:
        session_id = str(int(time.time()))

    formats = [str(payload_type)]
    if dtmf_payload_type > 0:
        formats.append(str(dtmf_payload_type))

    attrs: dict[str, list[str]] = {}
    attrs["rtpmap"] = [f"{payload_type} {codec_name}/{sample_rate}"]
    if dtmf_payload_type > 0:
        attrs["rtpmap"].append(f"{dtmf_payload_type} telephone-event/8000")
        attrs["fmtp"] = [f"{dtmf_payload_type} 0-16"]
    attrs["ptime"] = [str(ptime)]
    attrs.setdefault("sendrecv", [])

    media = MediaDescription(
        media="audio",
        port=rtp_port,
        proto="RTP/AVP",
        formats=formats,
        attributes=attrs,
    )
    media.codecs = _extract_codecs(media)

    return _build_sdp_envelope(local_ip, session_id, "-", [media], advertised_ip=advertised_ip)


# --- SDP envelope helper ---


def _build_sdp_envelope(
    local_ip: str,
    session_id: str,
    session_name: str,
    media: list[MediaDescription],
    advertised_ip: str | None = None,
) -> SdpMessage:
    """Build the common SDP envelope (origin, connection, timing).

    Args:
        local_ip: Default IP for ``o=`` and ``c=`` lines.
        advertised_ip: If set, overrides *local_ip* in ``o=`` and ``c=``
            lines.  Useful for NAT traversal where the RTP socket binds
            to a private address but the SDP must advertise a public one.
    """
    sdp_ip = advertised_ip or local_ip
    addr_type = "IP6" if ":" in sdp_ip else "IP4"
    return SdpMessage(
        version=0,
        origin=Origin(
            username="-",
            session_id=session_id,
            session_version=session_id,
            net_type="IN",
            addr_type=addr_type,
            address=sdp_ip,
        ),
        session_name=session_name,
        connection=ConnectionData(net_type="IN", addr_type=addr_type, address=sdp_ip),
        timing=TimingField(start_time=0, stop_time=0),
        media=media,
    )


# --- SDP Negotiation (RFC 3264) ---


class SdpNegotiationError(Exception):
    """Raised when SDP offer/answer negotiation fails."""


def _first_media_index(offer: SdpMessage, kind: str) -> int | None:
    """Index of the first ``m=<kind>`` section in *offer*, or ``None``."""
    for i, m in enumerate(offer.media):
        if m.media == kind:
            return i
    return None


def _reject_media(m: MediaDescription) -> MediaDescription:
    """Mirror an offered m-line as rejected: port 0 (RFC 3264 §6)."""
    return MediaDescription(media=m.media, port=0, proto=m.proto, formats=list(m.formats))


def _mirror_offer_media(
    offer: SdpMessage, negotiated: dict[int, MediaDescription]
) -> list[MediaDescription]:
    """Answer media list with the offer's m-line count and order (RFC 3264 §6).

    *negotiated* maps offer media index → answer media; every other offered
    m-line is mirrored as rejected.
    """
    return [negotiated.get(i, _reject_media(m)) for i, m in enumerate(offer.media)]


def negotiate_sdp(
    offer: SdpMessage,
    local_ip: str,
    rtp_port: int,
    supported_codecs: list[int] | None = None,
    dtmf_payload_type: int = 101,
    ptime: int = 20,
    session_id: str | None = None,
    session_name: str = "-",
    advertised_ip: str | None = None,
) -> tuple[SdpMessage, int]:
    """Build an SDP answer from an offer (RFC 3264).

    Codec selection follows the offerer's preference order: the first offered
    codec whose payload type appears in *supported_codecs* is chosen.

    Args:
        offer: The remote SDP offer.
        local_ip: Local IP address for the answer.
        rtp_port: Local RTP port.
        supported_codecs: Payload types we accept (default ``[0, 8]`` = PCMU, PCMA).
        dtmf_payload_type: Payload type for telephone-event in the answer
            (default 101). Set to ``0`` to disable.
        ptime: Default packetization time if not specified in the offer.
        session_id: SDP session ID; auto-generated if ``None``.
        session_name: SDP session name (``s=`` line); defaults to ``"-"``.
        advertised_ip: If set, overrides *local_ip* in SDP ``c=``/``o=``
            lines for NAT traversal.

    Returns:
        ``(answer_sdp, chosen_payload_type)``

    Raises:
        SdpNegotiationError: If no offered codec matches *supported_codecs*, or
            if the offer has no audio media.
    """
    if supported_codecs is None:
        supported_codecs = [0, 8]

    if session_id is None:
        session_id = str(int(time.time()))

    # Find the first audio media section in the offer
    audio_idx = _first_media_index(offer, "audio")
    if audio_idx is None:
        raise SdpNegotiationError("Offer contains no audio media")
    offer_audio = offer.media[audio_idx]

    # Codec selection: first offered codec we support wins
    chosen: Codec | None = None
    supported_set = set(supported_codecs)
    for codec in offer_audio.codecs:
        if codec.payload_type in supported_set:
            chosen = codec
            break

    if chosen is None:
        offered = [c.encoding_name or str(c.payload_type) for c in offer_audio.codecs]
        raise SdpNegotiationError(
            f"No matching codec found. Offered: {offered}, supported: {supported_codecs}"
        )

    # Check if offer includes telephone-event for DTMF
    offer_dtmf_pt: int | None = None
    for codec in offer_audio.codecs:
        if codec.encoding_name.lower() == "telephone-event":
            offer_dtmf_pt = codec.payload_type
            break

    # Determine ptime: prefer offer's value
    answer_ptime = ptime
    offer_ptime_vals = offer_audio.attributes.get("ptime", [])
    if offer_ptime_vals:
        with contextlib.suppress(ValueError):
            answer_ptime = int(offer_ptime_vals[0])

    # Determine answer direction per RFC 3264 §6.1
    answer_direction = _DIRECTION_ANSWER.get(offer_audio.direction, "sendrecv")

    # Build answer media formats
    formats = [str(chosen.payload_type)]
    attrs: dict[str, list[str]] = {}

    # rtpmap for chosen codec (always include for clarity, even for static PTs)
    codec_rate = chosen.clock_rate or 8000
    codec_name = chosen.encoding_name
    if not codec_name and chosen.payload_type in _WELL_KNOWN_CODECS:
        codec_name = _WELL_KNOWN_CODECS[chosen.payload_type][0]
        codec_rate = _WELL_KNOWN_CODECS[chosen.payload_type][1]
    attrs["rtpmap"] = [f"{chosen.payload_type} {codec_name}/{codec_rate}"]

    # DTMF: include if offer had telephone-event
    include_dtmf = offer_dtmf_pt is not None and dtmf_payload_type > 0
    if include_dtmf:
        formats.append(str(dtmf_payload_type))
        attrs["rtpmap"].append(f"{dtmf_payload_type} telephone-event/8000")
        attrs["fmtp"] = [f"{dtmf_payload_type} 0-16"]

    # ptime
    attrs["ptime"] = [str(answer_ptime)]

    # direction
    attrs.setdefault(answer_direction, [])

    answer_media = MediaDescription(
        media="audio",
        port=rtp_port,
        proto=offer_audio.proto,
        formats=formats,
        attributes=attrs,
    )
    answer_media.codecs = _extract_codecs(answer_media)

    answer = _build_sdp_envelope(
        local_ip, session_id, session_name, [answer_media], advertised_ip=advertised_ip
    )
    answer.media = _mirror_offer_media(offer, {audio_idx: answer_media})
    return answer, chosen.payload_type
