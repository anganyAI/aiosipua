"""SDP parsing, building, and negotiation (RFC 4566, RFC 3264)."""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field

# --- Well-known static payload types (RFC 3551) ---

_WELL_KNOWN_CODECS: dict[int, tuple[str, int, int | None]] = {
    0: ("PCMU", 8000, 1),
    3: ("GSM", 8000, 1),
    4: ("G723", 8000, 1),
    8: ("PCMA", 8000, 1),
    9: ("G722", 8000, 1),
    18: ("G729", 8000, 1),
}

# Reverse lookup: encoding name (upper) -> (payload_type, clock_rate, channels)
_CODEC_BY_NAME: dict[str, tuple[int, int, int | None]] = {
    name.upper(): (pt, rate, ch) for pt, (name, rate, ch) in _WELL_KNOWN_CODECS.items()
}

# Direction answer mapping per RFC 3264 §6.1
_DIRECTION_ANSWER: dict[str, str] = {
    "sendrecv": "sendrecv",
    "sendonly": "recvonly",
    "recvonly": "sendonly",
    "inactive": "inactive",
}


# --- Dataclasses ---


@dataclass
class Origin:
    """SDP ``o=`` field."""

    username: str = "-"
    session_id: str = "0"
    session_version: str = "0"
    net_type: str = "IN"
    addr_type: str = "IP4"
    address: str = "0.0.0.0"


@dataclass
class ConnectionData:
    """SDP ``c=`` field."""

    net_type: str = "IN"
    addr_type: str = "IP4"
    address: str = "0.0.0.0"


@dataclass
class Bandwidth:
    """SDP ``b=`` field — THE BUG FIX (missing from sip-parser)."""

    bwtype: str = "AS"
    bandwidth: int = 0


@dataclass
class TimingField:
    """SDP ``t=`` field."""

    start_time: int = 0
    stop_time: int = 0


@dataclass
class Codec:
    """A codec extracted from rtpmap/fmtp attributes."""

    payload_type: int = 0
    encoding_name: str = ""
    clock_rate: int = 0
    channels: int | None = None
    fmtp: str | None = None


@dataclass
class MediaDescription:
    """SDP ``m=`` section and its associated fields."""

    media: str = ""
    port: int = 0
    proto: str = "RTP/AVP"
    formats: list[str] = field(default_factory=list)
    connection: ConnectionData | None = None
    bandwidths: list[Bandwidth] = field(default_factory=list)
    attributes: dict[str, list[str]] = field(default_factory=dict)
    codecs: list[Codec] = field(default_factory=list)

    @property
    def direction(self) -> str:
        """Media direction: sendrecv, sendonly, recvonly, or inactive."""
        for d in ("sendrecv", "sendonly", "recvonly", "inactive"):
            if d in self.attributes:
                return d
        return "sendrecv"  # default per RFC 3264


@dataclass
class SdpMessage:
    """A complete SDP session description."""

    version: int = 0
    origin: Origin = field(default_factory=Origin)
    session_name: str = " "
    connection: ConnectionData | None = None
    bandwidths: list[Bandwidth] = field(default_factory=list)
    timing: TimingField = field(default_factory=TimingField)
    attributes: dict[str, list[str]] = field(default_factory=dict)
    media: list[MediaDescription] = field(default_factory=list)

    @property
    def audio(self) -> MediaDescription | None:
        """First audio :class:`MediaDescription`, or ``None``."""
        for m in self.media:
            if m.media == "audio":
                return m
        return None

    @property
    def rtp_address(self) -> tuple[str, int] | None:
        """``(ip, port)`` for the first audio media stream.

        Uses the media-level ``c=`` if present, otherwise the session-level ``c=``.
        """
        audio = self.audio
        if audio is None:
            return None
        conn = audio.connection or self.connection
        if conn is None:
            return None
        return (conn.address, audio.port)


# --- Parsing ---


def _parse_origin(value: str) -> Origin:
    parts = value.split()
    if len(parts) >= 6:
        return Origin(
            username=parts[0],
            session_id=parts[1],
            session_version=parts[2],
            net_type=parts[3],
            addr_type=parts[4],
            address=parts[5],
        )
    return Origin()


def _parse_connection(value: str) -> ConnectionData:
    parts = value.split()
    if len(parts) >= 3:
        return ConnectionData(net_type=parts[0], addr_type=parts[1], address=parts[2])
    return ConnectionData()


def _parse_bandwidth(value: str) -> Bandwidth:
    if ":" in value:
        bwtype, _, bw_str = value.partition(":")
        return Bandwidth(bwtype=bwtype, bandwidth=int(bw_str))
    return Bandwidth()


def _parse_timing(value: str) -> TimingField:
    parts = value.split()
    if len(parts) >= 2:
        return TimingField(start_time=int(parts[0]), stop_time=int(parts[1]))
    return TimingField()


def _parse_media_line(value: str) -> MediaDescription:
    parts = value.split()
    if len(parts) >= 4:
        return MediaDescription(
            media=parts[0],
            port=int(parts[1]),
            proto=parts[2],
            formats=parts[3:],
        )
    if len(parts) >= 3:
        return MediaDescription(media=parts[0], port=int(parts[1]), proto=parts[2])
    return MediaDescription()


def _extract_codecs(media: MediaDescription) -> list[Codec]:
    """Extract codec information from rtpmap/fmtp attributes and well-known types."""
    rtpmaps: dict[int, Codec] = {}

    # Parse a=rtpmap lines
    for val in media.attributes.get("rtpmap", []):
        # "96 opus/48000/2" or "0 PCMU/8000"
        space_idx = val.find(" ")
        if space_idx == -1:
            continue
        pt = int(val[:space_idx])
        encoding_part = val[space_idx + 1 :]
        parts = encoding_part.split("/")
        codec = Codec(payload_type=pt, encoding_name=parts[0])
        if len(parts) >= 2:
            codec.clock_rate = int(parts[1])
        if len(parts) >= 3:
            codec.channels = int(parts[2])
        rtpmaps[pt] = codec

    # Parse a=fmtp lines
    for val in media.attributes.get("fmtp", []):
        space_idx = val.find(" ")
        if space_idx == -1:
            continue
        pt = int(val[:space_idx])
        fmtp_str = val[space_idx + 1 :]
        if pt in rtpmaps:
            rtpmaps[pt].fmtp = fmtp_str

    # Build ordered codec list matching format order
    codecs: list[Codec] = []
    for fmt in media.formats:
        try:
            pt = int(fmt)
        except ValueError:
            continue
        if pt in rtpmaps:
            codecs.append(rtpmaps[pt])
        elif pt in _WELL_KNOWN_CODECS:
            name, rate, channels = _WELL_KNOWN_CODECS[pt]
            codecs.append(
                Codec(
                    payload_type=pt,
                    encoding_name=name,
                    clock_rate=rate,
                    channels=channels,
                )
            )
        else:
            codecs.append(Codec(payload_type=pt))

    return codecs


def _add_attribute(attrs: dict[str, list[str]], line: str) -> None:
    """Parse an ``a=`` line and add to an attribute dict."""
    if ":" in line:
        key, _, val = line.partition(":")
        attrs.setdefault(key, []).append(val)
    else:
        # Flag attribute
        attrs.setdefault(line, [])


def parse_sdp(data: str) -> SdpMessage:
    """Parse an SDP body string into an :class:`SdpMessage`."""
    sdp = SdpMessage()
    current_media: MediaDescription | None = None

    for line in data.splitlines():
        line = line.strip()
        if len(line) < 2 or line[1] != "=":
            continue

        field_type = line[0]
        value = line[2:]

        if field_type == "m":
            # Start a new media section
            if current_media is not None:
                current_media.codecs = _extract_codecs(current_media)
                sdp.media.append(current_media)
            current_media = _parse_media_line(value)
        elif current_media is not None:
            # Media-level field
            if field_type == "c":
                current_media.connection = _parse_connection(value)
            elif field_type == "b":
                current_media.bandwidths.append(_parse_bandwidth(value))
            elif field_type == "a":
                _add_attribute(current_media.attributes, value)
        else:
            # Session-level field
            if field_type == "v":
                sdp.version = int(value)
            elif field_type == "o":
                sdp.origin = _parse_origin(value)
            elif field_type == "s":
                sdp.session_name = value
            elif field_type == "c":
                sdp.connection = _parse_connection(value)
            elif field_type == "b":
                sdp.bandwidths.append(_parse_bandwidth(value))
            elif field_type == "t":
                sdp.timing = _parse_timing(value)
            elif field_type == "a":
                _add_attribute(sdp.attributes, value)

    # Finalize last media section
    if current_media is not None:
        current_media.codecs = _extract_codecs(current_media)
        sdp.media.append(current_media)

    return sdp


# --- Serialization ---


def serialize_sdp(sdp: SdpMessage) -> str:
    """Serialize an :class:`SdpMessage` to an SDP body string."""
    lines: list[str] = []

    # v=
    lines.append(f"v={sdp.version}")

    # o=
    o = sdp.origin
    lines.append(
        f"o={o.username} {o.session_id} {o.session_version} {o.net_type} {o.addr_type} {o.address}"
    )

    # s=
    lines.append(f"s={sdp.session_name}")

    # c= (session-level)
    if sdp.connection:
        c = sdp.connection
        lines.append(f"c={c.net_type} {c.addr_type} {c.address}")

    # b= (session-level)
    for bw in sdp.bandwidths:
        lines.append(f"b={bw.bwtype}:{bw.bandwidth}")

    # t=
    lines.append(f"t={sdp.timing.start_time} {sdp.timing.stop_time}")

    # a= (session-level)
    for key, values in sdp.attributes.items():
        if values:
            for val in values:
                lines.append(f"a={key}:{val}")
        else:
            lines.append(f"a={key}")

    # Media sections
    for m in sdp.media:
        fmt_str = " ".join(m.formats)
        lines.append(f"m={m.media} {m.port} {m.proto} {fmt_str}")

        if m.connection:
            c = m.connection
            lines.append(f"c={c.net_type} {c.addr_type} {c.address}")

        for bw in m.bandwidths:
            lines.append(f"b={bw.bwtype}:{bw.bandwidth}")

        for key, values in m.attributes.items():
            if values:
                for val in values:
                    lines.append(f"a={key}:{val}")
            else:
                lines.append(f"a={key}")

    return "\r\n".join(lines) + "\r\n"


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

    return SdpMessage(
        version=0,
        origin=Origin(
            username="-",
            session_id=session_id,
            session_version=session_id,
            net_type="IN",
            addr_type="IP4",
            address=local_ip,
        ),
        session_name="-",
        connection=ConnectionData(net_type="IN", addr_type="IP4", address=local_ip),
        timing=TimingField(start_time=0, stop_time=0),
        media=[media],
    )


# --- SDP Negotiation (RFC 3264) ---


class SdpNegotiationError(Exception):
    """Raised when SDP offer/answer negotiation fails."""


def negotiate_sdp(
    offer: SdpMessage,
    local_ip: str,
    rtp_port: int,
    supported_codecs: list[int] | None = None,
    dtmf_payload_type: int = 101,
    ptime: int = 20,
    session_id: str | None = None,
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
    offer_audio = offer.audio
    if offer_audio is None:
        raise SdpNegotiationError("Offer contains no audio media")

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

    answer = SdpMessage(
        version=0,
        origin=Origin(
            username="-",
            session_id=session_id,
            session_version=session_id,
            net_type="IN",
            addr_type="IP4",
            address=local_ip,
        ),
        session_name="-",
        connection=ConnectionData(net_type="IN", addr_type="IP4", address=local_ip),
        timing=TimingField(start_time=0, stop_time=0),
        media=[answer_media],
    )

    return answer, chosen.payload_type
