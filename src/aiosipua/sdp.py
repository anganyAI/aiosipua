"""SDP parsing, building, and negotiation (RFC 4566, RFC 3264)."""

from __future__ import annotations

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
    """SDP ``b=`` field."""

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
    def video(self) -> MediaDescription | None:
        """First video :class:`MediaDescription`, or ``None``."""
        for m in self.media:
            if m.media == "video":
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

    @property
    def video_rtp_address(self) -> tuple[str, int] | None:
        """``(ip, port)`` for the first video media stream."""
        video = self.video
        if video is None:
            return None
        conn = video.connection or self.connection
        if conn is None:
            return None
        return (conn.address, video.port)


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
    """Parse an SDP body string into an :class:`SdpMessage`.

    Raises:
        TypeError: If *data* is bytes — SIP message bodies are raw bytes,
            decode first (e.g. ``parse_sdp(message.text)``).
    """
    if isinstance(data, bytes | bytearray):
        raise TypeError("parse_sdp expects text — pass message.text, not message.body")
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
                # RFC 4566 §5.3: a blank session name is spelled " "
                sdp.session_name = value if value else " "
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


from .sdp_negotiate import (  # noqa: E402  (facade re-export)
    SdpNegotiationError,
    build_sdp,
    negotiate_sdp,
)

__all__ = [
    "Bandwidth",
    "Codec",
    "ConnectionData",
    "MediaDescription",
    "Origin",
    "SdpMessage",
    "SdpNegotiationError",
    "TimingField",
    "build_sdp",
    "negotiate_sdp",
    "parse_sdp",
    "serialize_sdp",
]
