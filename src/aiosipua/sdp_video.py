"""Video SDP negotiation and building (RFC 3264)."""

from __future__ import annotations

import logging
import time

from .sdp import (
    Codec,
    MediaDescription,
    SdpMessage,
    SdpNegotiationError,
    _DIRECTION_ANSWER,
    _build_sdp_envelope,
    _extract_codecs,
    negotiate_sdp,
)

logger = logging.getLogger(__name__)


def negotiate_video_sdp(
    offer: SdpMessage,
    local_ip: str,
    video_rtp_port: int,
    supported_video_codecs: list[str] | None = None,
    session_id: str | None = None,
    session_name: str = "-",
) -> tuple[SdpMessage, int]:
    """Build an SDP answer for the video media line (RFC 3264).

    Handles only the ``m=video`` line.  For combined audio+video negotiation
    use :func:`negotiate_av_sdp`.

    Args:
        offer: The remote SDP offer.
        local_ip: Local IP address for the answer.
        video_rtp_port: Local RTP port for video.
        supported_video_codecs: Codec names we accept (default ``["H264"]``).
        session_id: SDP session ID; auto-generated if ``None``.
        session_name: SDP session name.

    Returns:
        ``(answer_sdp, chosen_payload_type)``

    Raises:
        SdpNegotiationError: If no video media or no matching codec.
    """
    if supported_video_codecs is None:
        supported_video_codecs = ["H264"]

    if session_id is None:
        session_id = str(int(time.time()))

    offer_video = offer.video
    if offer_video is None:
        raise SdpNegotiationError("Offer contains no video media")

    # Codec selection: first offered video codec we support
    supported_set = {c.upper() for c in supported_video_codecs}
    chosen: Codec | None = None
    for codec in offer_video.codecs:
        if codec.encoding_name.upper() in supported_set:
            chosen = codec
            break

    if chosen is None:
        offered = [c.encoding_name or str(c.payload_type) for c in offer_video.codecs]
        raise SdpNegotiationError(
            f"No matching video codec. Offered: {offered}, supported: {supported_video_codecs}"
        )

    # Direction mapping
    answer_direction = _DIRECTION_ANSWER.get(offer_video.direction, "sendrecv")

    # Build answer media
    formats = [str(chosen.payload_type)]
    attrs: dict[str, list[str]] = {}

    codec_rate = chosen.clock_rate or 90000
    attrs["rtpmap"] = [f"{chosen.payload_type} {chosen.encoding_name}/{codec_rate}"]

    if chosen.fmtp:
        attrs["fmtp"] = [f"{chosen.payload_type} {chosen.fmtp}"]

    attrs.setdefault(answer_direction, [])

    answer_media = MediaDescription(
        media="video",
        port=video_rtp_port,
        proto=offer_video.proto,
        formats=formats,
        attributes=attrs,
    )
    answer_media.codecs = _extract_codecs(answer_media)

    answer = _build_sdp_envelope(local_ip, session_id, session_name, [answer_media])
    return answer, chosen.payload_type


def negotiate_av_sdp(
    offer: SdpMessage,
    local_ip: str,
    audio_rtp_port: int,
    video_rtp_port: int,
    *,
    supported_codecs: list[int] | None = None,
    supported_video_codecs: list[str] | None = None,
    dtmf_payload_type: int = 101,
    ptime: int = 20,
    session_id: str | None = None,
    session_name: str = "-",
) -> tuple[SdpMessage, int, int | None]:
    """Negotiate both audio and video media lines in a single SDP answer.

    If the offer has no video, the answer includes only audio.

    Args:
        offer: The remote SDP offer.
        local_ip: Local IP for the answer.
        audio_rtp_port: Local RTP port for audio.
        video_rtp_port: Local RTP port for video.
        supported_codecs: Audio payload types (default ``[0, 8]``).
        supported_video_codecs: Video codec names (default ``["H264"]``).
        dtmf_payload_type: DTMF payload type (default 101).
        ptime: Default packetization time.
        session_id: SDP session ID.
        session_name: SDP session name.

    Returns:
        ``(answer_sdp, audio_payload_type, video_payload_type_or_None)``

    Raises:
        SdpNegotiationError: If no audio media or no matching audio codec.
    """
    if session_id is None:
        session_id = str(int(time.time()))

    # Negotiate audio (required)
    audio_answer, audio_pt = negotiate_sdp(
        offer=offer,
        local_ip=local_ip,
        rtp_port=audio_rtp_port,
        supported_codecs=supported_codecs,
        dtmf_payload_type=dtmf_payload_type,
        ptime=ptime,
        session_id=session_id,
        session_name=session_name,
    )

    # Try video (optional)
    video_pt: int | None = None
    if offer.video is not None:
        try:
            video_answer, video_pt = negotiate_video_sdp(
                offer=offer,
                local_ip=local_ip,
                video_rtp_port=video_rtp_port,
                supported_video_codecs=supported_video_codecs,
                session_id=session_id,
                session_name=session_name,
            )
            # Merge video media into audio answer
            video_media = video_answer.video
            if video_media is not None:
                audio_answer.media.append(video_media)
        except SdpNegotiationError:
            logger.debug("Video negotiation failed, answering with audio only")

    return audio_answer, audio_pt, video_pt


def build_video_sdp(
    local_ip: str,
    video_rtp_port: int,
    payload_type: int = 96,
    codec_name: str = "H264",
    clock_rate: int = 90000,
    fmtp: str | None = None,
    session_id: str | None = None,
) -> SdpMessage:
    """Build a video-only :class:`SdpMessage` (for outgoing video calls).

    Args:
        local_ip: Local IP address.
        video_rtp_port: RTP port for video.
        payload_type: RTP payload type (default 96).
        codec_name: Codec name (default ``"H264"``).
        clock_rate: RTP clock rate (default 90000).
        fmtp: Optional fmtp parameters.
        session_id: SDP session ID.
    """
    if session_id is None:
        session_id = str(int(time.time()))

    formats = [str(payload_type)]
    attrs: dict[str, list[str]] = {}
    attrs["rtpmap"] = [f"{payload_type} {codec_name}/{clock_rate}"]
    if fmtp:
        attrs["fmtp"] = [f"{payload_type} {fmtp}"]
    attrs.setdefault("sendrecv", [])

    media = MediaDescription(
        media="video",
        port=video_rtp_port,
        proto="RTP/AVP",
        formats=formats,
        attributes=attrs,
    )
    media.codecs = _extract_codecs(media)

    return _build_sdp_envelope(local_ip, session_id, "-", [media])
