# Changelog

All notable changes to `aiosipua` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was added during `0.7.1` and backfilled from the git tags and the
[GitHub Releases](https://github.com/anganyAI/aiosipua/releases). Releases
`0.1.0` through `0.3.0` predate the first tag (`v0.4.0`) and are not covered.

## [Unreleased]

## [0.7.1] - 2026-07-30

### Added
- **`symmetric_rtp` passthrough**: both `CallSession` and `VideoCallSession`
  grow `symmetric_rtp`, riding through to `aiortp.RTPSession.create` and
  `aiortp.VideoRTPSession.create`. aiortp has implemented the latching logic
  since 0.7.0, but neither bridge forwarded the flag, so it was unreachable
  from any application built on aiosipua. Without it, the `c=` address of the
  SDP offer alone decides where outbound media goes for the whole duration of
  the call — a caller can point the stream at a third party and never receive
  anything itself. With it enabled, the outbound destination only follows an
  address that packets were actually received from. The default is unchanged
  (`False`, matching aiortp): this is a pure passthrough, and flipping the
  default here would alter media behaviour for every existing call.

### Changed
- Docs: the `IncomingCall` X-header accessors now state that their values are
  caller-controlled.

## [0.7.0] - 2026-06-11

Companion release to aiortp 0.7.0. No GitHub release notes were published at
the time; this entry is reconstructed from the commits.

### Added
- **Adaptive playout passthrough**: `CallSession` exposes `playout` /
  `playout_max_delay_ms`. In playout mode the receive side delivers audio on a
  steady clock with a jitter-tracking buffer depth — the inbound defense for
  jittery links such as WiFi callers and congested paths. `jitter_prefetch`
  only applies when `playout` is off.
- **TX redundancy passthrough**: `duplicate_tx` rides the same `CallSession`
  surface as `plc` / `cn` / `playout`, for degraded links.

### Changed
- The `rtp` extra requires `aiortp >= 0.7.0`, which brings the playout
  wire-clock fix for RFC 3551 G.722 senders alongside `duplicate_tx`.

## [0.6.0] - 2026-06-11

Companion release to aiortp 0.6.0. No breaking changes from 0.5.0.

### Added
- **Comfort noise passthrough**: `CallSession` grows `cn` / `cn_payload_type`,
  riding through to `aiortp.RTPSession.create` — with `cn=True`, silence in a
  call plays RFC 3389 comfort noise instead of dead air.

### Changed
- The `rtp` extra requires `aiortp >= 0.6.0`.

## [0.5.0] - 2026-06-11

SIP conformance overhaul and a major feature batch: this release makes aiosipua
hold its own against real-world SIP servers and adds the signaling features a
voice-AI backend needs. 344 → 524 tests; every module under strict mypy.

### Added
- **Reliability**: 200 OK retransmitted until ACK over UDP, reliable
  provisionals with PRACK/100rel (RFC 3262), automatic transaction expiry.
- **REGISTER client** with auto-refresh, 423 handling, and expiry watchdog.
- **UPDATE** (RFC 3311) and **blind transfer via REFER** (RFC 3515) with
  transfer-progress NOTIFYs.
- **Session timers** (RFC 4028): UPDATE refreshes and dead-call watchdogs.
- **IPv6** end to end: bracketed literals in Via/Contact/URIs, `IN IP6` SDP.

### Changed
- **Breaking** — `SipUAC.send_cancel(call)` replaces
  `send_cancel(dialog, remote_addr)`. The CANCEL is built from the original
  INVITE (same branch and CSeq, RFC 3261 §9.1), which is what proxies require
  to match it.
- **Breaking** — `SipMessage.body` is now `bytes` (SIP bodies are octet
  streams). Read or write text bodies through the new `message.text` property;
  `parse_sdp` raises a `TypeError` pointing at `.text` if handed bytes.

### Fixed
- Digest authentication rewritten per RFC 7616: `qop="auth"` (cnonce/nc),
  SHA-256 (RFC 8760) alongside MD5, `opaque` echoed — challenges from
  Asterisk/FreeSWITCH/Kamailio now succeed.
- re-INVITE 200s are ACKed with their own CSeq; `on_answer` no longer replays.
- In-dialog requests are validated against the dialog (wrong tags → 481,
  non-increasing CSeq → 500); CANCEL matches the INVITE transaction by branch.
- SDP answers mirror every offered m-line in order, port 0 for rejected streams
  (RFC 3264 §6).
- `received` / `rport` stamped on incoming Vias (RFC 3581); `advertised_addr`
  on UAC/UAS for NATed signaling.

### Security
- Header-injection guards on all header setters; size caps on header count, TCP
  header bytes, and declared body length; required-header validation.
- The parser survives the RFC 4475 torture suite and holds two
  hypothesis-checked invariants: only `ValueError` on arbitrary input, and a
  stable wire format after one normalization pass.

## [0.4.3] - 2026-06-11

### Added
- **`lossy_caller` example**: dial an agent with controlled RTP packet loss, to
  exercise concealment and jitter handling.

### Changed
- The `rtp` extra requires `aiortp >= 0.5.0`.

## [0.4.2] - 2026-06-10

### Added
- **Packet loss concealment**: `CallSession` grows `plc` (default `True`),
  forwarded to `aiortp.RTPSession`, which replaces confirmed-lost packets with
  concealment PCM when `skip_audio_gaps` is enabled. The `concealed_frames`
  counter surfaces through the existing `stats` property.

### Changed
- README documents NAT traversal, with an example.

## [0.4.1] - 2026-03-24

### Added
- **SIP NAT traversal**: all SDP functions, `CallSession` and
  `VideoCallSession` accept an `advertised_ip` parameter. When set, SDP `c=` /
  `o=` lines use the advertised IP while RTP sockets bind to `local_ip`. Fully
  backward compatible.

## [0.4.0] - 2026-03-13

### Added
- **Video support**: `negotiate_video_sdp` (SDP answer for video media lines —
  H264, VP8, VP9, AV1), `negotiate_av_sdp` (combined audio+video negotiation in
  a single answer), `build_video_sdp` (video-only SDP offers for outgoing
  calls), and `VideoCallSession`, which bridges video SDP negotiation to
  aiortp's `VideoRTPSession` with frame callbacks.
- `SdpMessage.video` and `.video_rtp_address` convenience properties.
- GitHub Actions CI: tests on 3.11/3.12/3.13, ruff lint+format, mypy.

### Changed
- Extracted `_BaseCallSession`, shared by `CallSession` and `VideoCallSession`.
- Extracted a `_build_sdp_envelope` helper, DRYing SDP construction across five
  call sites.

### Fixed
- Removed an unsafe `aiortp.SUPPORTED_VIDEO_CODECS` reference that could raise
  `AttributeError`, and the dead `_WELL_KNOWN_VIDEO_CODECS` dict.
- Fixed a pre-existing mypy `no-redef` error in `uas.py`.
- Fixed the license stated in the README (BSD-3-Clause → MIT).

[Unreleased]: https://github.com/anganyAI/aiosipua/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/anganyAI/aiosipua/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/anganyAI/aiosipua/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/anganyAI/aiosipua/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/anganyAI/aiosipua/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/anganyAI/aiosipua/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/anganyAI/aiosipua/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/anganyAI/aiosipua/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/anganyAI/aiosipua/releases/tag/v0.4.0
