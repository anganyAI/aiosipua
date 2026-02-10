# aiosipua

Asyncio SIP micro-library for Python. Companion to [aiortp](https://github.com/anganyAI/aiortp).

Built for voice AI backends that need SIP signaling without the bloat of a full
SIP stack. Zero runtime dependencies, strict type hints, Python 3.11+.

## Features

- **SIP message parsing and serialization** — RFC 3261 compliant, compact header
  expansion, multi-value header splitting, structured accessors
- **SDP parsing, building, and negotiation** — RFC 4566 / RFC 3264, codec
  selection, DTMF, direction handling, bandwidth support
- **Transports** — UDP (`DatagramProtocol`) and TCP (Content-Length framing)
- **UAS** — incoming call handling with INVITE/BYE/CANCEL/OPTIONS dispatch,
  auto 100 Trying, `IncomingCall` high-level API
- **UAC** — backend-initiated BYE, re-INVITE (hold/unhold), CANCEL, INFO (DTMF)
- **Dialog management** — RFC 3261 dialog state machine, Record-Route support,
  in-dialog request/response creation
- **Transaction matching** — client and server transaction layer
- **aiortp bridge** — `CallSession` bridging SDP negotiation to RTP media with
  audio/DTMF callbacks
- **X-header support** — pass application metadata (room ID, session ID, tenant)
  through SIP headers

## Installation

```bash
pip install aiosipua

# With optional RTP support
pip install aiosipua[rtp]
```

## Examples

### Parse a SIP message

```python
from aiosipua import SipMessage, parse_sdp

raw = (
    "INVITE sip:bob@example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"
    "From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
    "To: Bob <sip:bob@example.com>\r\n"
    "Call-ID: a84b4c76e66710@example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@10.0.0.1:5060>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 142\r\n"
    "\r\n"
    "v=0\r\n"
    "o=- 2890844526 2890844526 IN IP4 10.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 20000 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=sendrecv\r\n"
)

msg = SipMessage.parse(raw)

# Structured header access
print(msg.from_addr.display_name)  # "Alice"
print(msg.from_addr.uri.user)      # "alice"
print(msg.to_addr.uri.host)        # "example.com"
print(msg.via[0].branch)           # "z9hG4bK776asdhds"
print(msg.cseq.method)             # "INVITE"
print(msg.call_id)                 # "a84b4c76e66710@example.com"

# Parse the SDP body
sdp = parse_sdp(msg.body)
audio = sdp.audio
print(audio.port)                  # 20000
print(audio.codecs[0].encoding_name)  # "PCMU"
print(sdp.rtp_address)             # ("10.0.0.1", 20000)
```

### SDP negotiation

```python
from aiosipua import parse_sdp, negotiate_sdp, serialize_sdp

# Parse an incoming SDP offer
offer = parse_sdp(sdp_body)

# Negotiate: pick the best codec, build an answer
answer, chosen_pt = negotiate_sdp(
    offer=offer,
    local_ip="10.0.0.5",
    rtp_port=30000,
    supported_codecs=[0, 8],  # PCMU, PCMA
)

print(f"Chosen codec: payload type {chosen_pt}")
print(serialize_sdp(answer))
```

### Receive calls with the UAS

```python
import asyncio
from aiosipua import IncomingCall, SipUAS
from aiosipua.rtp_bridge import CallSession
from aiosipua.transport import UdpSipTransport

async def handle_invite(call: IncomingCall):
    print(f"Incoming call: {call.caller} -> {call.callee}")
    print(f"X-headers: {call.x_headers}")

    if call.sdp_offer is None:
        call.reject(488, "Not Acceptable Here")
        return

    # Negotiate SDP and create RTP session
    session = CallSession(
        local_ip="10.0.0.5",
        rtp_port=30000,
        offer=call.sdp_offer,
    )

    # Accept the call with the SDP answer
    call.ringing()
    call.accept(session.sdp_answer)
    await session.start()

    # Wire up audio and DTMF callbacks
    session.on_audio = lambda pcm, ts: print(f"Audio: {len(pcm)} bytes")
    session.on_dtmf = lambda digit, dur: print(f"DTMF: {digit}")

def handle_bye(call: IncomingCall, request):
    print(f"Call ended: {call.call_id}")

async def main():
    transport = UdpSipTransport(local_addr=("0.0.0.0", 5060))
    uas = SipUAS(transport)
    uas.on_invite = lambda call: asyncio.get_running_loop().create_task(handle_invite(call))
    uas.on_bye = handle_bye

    await uas.start()
    print("Listening on port 5060...")
    await asyncio.Event().wait()

asyncio.run(main())
```

### Backend-initiated actions with the UAC

```python
from aiosipua import SipUAC
from aiosipua.transport import UdpSipTransport

transport = UdpSipTransport(local_addr=("0.0.0.0", 5060))
uac = SipUAC(transport)

# Hang up a call
uac.send_bye(dialog, remote_addr=("10.0.0.1", 5060))

# Put a call on hold with re-INVITE
from aiosipua import build_sdp
hold_sdp = build_sdp(
    local_ip="10.0.0.5",
    rtp_port=30000,
    payload_type=0,
    direction="sendonly",
)
uac.send_reinvite(dialog, sdp=hold_sdp, remote_addr=("10.0.0.1", 5060))

# Send DTMF via SIP INFO
uac.send_info(
    dialog,
    body="Signal=5\r\nDuration=250\r\n",
    content_type="application/dtmf-relay",
    remote_addr=("10.0.0.1", 5060),
)
```

### Build a SIP message from scratch

```python
from aiosipua import SipRequest, SipResponse, generate_branch, generate_call_id, generate_tag

# Build a SIP request
request = SipRequest(method="OPTIONS", uri="sip:bob@example.com")
request.headers.set_single("Via", f"SIP/2.0/UDP 10.0.0.1:5060;branch={generate_branch()}")
request.headers.set_single("From", f"<sip:alice@example.com>;tag={generate_tag()}")
request.headers.set_single("To", "<sip:bob@example.com>")
request.headers.set_single("Call-ID", generate_call_id())
request.headers.set_single("CSeq", "1 OPTIONS")

# Serialize to bytes for the wire
raw_bytes = bytes(request)
```

### Modify and re-serialize

```python
from aiosipua import SipMessage

msg = SipMessage.parse(raw_sip_text)

# Add a Via header
msg.headers.append("Via", "SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bKnew")

# Change the Contact
msg.headers.set_single("Contact", "<sip:newhost@10.0.0.99:5060>")

# Add custom X-headers
msg.headers.set_single("X-Room-ID", "room-42")
msg.headers.set_single("X-Session-ID", "sess-abc123")

# Re-serialize (Content-Length auto-updated)
print(msg.serialize())
```

### TCP transport

```python
import asyncio
from aiosipua.transport import TcpSipTransport

async def main():
    transport = TcpSipTransport(local_addr=("0.0.0.0", 5060))

    # As a server
    transport.on_message = lambda msg, addr: print(f"Received from {addr}")
    await transport.start()

    # Or connect as a client
    await transport.connect(("proxy.example.com", 5060))
    transport.send(request, ("proxy.example.com", 5060))

asyncio.run(main())
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│  SipUAS     │────▶│  Dialog      │────▶│  SipUAC    │
│  (incoming) │     │  (state mgr) │     │  (outgoing)│
└──────┬──────┘     └──────────────┘     └─────┬──────┘
       │                                       │
       ▼                                       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Transaction │    │  SDP/Codec   │    │  CallSession │
│  Layer       │    │  Negotiation │    │  (RTP bridge)│
└──────┬───────┘    └──────────────┘    └──────┬───────┘
       │                                       │
       ▼                                       ▼
┌──────────────┐                        ┌──────────────┐
│  Transport   │                        │  aiortp      │
│  (UDP / TCP) │                        │  (optional)  │
└──────────────┘                        └──────────────┘
```

## More examples

See the [`examples/`](examples/) directory:

- **`echo_server.py`** — Receives audio via RTP and echoes it back
- **`dtmf_ivr.py`** — Collects DTMF digits and hangs up on `#`
- **`roomkit_prototype.py`** — Voice AI backend integration with X-header metadata

## License

BSD-3-Clause. See [LICENSE](LICENSE) for details.
