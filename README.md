# aiosipua

Asyncio SIP micro-library for Python. Companion to [aiortp](https://github.com/anganyAI/aiortp).

## Features

- SIP message parsing and serialization (RFC 3261)
- SDP parsing and building (RFC 4566)
- Zero runtime dependencies — stdlib only
- Strict type hints (mypy strict mode)
- Python 3.11+

## Installation

```bash
pip install aiosipua
```

## Quick Start

```python
from aiosipua import SipMessage, parse_sdp

# Parse a SIP message
msg = SipMessage.parse(raw_sip_text)

# Access structured headers
print(msg.via)
print(msg.from_addr)
print(msg.cseq)

# Parse SDP body
if msg.body:
    sdp = parse_sdp(msg.body)
    for media in sdp.media:
        print(media.codecs)
```

## License

BSD-3-Clause. See [LICENSE](LICENSE) for details.
