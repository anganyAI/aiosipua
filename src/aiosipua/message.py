"""SIP message model: parsing, serialization, and structured accessors."""

from __future__ import annotations

from dataclasses import dataclass, field

from .headers import (
    MULTI_INSTANCE_HEADERS,
    Address,
    CaseInsensitiveDict,
    CSeq,
    Via,
    expand_compact_header,
    parse_address,
    parse_cseq,
    parse_via,
    prettify_header_name,
    stringify_address,
    stringify_cseq,
    stringify_via,
)


def _split_multi_value(s: str) -> list[str]:
    """Split a header value on commas, respecting angle brackets and quotes.

    State machine: tracks nesting inside ``< >`` and ``" "`` so that commas
    within URIs or quoted strings are not treated as separators.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_quotes = False

    for ch in s:
        if ch == '"' and depth == 0:
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == "<" and not in_quotes:
            depth += 1
            current.append(ch)
        elif ch == ">" and not in_quotes:
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0 and not in_quotes:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


@dataclass
class SipMessage:
    """Base class for SIP messages."""

    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    body: str = ""

    @staticmethod
    def parse(data: str) -> SipRequest | SipResponse:
        """Parse a raw SIP message string into a typed message object."""
        # Split headers from body, preserving body content as-is
        if "\r\n\r\n" in data:
            header_section, _, body = data.partition("\r\n\r\n")
        elif "\n\n" in data:
            header_section, _, body = data.partition("\n\n")
        else:
            header_section = data
            body = ""

        # Normalize line endings in header section only
        header_section = header_section.replace("\r\n", "\n").replace("\r", "\n")
        lines = header_section.split("\n")
        if not lines:
            raise ValueError("Empty SIP message")

        start_line = lines[0].strip()

        # Unfold continuation lines (RFC 3261 §7.3.1)
        header_lines: list[str] = []
        for line in lines[1:]:
            if not line:
                continue
            if line[0] in (" ", "\t") and header_lines:
                # Continuation of previous header
                header_lines[-1] += " " + line.strip()
            else:
                header_lines.append(line)

        # Parse headers
        headers = CaseInsensitiveDict()
        for line in header_lines:
            colon_idx = line.find(":")
            if colon_idx == -1:
                continue
            name = line[:colon_idx].strip()
            value = line[colon_idx + 1 :].strip()

            # Expand compact headers
            name = expand_compact_header(name)

            # Split multi-value headers
            lower = name.lower()
            if lower in MULTI_INSTANCE_HEADERS:
                for val in _split_multi_value(value):
                    headers.append(name, val)
            else:
                headers.append(name, value)

        # Detect request vs response
        if start_line.startswith("SIP/"):
            # Response: "SIP/2.0 200 OK"
            parts = start_line.split(None, 2)
            status_code = int(parts[1]) if len(parts) > 1 else 0
            reason = parts[2] if len(parts) > 2 else ""
            return SipResponse(
                headers=headers, body=body, status_code=status_code, reason_phrase=reason
            )
        else:
            # Request: "INVITE sip:bob@example.com SIP/2.0"
            parts = start_line.split(None, 2)
            method = parts[0] if parts else ""
            uri = parts[1] if len(parts) > 1 else ""
            return SipRequest(headers=headers, body=body, method=method, uri=uri)

    def serialize(self) -> str:
        """Serialize the message back to a SIP wire-format string."""
        lines: list[str] = [self._start_line()]

        # Auto-set Content-Length
        body_bytes = self.body.encode("utf-8") if self.body else b""
        self.headers.set_single("Content-Length", str(len(body_bytes)))

        for name, values in self.headers.items():
            pretty = prettify_header_name(name)
            for val in values:
                lines.append(f"{pretty}: {val}")

        lines.append("")
        result = "\r\n".join(lines)
        if self.body:
            result += "\r\n" + self.body
        else:
            result += "\r\n"
        return result

    def _start_line(self) -> str:
        raise NotImplementedError

    def __bytes__(self) -> bytes:
        return self.serialize().encode("utf-8")

    # --- Header convenience methods ---

    def get_header(self, name: str) -> str | None:
        """Get the first value of a header."""
        return self.headers.get_first(name)

    def get_header_values(self, name: str) -> list[str]:
        """Get all values for a header."""
        return self.headers.get(name)

    def set_header(self, name: str, value: str) -> None:
        """Set a header to a single value."""
        self.headers.set_single(name, value)

    def add_header(self, name: str, value: str) -> None:
        """Append a value to a header."""
        self.headers.append(name, value)

    def remove_header(self, name: str) -> None:
        """Remove all values for a header."""
        self.headers.remove(name)

    # --- Structured property accessors (lazy parsing) ---

    @property
    def via(self) -> list[Via]:
        """All Via headers, parsed into :class:`Via` objects."""
        return [parse_via(v) for v in self.headers.get("via")]

    @via.setter
    def via(self, vias: list[Via]) -> None:
        self.headers.remove("via")
        for v in vias:
            self.headers.append("Via", stringify_via(v))

    @property
    def from_addr(self) -> Address | None:
        """The From header, parsed into an :class:`Address`."""
        raw = self.headers.get_first("from")
        return parse_address(raw) if raw else None

    @from_addr.setter
    def from_addr(self, addr: Address) -> None:
        self.headers.set_single("From", stringify_address(addr))

    @property
    def to_addr(self) -> Address | None:
        """The To header, parsed into an :class:`Address`."""
        raw = self.headers.get_first("to")
        return parse_address(raw) if raw else None

    @to_addr.setter
    def to_addr(self, addr: Address) -> None:
        self.headers.set_single("To", stringify_address(addr))

    @property
    def cseq(self) -> CSeq | None:
        """The CSeq header, parsed into a :class:`CSeq`."""
        raw = self.headers.get_first("cseq")
        return parse_cseq(raw) if raw else None

    @cseq.setter
    def cseq(self, cseq: CSeq) -> None:
        self.headers.set_single("CSeq", stringify_cseq(cseq))

    @property
    def call_id(self) -> str | None:
        """The Call-ID header value."""
        return self.headers.get_first("call-id")

    @call_id.setter
    def call_id(self, value: str) -> None:
        self.headers.set_single("Call-ID", value)

    @property
    def contact(self) -> list[Address]:
        """All Contact headers, parsed into :class:`Address` objects."""
        return [parse_address(v) for v in self.headers.get("contact")]

    @contact.setter
    def contact(self, addrs: list[Address]) -> None:
        self.headers.remove("contact")
        for a in addrs:
            self.headers.append("Contact", stringify_address(a))

    @property
    def content_type(self) -> str | None:
        """The Content-Type header value."""
        return self.headers.get_first("content-type")

    @content_type.setter
    def content_type(self, value: str) -> None:
        self.headers.set_single("Content-Type", value)

    @property
    def content_length(self) -> int:
        """The Content-Length header value (defaults to 0)."""
        raw = self.headers.get_first("content-length")
        return int(raw) if raw else 0

    @content_length.setter
    def content_length(self, value: int) -> None:
        self.headers.set_single("Content-Length", str(value))


@dataclass
class SipRequest(SipMessage):
    """A SIP request message."""

    method: str = ""
    uri: str = ""

    def _start_line(self) -> str:
        return f"{self.method} {self.uri} SIP/2.0"


@dataclass
class SipResponse(SipMessage):
    """A SIP response message."""

    status_code: int = 0
    reason_phrase: str = ""

    def _start_line(self) -> str:
        return f"SIP/2.0 {self.status_code} {self.reason_phrase}"
