"""SIP header parsing, dataclasses, and serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


# --- Compact header expansion (RFC 3261 §7.3.3) ---

COMPACT_HEADERS: dict[str, str] = {
    "i": "call-id",
    "m": "contact",
    "e": "content-encoding",
    "l": "content-length",
    "c": "content-type",
    "f": "from",
    "s": "subject",
    "k": "supported",
    "t": "to",
    "v": "via",
}


def expand_compact_header(name: str) -> str:
    """Expand a single-letter compact header name to its full form."""
    return COMPACT_HEADERS.get(name.lower(), name)


# --- Header name prettification ---

_PRETTY_NAMES: dict[str, str] = {
    "accept": "Accept",
    "accept-encoding": "Accept-Encoding",
    "accept-language": "Accept-Language",
    "alert-info": "Alert-Info",
    "allow": "Allow",
    "authentication-info": "Authentication-Info",
    "authorization": "Authorization",
    "call-id": "Call-ID",
    "call-info": "Call-Info",
    "contact": "Contact",
    "content-disposition": "Content-Disposition",
    "content-encoding": "Content-Encoding",
    "content-language": "Content-Language",
    "content-length": "Content-Length",
    "content-type": "Content-Type",
    "cseq": "CSeq",
    "date": "Date",
    "error-info": "Error-Info",
    "event": "Event",
    "expires": "Expires",
    "from": "From",
    "in-reply-to": "In-Reply-To",
    "max-forwards": "Max-Forwards",
    "mime-version": "MIME-Version",
    "min-expires": "Min-Expires",
    "organization": "Organization",
    "path": "Path",
    "priority": "Priority",
    "proxy-authenticate": "Proxy-Authenticate",
    "proxy-authorization": "Proxy-Authorization",
    "proxy-require": "Proxy-Require",
    "record-route": "Record-Route",
    "refer-to": "Refer-To",
    "reply-to": "Reply-To",
    "require": "Require",
    "retry-after": "Retry-After",
    "route": "Route",
    "server": "Server",
    "subject": "Subject",
    "supported": "Supported",
    "timestamp": "Timestamp",
    "to": "To",
    "unsupported": "Unsupported",
    "user-agent": "User-Agent",
    "via": "Via",
    "warning": "Warning",
    "www-authenticate": "WWW-Authenticate",
}


def prettify_header_name(name: str) -> str:
    """Return the canonical casing for a known SIP header, or title-case fallback."""
    pretty = _PRETTY_NAMES.get(name.lower())
    if pretty is not None:
        return pretty
    # Title-case fallback: capitalize each word separated by hyphens
    return "-".join(part.capitalize() for part in name.split("-"))


# --- Multi-instance headers ---

MULTI_INSTANCE_HEADERS: frozenset[str] = frozenset(
    {
        "via",
        "contact",
        "route",
        "record-route",
        "path",
        "allow",
        "supported",
        "require",
        "proxy-require",
        "unsupported",
        "accept",
        "accept-encoding",
        "accept-language",
        "warning",
    }
)


# --- Case-insensitive header dict ---


def _check_header_safety(name: str, value: str) -> None:
    """Reject header injection at the API boundary (CWE-93).

    Application data fed into ``set_single``/``append`` must never smuggle
    extra header lines into the serialized message.
    """
    if "\r" in name or "\n" in name or ":" in name:
        raise ValueError(f"Invalid header name: {name!r}")
    if "\r" in value or "\n" in value:
        raise ValueError(f"Header value for {name} contains line breaks")


class CaseInsensitiveDict:
    """Case-insensitive dict for SIP headers, preserving original casing.

    Setters reject names/values containing line breaks (header injection).
    """

    def __init__(self) -> None:
        self._store: dict[str, list[str]] = {}
        self._original: dict[str, str] = {}

    def _key(self, name: str) -> str:
        return name.lower()

    def get(self, name: str) -> list[str]:
        """Get all values for a header, or empty list if absent."""
        return self._store.get(self._key(name), [])

    def get_first(self, name: str, default: str | None = None) -> str | None:
        """Get the first value for a header, or *default* if absent."""
        values = self._store.get(self._key(name))
        if values:
            return values[0]
        return default

    def set_single(self, name: str, value: str) -> None:
        """Set a header to exactly one value, replacing any existing values.

        Raises:
            ValueError: If the name or value would inject header lines.
        """
        _check_header_safety(name, value)
        key = self._key(name)
        self._store[key] = [value]
        self._original[key] = name

    def append(self, name: str, value: str) -> None:
        """Append a value to a header (creates if absent).

        Raises:
            ValueError: If the name or value would inject header lines.
        """
        _check_header_safety(name, value)
        key = self._key(name)
        if key not in self._store:
            self._store[key] = []
            self._original[key] = name
        self._store[key].append(value)

    def remove(self, name: str) -> None:
        """Remove all values for a header."""
        key = self._key(name)
        self._store.pop(key, None)
        self._original.pop(key, None)

    def __contains__(self, name: str) -> bool:
        return self._key(name) in self._store

    def __len__(self) -> int:
        return len(self._store)

    def items(self) -> Iterator[tuple[str, list[str]]]:
        """Yield ``(original_cased_name, values)`` pairs."""
        for key, values in self._store.items():
            yield self._original[key], values

    def copy(self) -> CaseInsensitiveDict:
        """Return a shallow copy."""
        new = CaseInsensitiveDict()
        for key, values in self._store.items():
            new._store[key] = list(values)
            new._original[key] = self._original[key]
        return new


# --- Dataclasses ---


@dataclass
class SipUri:
    """SIP or SIPS URI (RFC 3261 §19.1)."""

    scheme: str = "sip"
    user: str | None = None
    host: str = ""
    port: int | None = None
    params: dict[str, str | None] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Address:
    """SIP name-addr or addr-spec (RFC 3261 §20.10)."""

    display_name: str | None = None
    uri: SipUri = field(default_factory=SipUri)
    params: dict[str, str | None] = field(default_factory=dict)

    @property
    def tag(self) -> str | None:
        """The ``tag`` parameter, if present."""
        return self.params.get("tag")

    @tag.setter
    def tag(self, value: str | None) -> None:
        if value is None:
            self.params.pop("tag", None)
        else:
            self.params["tag"] = value


@dataclass
class Via:
    """SIP Via header value (RFC 3261 §20.42)."""

    protocol: str = "SIP/2.0"
    transport: str = "UDP"
    host: str = ""
    port: int | None = None
    params: dict[str, str | None] = field(default_factory=dict)

    @property
    def branch(self) -> str | None:
        return self.params.get("branch")

    @branch.setter
    def branch(self, value: str | None) -> None:
        if value is None:
            self.params.pop("branch", None)
        else:
            self.params["branch"] = value

    @property
    def received(self) -> str | None:
        return self.params.get("received")

    @received.setter
    def received(self, value: str | None) -> None:
        if value is None:
            self.params.pop("received", None)
        else:
            self.params["received"] = value

    @property
    def rport(self) -> str | None:
        return self.params.get("rport")

    @rport.setter
    def rport(self, value: str | None) -> None:
        if value is None:
            self.params.pop("rport", None)
        else:
            self.params["rport"] = value


@dataclass
class CSeq:
    """CSeq header (RFC 3261 §20.16)."""

    seq: int = 0
    method: str = ""


@dataclass
class AuthChallenge:
    """WWW-Authenticate or Proxy-Authenticate header value."""

    scheme: str = ""
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthCredentials:
    """Authorization or Proxy-Authorization header value."""

    scheme: str = ""
    params: dict[str, str] = field(default_factory=dict)


from .header_codec import (  # noqa: E402  (facade re-export)
    parse_address,
    parse_auth,
    parse_cseq,
    parse_params,
    parse_uri,
    parse_via,
    stringify_address,
    stringify_auth,
    stringify_cseq,
    stringify_uri,
    stringify_via,
)

__all__ = [
    "COMPACT_HEADERS",
    "MULTI_INSTANCE_HEADERS",
    "Address",
    "AuthChallenge",
    "AuthCredentials",
    "CSeq",
    "CaseInsensitiveDict",
    "SipUri",
    "Via",
    "expand_compact_header",
    "parse_address",
    "parse_auth",
    "parse_cseq",
    "parse_params",
    "parse_uri",
    "parse_via",
    "prettify_header_name",
    "stringify_address",
    "stringify_auth",
    "stringify_cseq",
    "stringify_uri",
    "stringify_via",
]
