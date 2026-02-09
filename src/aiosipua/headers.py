"""SIP header parsing, dataclasses, and serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, overload

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


class CaseInsensitiveDict:
    """Case-insensitive dict for SIP headers, preserving original casing."""

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
        """Set a header to exactly one value, replacing any existing values."""
        key = self._key(name)
        self._store[key] = [value]
        self._original[key] = name

    def append(self, name: str, value: str) -> None:
        """Append a value to a header (creates if absent)."""
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


# --- Parse functions ---


def parse_params(s: str) -> dict[str, str | None]:
    """Parse ``;key=value`` parameters from a string.

    Returns a dict where valueless params map to ``None``.
    """
    params: dict[str, str | None] = {}
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            params[key.strip().lower()] = val.strip()
        else:
            params[part.lower()] = None
    return params


def parse_uri(s: str) -> SipUri:
    """Parse a SIP/SIPS URI string into a :class:`SipUri`."""
    s = s.strip()
    uri = SipUri()

    # scheme
    if ":" in s and s.split(":", 1)[0].lower() in ("sip", "sips"):
        scheme_part, _, rest = s.partition(":")
        uri.scheme = scheme_part.lower()
    else:
        rest = s

    # headers (after ?)
    if "?" in rest:
        rest, _, header_part = rest.partition("?")
        for hdr in header_part.split("&"):
            if "=" in hdr:
                hk, _, hv = hdr.partition("=")
                uri.headers[hk] = hv

    # params (after ;) — but we need to find the first ; that's not part of the hostport
    # user@host:port;params
    if ";" in rest:
        base, _, param_str = rest.partition(";")
        uri.params = parse_params(param_str)
        rest = base

    # user@host
    if "@" in rest:
        uri.user, _, hostport = rest.partition("@")
    else:
        hostport = rest

    # host:port — handle IPv6 [addr]:port
    if hostport.startswith("["):
        bracket_end = hostport.find("]")
        if bracket_end != -1:
            uri.host = hostport[: bracket_end + 1]
            after = hostport[bracket_end + 1 :]
            if after.startswith(":"):
                uri.port = int(after[1:])
        else:
            uri.host = hostport
    elif ":" in hostport:
        host_part, _, port_part = hostport.rpartition(":")
        uri.host = host_part
        try:
            uri.port = int(port_part)
        except ValueError:
            uri.host = hostport
    else:
        uri.host = hostport

    return uri


def stringify_uri(uri: SipUri) -> str:
    """Serialize a :class:`SipUri` back to string form."""
    s = f"{uri.scheme}:"
    if uri.user is not None:
        s += f"{uri.user}@"
    s += uri.host
    if uri.port is not None:
        s += f":{uri.port}"
    for key, val in uri.params.items():
        if val is not None:
            s += f";{key}={val}"
        else:
            s += f";{key}"
    if uri.headers:
        pairs = [f"{k}={v}" for k, v in uri.headers.items()]
        s += "?" + "&".join(pairs)
    return s


def parse_address(s: str) -> Address:
    """Parse a SIP address (name-addr or addr-spec) into an :class:`Address`."""
    s = s.strip()
    addr = Address()

    # name-addr form: "Display Name" <uri>;params  or  <uri>;params
    lt = s.find("<")
    gt = s.find(">")
    if lt != -1 and gt != -1 and gt > lt:
        display = s[:lt].strip()
        if display.startswith('"') and display.endswith('"'):
            display = display[1:-1]
        addr.display_name = display if display else None
        uri_str = s[lt + 1 : gt]
        addr.uri = parse_uri(uri_str)
        after = s[gt + 1 :].strip()
        if after.startswith(";"):
            addr.params = parse_params(after[1:])
    else:
        # addr-spec form: uri;params (no angle brackets)
        # Separate URI params from address params — tricky because they share ';'
        # In addr-spec, everything is part of the URI+params
        # We need to find tag= and similar address-level params
        # Heuristic: parse as URI, then extract known address params
        if ";" in s:
            parts = s.split(";")
            uri_parts: list[str] = [parts[0]]
            addr_params: list[str] = []
            for part in parts[1:]:
                stripped = part.strip()
                key = stripped.split("=", 1)[0].lower()
                if key == "tag":
                    addr_params.append(stripped)
                else:
                    uri_parts.append(part)
            addr.uri = parse_uri(";".join(uri_parts))
            if addr_params:
                addr.params = parse_params(";".join(addr_params))
        else:
            addr.uri = parse_uri(s)

    return addr


def stringify_address(addr: Address) -> str:
    """Serialize an :class:`Address` back to string form."""
    uri_str = stringify_uri(addr.uri)
    parts: list[str] = []
    if addr.display_name:
        parts.append(f'"{addr.display_name}" <{uri_str}>')
    else:
        parts.append(f"<{uri_str}>")
    for key, val in addr.params.items():
        if val is not None:
            parts.append(f";{key}={val}")
        else:
            parts.append(f";{key}")
    return "".join(parts)


def parse_via(s: str) -> Via:
    """Parse a Via header value into a :class:`Via`."""
    s = s.strip()
    via = Via()

    # "SIP/2.0/UDP host:port;params"
    # Split protocol/transport from sent-by
    slash_count = 0
    for i, ch in enumerate(s):
        if ch == "/":
            slash_count += 1
        if slash_count == 2:
            # find the space after transport
            space_idx = s.find(" ", i)
            if space_idx != -1:
                proto_part = s[:space_idx]
                rest = s[space_idx + 1 :].strip()
            else:
                proto_part = s
                rest = ""
            # parse protocol and transport
            proto_parts = proto_part.split("/")
            if len(proto_parts) >= 3:
                via.protocol = f"{proto_parts[0]}/{proto_parts[1]}"
                via.transport = proto_parts[2].upper()
            break
    else:
        rest = s

    # sent-by and params
    if ";" in rest:
        sentby, _, param_str = rest.partition(";")
        via.params = parse_params(param_str)
    else:
        sentby = rest

    sentby = sentby.strip()
    if sentby.startswith("["):
        bracket_end = sentby.find("]")
        if bracket_end != -1:
            via.host = sentby[: bracket_end + 1]
            after = sentby[bracket_end + 1 :]
            if after.startswith(":"):
                via.port = int(after[1:])
        else:
            via.host = sentby
    elif ":" in sentby:
        host_part, _, port_part = sentby.rpartition(":")
        via.host = host_part
        try:
            via.port = int(port_part)
        except ValueError:
            via.host = sentby
    else:
        via.host = sentby

    return via


def stringify_via(via: Via) -> str:
    """Serialize a :class:`Via` back to string form."""
    s = f"{via.protocol}/{via.transport} {via.host}"
    if via.port is not None:
        s += f":{via.port}"
    for key, val in via.params.items():
        if val is not None:
            s += f";{key}={val}"
        else:
            s += f";{key}"
    return s


def parse_cseq(s: str) -> CSeq:
    """Parse a CSeq header value into a :class:`CSeq`."""
    s = s.strip()
    parts = s.split(None, 1)
    if len(parts) == 2:
        return CSeq(seq=int(parts[0]), method=parts[1])
    return CSeq()


def stringify_cseq(cseq: CSeq) -> str:
    """Serialize a :class:`CSeq` back to string form."""
    return f"{cseq.seq} {cseq.method}"


@overload
def parse_auth(s: str) -> AuthChallenge: ...
@overload
def parse_auth(s: str, *, credentials: Literal[False]) -> AuthChallenge: ...
@overload
def parse_auth(s: str, *, credentials: Literal[True]) -> AuthCredentials: ...


def parse_auth(s: str, *, credentials: bool = False) -> AuthChallenge | AuthCredentials:
    """Parse an auth header (WWW-Authenticate, Authorization, etc.)."""
    s = s.strip()
    space_idx = s.find(" ")
    if space_idx == -1:
        scheme = s
        param_str = ""
    else:
        scheme = s[:space_idx]
        param_str = s[space_idx + 1 :]

    params: dict[str, str] = {}
    # Parse comma-separated key=value pairs, values may be quoted
    if param_str:
        for part in _split_auth_params(param_str):
            part = part.strip()
            if "=" in part:
                key, _, val = part.partition("=")
                val = val.strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                params[key.strip()] = val

    if credentials:
        return AuthCredentials(scheme=scheme, params=params)
    return AuthChallenge(scheme=scheme, params=params)


def _split_auth_params(s: str) -> list[str]:
    """Split auth params on commas, respecting quoted strings."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in s:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == "," and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def stringify_auth(auth: AuthChallenge | AuthCredentials) -> str:
    """Serialize an auth challenge or credentials back to string form."""
    parts: list[str] = []
    for key, val in auth.params.items():
        if val and (not val.isdigit() and val.lower() not in ("true", "false")):
            parts.append(f'{key}="{val}"')
        else:
            parts.append(f"{key}={val}")
    return f"{auth.scheme} {', '.join(parts)}"
