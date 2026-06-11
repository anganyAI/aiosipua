"""Parsing and serialization of structured SIP header values.

The wire codecs for URIs, addresses, Via, CSeq, and auth headers — the
data model lives in :mod:`aiosipua.headers`, which re-exports everything
here for the public API.
"""

from __future__ import annotations

from typing import Literal, overload

from .headers import Address, AuthChallenge, AuthCredentials, CSeq, SipUri, Via

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
                try:
                    uri.port = int(after[1:])
                except ValueError:
                    uri.host = hostport
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


def _bracket_ipv6(host: str) -> str:
    """Bracket a bare IPv6 literal for URI/Via serialization (RFC 3261 §19.1.1)."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def stringify_uri(uri: SipUri) -> str:
    """Serialize a :class:`SipUri` back to string form."""
    s = f"{uri.scheme}:"
    if uri.user is not None:
        s += f"{uri.user}@"
    s += _bracket_ipv6(uri.host)
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
                key = stripped.split("=", 1)[0].strip().lower()
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
                try:
                    via.port = int(after[1:])
                except ValueError:
                    via.host = sentby
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
    s = f"{via.protocol}/{via.transport} {_bracket_ipv6(via.host)}"
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


# Params serialized as unquoted tokens (RFC 7616 §3.3/§3.4).  ``qop`` is a
# token in credentials but a quoted list in challenges.
_UNQUOTED_AUTH_PARAMS = frozenset({"algorithm", "nc", "stale"})


def stringify_auth(auth: AuthChallenge | AuthCredentials) -> str:
    """Serialize an auth challenge or credentials back to string form."""
    is_credentials = isinstance(auth, AuthCredentials)
    parts: list[str] = []
    for key, val in auth.params.items():
        k = key.lower()
        if k in _UNQUOTED_AUTH_PARAMS or (k == "qop" and is_credentials):
            parts.append(f"{key}={val}")
        else:
            parts.append(f'{key}="{val}"')
    return f"{auth.scheme} {', '.join(parts)}"
