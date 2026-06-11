"""SIP digest authentication (RFC 7616 / RFC 8760, with RFC 2617 fallback).

Builds Authorization / Proxy-Authorization credentials from a server
challenge.  Supports ``algorithm=MD5`` and ``SHA-256``, ``qop="auth"``
(with cnonce and nonce-count), and echoes ``opaque``.

Not supported: ``auth-int`` and the ``-sess`` algorithm variants.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from .headers import AuthChallenge

from .headers import AuthCredentials


@dataclass
class SipDigestAuth:
    """Credentials for SIP digest authentication."""

    username: str
    password: str


# Algorithm registry (RFC 8760) — challenge value (uppercased) → hash constructor
_HASHERS: dict[str, Callable[[bytes], hashlib._Hash]] = {
    "MD5": hashlib.md5,
    "SHA-256": hashlib.sha256,
}


def _parse_qop(challenge_qop: str) -> list[str]:
    """Split a challenge's qop list (e.g. ``"auth, auth-int"``)."""
    return [q.strip().lower() for q in challenge_qop.split(",") if q.strip()]


def build_credentials(
    auth: SipDigestAuth,
    challenge: AuthChallenge,
    method: str,
    uri: str,
    *,
    nonce_count: int = 1,
    cnonce: str | None = None,
) -> AuthCredentials | None:
    """Compute digest credentials answering *challenge* (RFC 7616 §3.4).

    Args:
        auth: Username and password.
        challenge: Parsed WWW-Authenticate / Proxy-Authenticate value.
        method: The SIP method being authenticated (e.g. ``"INVITE"``).
        uri: The request URI (digest-uri).
        nonce_count: Times this nonce has been used, including this request.
        cnonce: Client nonce; auto-generated if ``None``.

    Returns:
        The :class:`AuthCredentials` to serialize into an Authorization /
        Proxy-Authorization header, or ``None`` if the challenge cannot be
        answered (non-digest scheme, missing nonce, unsupported algorithm,
        or qop offered without ``auth``).
    """
    if challenge.scheme.lower() != "digest":
        return None

    nonce = challenge.params.get("nonce", "")
    if not nonce:
        return None

    algorithm = challenge.params.get("algorithm", "MD5")
    hasher = _HASHERS.get(algorithm.upper())
    if hasher is None:
        return None

    # qop negotiation: the only mode we implement is "auth"
    qop_offered = _parse_qop(challenge.params.get("qop", ""))
    use_qop = "auth" in qop_offered
    if qop_offered and not use_qop:
        return None

    realm = challenge.params.get("realm", "")

    def h(data: str) -> str:
        return hasher(data.encode("utf-8")).hexdigest()

    ha1 = h(f"{auth.username}:{realm}:{auth.password}")
    ha2 = h(f"{method}:{uri}")

    params: dict[str, str] = {
        "username": auth.username,
        "realm": realm,
        "nonce": nonce,
        "uri": uri,
        "algorithm": algorithm,
    }

    if use_qop:
        if cnonce is None:
            cnonce = os.urandom(8).hex()
        nc = f"{nonce_count:08x}"
        params["response"] = h(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        params["qop"] = "auth"
        params["nc"] = nc
        params["cnonce"] = cnonce
    else:
        # RFC 2617 mode (challenge without qop)
        params["response"] = h(f"{ha1}:{nonce}:{ha2}")

    opaque = challenge.params.get("opaque")
    if opaque is not None:
        params["opaque"] = opaque

    return AuthCredentials(scheme="Digest", params=params)
