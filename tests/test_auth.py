"""Tests for aiosipua.auth (RFC 7616 / RFC 8760 digest authentication)."""

from __future__ import annotations

import hashlib

from aiosipua.auth import SipDigestAuth, build_credentials
from aiosipua.headers import AuthChallenge, parse_auth, stringify_auth

# RFC 7616 §3.9.1 example: same challenge for both algorithms
_RFC7616_AUTH = SipDigestAuth(username="Mufasa", password="Circle of Life")
_RFC7616_PARAMS = {
    "realm": "http-auth@example.org",
    "qop": "auth, auth-int",
    "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
}
_RFC7616_CNONCE = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"


class TestRfc7616Vectors:
    def _build(self, algorithm: str) -> dict[str, str]:
        challenge = AuthChallenge(
            scheme="Digest", params={**_RFC7616_PARAMS, "algorithm": algorithm}
        )
        creds = build_credentials(
            _RFC7616_AUTH,
            challenge,
            "GET",
            "/dir/index.html",
            cnonce=_RFC7616_CNONCE,
        )
        assert creds is not None
        return creds.params

    def test_md5_response(self) -> None:
        params = self._build("MD5")
        assert params["response"] == "8ca523f5e9506fed4657c9700eebdbec"

    def test_sha256_response(self) -> None:
        params = self._build("SHA-256")
        assert params["response"] == (
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        )

    def test_qop_params_present(self) -> None:
        params = self._build("SHA-256")
        assert params["qop"] == "auth"
        assert params["nc"] == "00000001"
        assert params["cnonce"] == _RFC7616_CNONCE

    def test_opaque_echoed(self) -> None:
        params = self._build("SHA-256")
        assert params["opaque"] == _RFC7616_PARAMS["opaque"]

    def test_algorithm_echoed(self) -> None:
        assert self._build("SHA-256")["algorithm"] == "SHA-256"
        assert self._build("MD5")["algorithm"] == "MD5"


class TestLegacyRfc2617:
    def test_no_qop_uses_legacy_formula(self) -> None:
        """Challenge without qop → RFC 2617 response, no nc/cnonce in credentials."""
        challenge = AuthChallenge(
            scheme="Digest", params={"realm": "asterisk", "nonce": "abc123def456"}
        )
        auth = SipDigestAuth(username="alice", password="secret")
        creds = build_credentials(auth, challenge, "INVITE", "sip:them@example.com")
        assert creds is not None

        ha1 = hashlib.md5(b"alice:asterisk:secret").hexdigest()
        ha2 = hashlib.md5(b"INVITE:sip:them@example.com").hexdigest()
        expected = hashlib.md5(f"{ha1}:abc123def456:{ha2}".encode()).hexdigest()

        assert creds.params["response"] == expected
        assert "qop" not in creds.params
        assert "nc" not in creds.params
        assert "cnonce" not in creds.params


class TestUnsupportedChallenges:
    def test_non_digest_scheme(self) -> None:
        challenge = AuthChallenge(scheme="Bearer", params={"realm": "x"})
        auth = SipDigestAuth(username="a", password="b")
        assert build_credentials(auth, challenge, "INVITE", "sip:x") is None

    def test_missing_nonce(self) -> None:
        challenge = AuthChallenge(scheme="Digest", params={"realm": "x"})
        auth = SipDigestAuth(username="a", password="b")
        assert build_credentials(auth, challenge, "INVITE", "sip:x") is None

    def test_unknown_algorithm(self) -> None:
        challenge = AuthChallenge(
            scheme="Digest",
            params={"realm": "x", "nonce": "n", "algorithm": "SHA-512-256"},
        )
        auth = SipDigestAuth(username="a", password="b")
        assert build_credentials(auth, challenge, "INVITE", "sip:x") is None

    def test_qop_without_auth_mode(self) -> None:
        """qop offered but no "auth" choice (e.g. auth-int only) → unsupported."""
        challenge = AuthChallenge(
            scheme="Digest",
            params={"realm": "x", "nonce": "n", "qop": "auth-int"},
        )
        auth = SipDigestAuth(username="a", password="b")
        assert build_credentials(auth, challenge, "INVITE", "sip:x") is None


class TestWireFormat:
    def test_credentials_serialization_quoting(self) -> None:
        """RFC 7616 §3.4: algorithm/qop/nc are tokens; the rest is quoted."""
        challenge = AuthChallenge(
            scheme="Digest",
            params={
                "realm": "asterisk",
                "nonce": "abc",
                "qop": "auth",
                "algorithm": "SHA-256",
                "opaque": "xyz",
            },
        )
        auth = SipDigestAuth(username="alice", password="secret")
        creds = build_credentials(auth, challenge, "INVITE", "sip:them@example.com")
        assert creds is not None
        wire = stringify_auth(creds)

        assert wire.startswith("Digest ")
        assert 'username="alice"' in wire
        assert 'realm="asterisk"' in wire
        assert 'nonce="abc"' in wire
        assert 'uri="sip:them@example.com"' in wire
        assert 'opaque="xyz"' in wire
        assert "algorithm=SHA-256" in wire
        assert 'algorithm="' not in wire
        assert "qop=auth" in wire
        assert 'qop="' not in wire
        assert "nc=00000001" in wire
        assert 'nc="' not in wire

    def test_round_trip_through_parse(self) -> None:
        challenge = AuthChallenge(
            scheme="Digest", params={"realm": "r", "nonce": "n", "qop": "auth"}
        )
        auth = SipDigestAuth(username="u", password="p")
        creds = build_credentials(auth, challenge, "INVITE", "sip:x")
        assert creds is not None

        reparsed = parse_auth(stringify_auth(creds), credentials=True)
        assert reparsed.scheme == "Digest"
        assert reparsed.params["username"] == "u"
        assert reparsed.params["nc"] == "00000001"
        assert reparsed.params["response"] == creds.params["response"]
