"""Protocol helper utilities for SIP message generation."""

from __future__ import annotations

import os
import uuid


def generate_call_id(domain: str) -> str:
    """Generate a unique Call-ID in the form ``{uuid4}@{domain}``."""
    return f"{uuid.uuid4()}@{domain}"


def generate_branch() -> str:
    """Generate a Via branch parameter with the RFC 3261 magic cookie prefix."""
    return f"z9hG4bK{os.urandom(8).hex()}"


def generate_tag() -> str:
    """Generate a random tag for From/To headers."""
    return os.urandom(8).hex()


def bracket_ipv6(host: str) -> str:
    """Bracket a bare IPv6 literal for URI/Via serialization (RFC 3261 §19.1.1)."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def format_addr(host: str, port: int) -> str:
    """``host:port`` for URIs and Via sent-by, bracketing IPv6 literals."""
    return f"{bracket_ipv6(host)}:{port}"
