"""Tests for aiosipua.utils."""

from aiosipua.utils import generate_branch, generate_call_id, generate_tag


class TestGenerateCallId:
    def test_format(self) -> None:
        cid = generate_call_id("example.com")
        assert "@example.com" in cid
        local, _, domain = cid.partition("@")
        assert domain == "example.com"
        assert len(local) > 0

    def test_uniqueness(self) -> None:
        ids = {generate_call_id("example.com") for _ in range(100)}
        assert len(ids) == 100


class TestGenerateBranch:
    def test_magic_cookie_prefix(self) -> None:
        branch = generate_branch()
        assert branch.startswith("z9hG4bK")

    def test_length(self) -> None:
        branch = generate_branch()
        # "z9hG4bK" (7) + 16 hex chars
        assert len(branch) == 23

    def test_uniqueness(self) -> None:
        branches = {generate_branch() for _ in range(100)}
        assert len(branches) == 100


class TestGenerateTag:
    def test_format(self) -> None:
        tag = generate_tag()
        # 8 bytes = 16 hex chars
        assert len(tag) == 16
        int(tag, 16)  # should not raise

    def test_uniqueness(self) -> None:
        tags = {generate_tag() for _ in range(100)}
        assert len(tags) == 100
