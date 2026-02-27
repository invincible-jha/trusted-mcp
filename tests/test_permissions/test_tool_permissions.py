"""Tests for trusted_mcp.permissions.tool_permissions."""
from __future__ import annotations

import pytest

from trusted_mcp.permissions.tool_permissions import (
    PermissionViolation,
    ToolPermission,
    ToolPermissionChecker,
    ViolationType,
)


# ---------------------------------------------------------------------------
# ToolPermission tests
# ---------------------------------------------------------------------------


class TestToolPermissionCreate:
    def test_create_minimal(self) -> None:
        perm = ToolPermission.create("my_tool")
        assert perm.tool_name == "my_tool"
        assert perm.allowed_paths == ()
        assert perm.max_response_size == 0
        assert perm.requires_approval is False
        assert perm.allowed_argument_keys == ()
        assert perm.denied_argument_values == {}

    def test_create_with_all_fields(self) -> None:
        perm = ToolPermission.create(
            "read_file",
            allowed_paths=["/workspace/**", "/tmp/*.txt"],
            max_response_size=65536,
            requires_approval=True,
            allowed_argument_keys=["path", "encoding"],
            denied_argument_values={"path": ["/etc/passwd", "/etc/shadow"]},
        )
        assert perm.tool_name == "read_file"
        assert "/workspace/**" in perm.allowed_paths
        assert perm.max_response_size == 65536
        assert perm.requires_approval is True
        assert "path" in perm.allowed_argument_keys
        assert "/etc/passwd" in perm.denied_argument_values.get("path", frozenset())

    def test_frozen_immutability(self) -> None:
        perm = ToolPermission.create("tool")
        with pytest.raises((AttributeError, TypeError)):
            perm.tool_name = "other"  # type: ignore[misc]

    def test_denied_values_stored_lowercase(self) -> None:
        perm = ToolPermission.create(
            "tool",
            denied_argument_values={"mode": ["ADMIN", "Root"]},
        )
        denied = perm.denied_argument_values["mode"]
        assert "admin" in denied
        assert "root" in denied


class TestToolPermissionPathIsAllowed:
    def test_no_patterns_allows_all(self) -> None:
        perm = ToolPermission.create("tool")
        assert perm.path_is_allowed("/any/path/whatsoever") is True

    def test_matching_glob_pattern(self) -> None:
        perm = ToolPermission.create("tool", allowed_paths=["/workspace/**"])
        assert perm.path_is_allowed("/workspace/project/file.py") is True

    def test_non_matching_glob_pattern(self) -> None:
        perm = ToolPermission.create("tool", allowed_paths=["/workspace/**"])
        assert perm.path_is_allowed("/etc/passwd") is False

    def test_multiple_patterns_any_match(self) -> None:
        perm = ToolPermission.create(
            "tool",
            allowed_paths=["/workspace/**", "/tmp/*.txt"],
        )
        assert perm.path_is_allowed("/tmp/notes.txt") is True
        assert perm.path_is_allowed("/tmp/notes.py") is False

    def test_windows_backslash_normalized(self) -> None:
        perm = ToolPermission.create("tool", allowed_paths=["/workspace/**"])
        assert perm.path_is_allowed("/workspace\\subdir\\file.py") is True


# ---------------------------------------------------------------------------
# ToolPermissionChecker tests
# ---------------------------------------------------------------------------


class TestToolPermissionCheckerRegistration:
    def test_register_and_get(self) -> None:
        checker = ToolPermissionChecker()
        perm = ToolPermission.create("tool_a")
        checker.register(perm)
        assert checker.get("tool_a") is perm

    def test_get_unknown_tool_returns_none(self) -> None:
        checker = ToolPermissionChecker()
        assert checker.get("nonexistent") is None

    def test_register_many(self) -> None:
        checker = ToolPermissionChecker()
        perms = [
            ToolPermission.create("tool_a"),
            ToolPermission.create("tool_b"),
        ]
        checker.register_many(perms)
        assert checker.get("tool_a") is not None
        assert checker.get("tool_b") is not None

    def test_register_replaces_existing(self) -> None:
        checker = ToolPermissionChecker()
        perm1 = ToolPermission.create("tool_a", max_response_size=100)
        perm2 = ToolPermission.create("tool_a", max_response_size=200)
        checker.register(perm1)
        checker.register(perm2)
        assert checker.get("tool_a").max_response_size == 200  # type: ignore[union-attr]


class TestToolPermissionCheckerCheckRequest:
    def test_unregistered_tool_permissive_mode(self) -> None:
        checker = ToolPermissionChecker(strict_mode=False)
        violations = checker.check_request("unknown_tool", {"arg": "val"})
        assert violations == []

    def test_unregistered_tool_strict_mode(self) -> None:
        checker = ToolPermissionChecker(strict_mode=True)
        violations = checker.check_request("unknown_tool", {"arg": "val"})
        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.TOOL_NOT_REGISTERED

    def test_no_violations_compliant_request(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("read_file", allowed_paths=["/workspace/**"])
        )
        violations = checker.check_request("read_file", {"path": "/workspace/main.py"})
        assert violations == []

    def test_path_violation_detected(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("read_file", allowed_paths=["/workspace/**"])
        )
        violations = checker.check_request("read_file", {"path": "/etc/passwd"})
        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.PATH_NOT_ALLOWED
        assert violations[0].argument_key == "path"
        assert violations[0].offending_value == "/etc/passwd"

    def test_approval_required_always_flagged(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("sensitive_tool", requires_approval=True)
        )
        violations = checker.check_request("sensitive_tool", {})
        types = [v.violation_type for v in violations]
        assert ViolationType.APPROVAL_REQUIRED in types

    def test_denied_argument_value(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create(
                "run_query",
                denied_argument_values={"mode": ["admin"]},
            )
        )
        violations = checker.check_request("run_query", {"mode": "ADMIN"})
        assert any(
            v.violation_type == ViolationType.ARGUMENT_TYPE_INVALID
            for v in violations
        )

    def test_allowed_argument_keys_enforced(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create(
                "tool",
                allowed_argument_keys=["query"],
            )
        )
        violations = checker.check_request("tool", {"query": "hello", "extra": "bad"})
        assert any(
            v.violation_type == ViolationType.ARGUMENT_TYPE_INVALID
            and v.argument_key == "extra"
            for v in violations
        )

    def test_file_path_key_variants_checked(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("tool", allowed_paths=["/safe/**"])
        )
        for key in ["file_path", "filepath", "filename", "directory"]:
            violations = checker.check_request("tool", {key: "/unsafe/place"})
            assert any(
                v.violation_type == ViolationType.PATH_NOT_ALLOWED
                for v in violations
            ), f"Expected violation for key={key}"

    def test_non_path_keys_not_path_checked(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("tool", allowed_paths=["/safe/**"])
        )
        violations = checker.check_request("tool", {"query": "/unsafe/place"})
        assert not any(
            v.violation_type == ViolationType.PATH_NOT_ALLOWED
            for v in violations
        )


class TestToolPermissionCheckerCheckResponseSize:
    def test_no_limit_configured(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(ToolPermission.create("tool", max_response_size=0))
        violations = checker.check_response_size("tool", "x" * 1_000_000)
        assert violations == []

    def test_within_limit(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(ToolPermission.create("tool", max_response_size=100))
        violations = checker.check_response_size("tool", "hello")
        assert violations == []

    def test_exceeds_limit_str(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(ToolPermission.create("tool", max_response_size=10))
        violations = checker.check_response_size("tool", "x" * 100)
        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.RESPONSE_TOO_LARGE

    def test_exceeds_limit_bytes(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(ToolPermission.create("tool", max_response_size=5))
        violations = checker.check_response_size("tool", b"0123456789")
        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.RESPONSE_TOO_LARGE

    def test_unregistered_tool_no_violation(self) -> None:
        checker = ToolPermissionChecker()
        violations = checker.check_response_size("unknown", "x" * 1_000_000)
        assert violations == []


class TestIsCompliant:
    def test_compliant_request(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("tool", allowed_paths=["/workspace/**"])
        )
        assert checker.is_compliant("tool", {"path": "/workspace/x.py"}) is True

    def test_approval_required_does_not_block_is_compliant(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("tool", requires_approval=True)
        )
        # Approval-required is a soft signal, not a hard block
        assert checker.is_compliant("tool", {}) is True

    def test_path_violation_not_compliant(self) -> None:
        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create("tool", allowed_paths=["/workspace/**"])
        )
        assert checker.is_compliant("tool", {"path": "/etc/passwd"}) is False


class TestPermissionViolationDataclass:
    def test_violation_frozen(self) -> None:
        v = PermissionViolation(
            tool_name="t",
            violation_type=ViolationType.PATH_NOT_ALLOWED,
            detail="test",
        )
        with pytest.raises((AttributeError, TypeError)):
            v.tool_name = "x"  # type: ignore[misc]

    def test_violation_defaults(self) -> None:
        v = PermissionViolation(
            tool_name="t",
            violation_type=ViolationType.APPROVAL_REQUIRED,
            detail="needs approval",
        )
        assert v.argument_key == ""
        assert v.offending_value == ""
