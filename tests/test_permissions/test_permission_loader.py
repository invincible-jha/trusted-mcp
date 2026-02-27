"""Tests for trusted_mcp.permissions.permission_loader."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from trusted_mcp.permissions.permission_loader import (
    PermissionLoader,
    load_permissions_from_yaml,
)
from trusted_mcp.permissions.tool_permissions import ViolationType


VALID_YAML = """
permissions:
  - tool_name: read_file
    allowed_paths:
      - "/workspace/**"
    max_response_size: 65536
    requires_approval: false

  - tool_name: execute_command
    requires_approval: true
    max_response_size: 1048576
    denied_argument_values:
      shell:
        - "bash"
        - "sh"
"""

EMPTY_YAML = ""

MINIMAL_YAML = """
permissions:
  - tool_name: my_tool
"""


class TestLoadPermissionsFromYaml:
    def test_valid_yaml_returns_correct_count(self) -> None:
        perms = load_permissions_from_yaml(VALID_YAML)
        assert len(perms) == 2

    def test_tool_names_parsed(self) -> None:
        perms = load_permissions_from_yaml(VALID_YAML)
        names = {p.tool_name for p in perms}
        assert "read_file" in names
        assert "execute_command" in names

    def test_allowed_paths_parsed(self) -> None:
        perms = load_permissions_from_yaml(VALID_YAML)
        read_perm = next(p for p in perms if p.tool_name == "read_file")
        assert "/workspace/**" in read_perm.allowed_paths

    def test_requires_approval_parsed(self) -> None:
        perms = load_permissions_from_yaml(VALID_YAML)
        exec_perm = next(p for p in perms if p.tool_name == "execute_command")
        assert exec_perm.requires_approval is True

    def test_denied_values_parsed(self) -> None:
        perms = load_permissions_from_yaml(VALID_YAML)
        exec_perm = next(p for p in perms if p.tool_name == "execute_command")
        assert "bash" in exec_perm.denied_argument_values.get("shell", frozenset())

    def test_empty_yaml_returns_empty_list(self) -> None:
        perms = load_permissions_from_yaml(EMPTY_YAML)
        assert perms == []

    def test_minimal_entry(self) -> None:
        perms = load_permissions_from_yaml(MINIMAL_YAML)
        assert len(perms) == 1
        assert perms[0].tool_name == "my_tool"

    def test_missing_tool_name_raises(self) -> None:
        bad_yaml = "permissions:\n  - max_response_size: 100\n"
        with pytest.raises(ValueError, match="tool_name"):
            load_permissions_from_yaml(bad_yaml)

    def test_invalid_top_level_raises(self) -> None:
        with pytest.raises(ValueError):
            load_permissions_from_yaml("- item1\n- item2\n")


class TestPermissionLoader:
    def test_load_string_returns_checker(self) -> None:
        loader = PermissionLoader()
        checker = loader.load_string(VALID_YAML)
        assert checker.get("read_file") is not None
        assert checker.get("execute_command") is not None

    def test_checker_validates_correctly(self) -> None:
        loader = PermissionLoader()
        checker = loader.load_string(VALID_YAML)
        violations = checker.check_request(
            "read_file", {"path": "/etc/passwd"}
        )
        assert any(
            v.violation_type == ViolationType.PATH_NOT_ALLOWED
            for v in violations
        )

    def test_load_file(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(VALID_YAML)
            tmp_path = Path(tmp.name)

        try:
            loader = PermissionLoader()
            checker = loader.load_file(tmp_path)
            assert checker.get("read_file") is not None
        finally:
            tmp_path.unlink()

    def test_load_file_not_found_raises(self) -> None:
        loader = PermissionLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_file(Path("/nonexistent/path/permissions.yaml"))

    def test_strict_mode_propagated(self) -> None:
        loader = PermissionLoader(strict_mode=True)
        checker = loader.load_string(VALID_YAML)
        assert checker.strict_mode is True
        violations = checker.check_request("unknown_tool", {})
        assert any(
            v.violation_type == ViolationType.TOOL_NOT_REGISTERED
            for v in violations
        )
