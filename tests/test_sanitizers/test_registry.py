"""Tests for trusted_mcp.sanitizers.registry.SanitizerRegistry."""
from __future__ import annotations

import pytest

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult
from trusted_mcp.sanitizers.registry import SanitizerRegistry
from trusted_mcp.sanitizers.shell_sanitizer import ShellSanitizer
from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer
from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer


class AlwaysSafeSanitizer(Sanitizer):
    """Test sanitizer that always returns safe."""

    def sanitize(self, value: str) -> SanitizeResult:
        return SanitizeResult(safe=True, original=value, sanitized=value)


class AlwaysUnsafeSanitizer(Sanitizer):
    """Test sanitizer that always returns unsafe."""

    def sanitize(self, value: str) -> SanitizeResult:
        return SanitizeResult(
            safe=False,
            original=value,
            sanitized=value,
            violations=["always rejected"],
        )


class TestSanitizerRegistryInitialisation:
    def test_default_registry_has_rules(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        assert registry.rule_count() > 0

    def test_no_defaults_registry_is_empty(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        assert registry.rule_count() == 0

    def test_default_registry_has_shell_sanitizer_for_all_tools(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("any_tool")
        assert any(isinstance(s, ShellSanitizer) for s in sanitizers)

    def test_default_registry_has_path_sanitizer_for_file_tools(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("read_file")
        assert any(isinstance(s, PathSanitizer) for s in sanitizers)

    def test_default_registry_has_sql_sanitizer_for_db_tools(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("sql_query")
        assert any(isinstance(s, SQLSanitizer) for s in sanitizers)


class TestSanitizerRegistryRegister:
    def test_register_adds_rule(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [AlwaysSafeSanitizer()])
        assert registry.rule_count() == 1

    def test_register_empty_list_raises(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        with pytest.raises(ValueError, match="empty sanitizer list"):
            registry.register(".*", [])

    def test_register_invalid_pattern_raises(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        with pytest.raises(Exception):
            registry.register("[invalid", [AlwaysSafeSanitizer()])

    def test_register_multiple_rules(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register("tool_a", [AlwaysSafeSanitizer()])
        registry.register("tool_b", [AlwaysUnsafeSanitizer()])
        assert registry.rule_count() == 2


class TestSanitizerRegistryGetSanitizers:
    def test_matching_pattern_returns_sanitizers(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        sanitizer = AlwaysSafeSanitizer()
        registry.register("my_tool", [sanitizer])
        result = registry.get_sanitizers("my_tool")
        assert sanitizer in result

    def test_non_matching_pattern_returns_empty(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register("specific_tool", [AlwaysSafeSanitizer()])
        result = registry.get_sanitizers("other_tool")
        assert result == []

    def test_wildcard_pattern_matches_all(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        sanitizer = AlwaysSafeSanitizer()
        registry.register(".*", [sanitizer])
        for name in ["any_tool", "read_file", "query_db"]:
            result = registry.get_sanitizers(name)
            assert sanitizer in result

    def test_multiple_matching_patterns_combine_sanitizers(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        safe_sanitizer = AlwaysSafeSanitizer()
        unsafe_sanitizer = AlwaysUnsafeSanitizer()
        registry.register(".*", [safe_sanitizer])
        registry.register("file.*", [unsafe_sanitizer])
        result = registry.get_sanitizers("file_read")
        assert safe_sanitizer in result
        assert unsafe_sanitizer in result

    def test_registration_order_preserved(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        s1 = AlwaysSafeSanitizer()
        s2 = AlwaysUnsafeSanitizer()
        registry.register(".*", [s1, s2])
        result = registry.get_sanitizers("any_tool")
        assert result[0] is s1
        assert result[1] is s2

    def test_case_insensitive_matching(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        sanitizer = AlwaysSafeSanitizer()
        registry.register("file_read", [sanitizer])
        result = registry.get_sanitizers("FILE_READ")
        assert sanitizer in result


class TestSanitizerRegistryClear:
    def test_clear_removes_all_rules(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        registry.clear()
        assert registry.rule_count() == 0

    def test_after_clear_no_sanitizers_returned(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        registry.clear()
        result = registry.get_sanitizers("any_tool")
        assert result == []


class TestSanitizerRegistryDefaultMappings:
    def test_path_tool_gets_path_and_shell_sanitizer(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("read_path")
        types = {type(s) for s in sanitizers}
        assert ShellSanitizer in types
        assert PathSanitizer in types

    def test_db_tool_gets_sql_and_shell_sanitizer(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("database_query")
        types = {type(s) for s in sanitizers}
        assert ShellSanitizer in types
        assert SQLSanitizer in types

    def test_generic_tool_only_gets_shell_sanitizer(self) -> None:
        registry = SanitizerRegistry(use_defaults=True)
        sanitizers = registry.get_sanitizers("send_email")
        types = {type(s) for s in sanitizers}
        assert ShellSanitizer in types
        # Should not include SQL or Path for a non-matching tool
        assert SQLSanitizer not in types
        assert PathSanitizer not in types
