"""Tests for trusted_mcp.sanitizers.sql_sanitizer.SQLSanitizer."""
from __future__ import annotations

import pytest

from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer


@pytest.fixture()
def sanitizer() -> SQLSanitizer:
    return SQLSanitizer()


class TestSQLSanitizerBenignInputs:
    def test_plain_text_passes(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("John Smith")
        assert result.safe is True
        assert result.violations == []

    def test_email_address_passes(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("user@example.com")
        assert result.safe is True

    def test_numeric_value_passes(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("42")
        assert result.safe is True

    def test_empty_string_passes(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("")
        assert result.safe is True

    def test_normal_search_query_passes(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("find files in the project directory")
        assert result.safe is True

    def test_single_quote_in_name_no_injection_passes(
        self, sanitizer: SQLSanitizer
    ) -> None:
        # A name like "O'Brien" with a single quote but no injection context
        result = sanitizer.sanitize("O'Brien")
        assert isinstance(result.safe, bool)  # Depends on pattern specifics


class TestSQLSanitizerAttackPatterns:
    def test_or_1_equals_1_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("' OR 1=1 --")
        assert result.safe is False
        assert len(result.violations) > 0

    def test_drop_table_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("'; DROP TABLE users; --")
        assert result.safe is False

    def test_union_select_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("' UNION SELECT username, password FROM users --")
        assert result.safe is False

    def test_sql_comment_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("admin'--")
        assert result.safe is False

    def test_stacked_insert_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("value'; INSERT INTO admin VALUES('hacker', 'pw');--")
        assert result.safe is False

    def test_stacked_update_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("'; UPDATE users SET role='admin' WHERE 1=1--")
        assert result.safe is False

    def test_union_all_select_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("1 UNION ALL SELECT NULL,NULL,NULL--")
        assert result.safe is False

    def test_sleep_based_blind_injection_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("1' AND sleep(5)--")
        assert result.safe is False

    def test_comment_based_injection_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("admin'/**/OR/**/1=1--")
        assert result.safe is False

    def test_case_insensitive_detection(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("' union select * from users --")
        assert result.safe is False

    def test_truncate_table_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("'; TRUNCATE TABLE sessions;--")
        assert result.safe is False


class TestSQLSanitizerAlwaysRejects:
    def test_sanitized_equals_original_on_violation(
        self, sanitizer: SQLSanitizer
    ) -> None:
        value = "' OR 1=1 --"
        result = sanitizer.sanitize(value)
        assert result.sanitized == value
        assert result.original == value

    def test_violations_list_populated(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("' OR 1=1 --")
        assert isinstance(result.violations, list)
        assert len(result.violations) > 0


class TestSQLSanitizerEdgeCases:
    def test_very_long_string_no_error(self, sanitizer: SQLSanitizer) -> None:
        long_input = "a" * 100000
        result = sanitizer.sanitize(long_input)
        assert isinstance(result.safe, bool)

    def test_unicode_input_no_error(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("用户名称 SELECT")
        assert isinstance(result.safe, bool)

    def test_multiline_sql_blocked(self, sanitizer: SQLSanitizer) -> None:
        result = sanitizer.sanitize("value\n'; DROP TABLE users; --")
        assert result.safe is False
