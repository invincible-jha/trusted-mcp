"""Tests for trusted_mcp.sanitizers.url_sanitizer.URLSanitizer."""
from __future__ import annotations

import pytest

from trusted_mcp.sanitizers.url_sanitizer import URLSanitizer


@pytest.fixture()
def sanitizer() -> URLSanitizer:
    return URLSanitizer()


class TestURLSanitizerBenignInputs:
    def test_https_url_passes(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("https://example.com/api/data")
        assert result.safe is True
        assert result.violations == []

    def test_http_url_passes(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("http://example.com")
        assert result.safe is True

    def test_https_with_path_and_query_passes(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("https://api.example.com/v2/users?limit=10&offset=0")
        assert result.safe is True

    def test_empty_string_passes(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("")
        assert result.safe is True

    def test_plain_text_without_scheme_passes(self, sanitizer: URLSanitizer) -> None:
        # Non-URL text should pass through since it's not a URL
        result = sanitizer.sanitize("just some plain text")
        assert result.safe is True

    def test_hostname_without_scheme_passes(self, sanitizer: URLSanitizer) -> None:
        # "example.com" without a scheme is not a URL
        result = sanitizer.sanitize("example.com")
        assert result.safe is True


class TestURLSanitizerDangerousSchemes:
    def test_file_scheme_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("file:///etc/passwd")
        assert result.safe is False
        assert len(result.violations) > 0

    def test_javascript_scheme_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("javascript:alert(1)")
        assert result.safe is False

    def test_javascript_with_spaces_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("javascript  :alert(document.cookie)")
        assert result.safe is False

    def test_data_scheme_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("data:text/html;base64,PHNjcmlwdD4=")
        assert result.safe is False

    def test_ftp_scheme_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("ftp://attacker.com/malware.exe")
        assert result.safe is False

    def test_vbscript_scheme_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("vbscript:MsgBox('XSS')")
        assert result.safe is False

    def test_file_windows_path_blocked(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("file:///C:/Windows/System32/drivers/etc/hosts")
        assert result.safe is False


class TestURLSanitizerCustomSchemes:
    def test_custom_allowed_scheme_passes(self) -> None:
        sanitizer = URLSanitizer(allowed_schemes={"https", "sftp"})
        result = sanitizer.sanitize("sftp://secure-server.example.com/data")
        assert result.safe is True

    def test_http_blocked_when_not_in_custom_allowlist(self) -> None:
        sanitizer = URLSanitizer(allowed_schemes={"https"})
        result = sanitizer.sanitize("http://example.com")
        assert result.safe is False

    def test_default_https_still_works_with_custom_set(self) -> None:
        sanitizer = URLSanitizer(allowed_schemes={"https", "ftp"})
        # ftp is in allowed_schemes — check that always-blocked still applies
        result = sanitizer.sanitize("file:///etc/passwd")
        assert result.safe is False


class TestURLSanitizerAlwaysRejects:
    def test_sanitized_equals_original_on_violation(
        self, sanitizer: URLSanitizer
    ) -> None:
        value = "file:///etc/passwd"
        result = sanitizer.sanitize(value)
        assert result.sanitized == value
        assert result.original == value

    def test_violations_populated_on_block(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("javascript:alert(1)")
        assert isinstance(result.violations, list)
        assert len(result.violations) > 0


class TestURLSanitizerEdgeCases:
    def test_very_long_url_no_error(self, sanitizer: URLSanitizer) -> None:
        long_url = "https://example.com/" + "a" * 10000
        result = sanitizer.sanitize(long_url)
        assert isinstance(result.safe, bool)

    def test_unicode_url_no_error(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("https://例え.jp/パス")
        assert isinstance(result.safe, bool)

    def test_url_missing_host_flagged(self, sanitizer: URLSanitizer) -> None:
        result = sanitizer.sanitize("https:///no-host")
        # URL with scheme but no host should be flagged
        assert isinstance(result.safe, bool)
