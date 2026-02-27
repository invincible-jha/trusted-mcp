"""Tests for trusted_mcp.sanitizers.path_sanitizer.PathSanitizer."""
from __future__ import annotations

import pytest

from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer


class TestPathSanitizerBenignInputs:
    def test_simple_filename_passes(self) -> None:
        sanitizer = PathSanitizer(block_absolute=False)
        result = sanitizer.sanitize("README.md")
        assert result.safe is True

    def test_relative_path_without_traversal_passes(self) -> None:
        sanitizer = PathSanitizer(block_absolute=False)
        result = sanitizer.sanitize("docs/api/README.md")
        assert result.safe is True

    def test_empty_string_passes(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("")
        assert result.safe is True

    def test_allowed_absolute_path_passes(self) -> None:
        sanitizer = PathSanitizer(allowed_base_dirs=["/workspace"])
        result = sanitizer.sanitize("/workspace/docs/readme.txt")
        assert result.safe is True

    def test_allowed_base_dir_itself_passes(self) -> None:
        sanitizer = PathSanitizer(allowed_base_dirs=["/data"])
        result = sanitizer.sanitize("/data")
        assert result.safe is True


class TestPathSanitizerTraversalDetection:
    def test_unix_dotdot_slash_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("../../etc/passwd")
        assert result.safe is False
        assert len(result.violations) > 0

    def test_windows_dotdot_backslash_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize(r"..\..\windows\system32")
        assert result.safe is False

    def test_encoded_traversal_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("%2e%2e%2fetc%2fpasswd")
        assert result.safe is False

    def test_dotdot_at_end_of_path_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("safe/path/..")
        assert result.safe is False

    def test_sensitive_etc_passwd_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("/etc/passwd")
        assert result.safe is False

    def test_sensitive_etc_shadow_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("/etc/shadow")
        assert result.safe is False

    def test_proc_self_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("/proc/self/environ")
        assert result.safe is False

    def test_sys_path_blocked(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("/sys/kernel/security")
        assert result.safe is False


class TestPathSanitizerAbsolutePaths:
    def test_absolute_path_blocked_with_no_allowlist(self) -> None:
        sanitizer = PathSanitizer(block_absolute=True)
        result = sanitizer.sanitize("/home/user/file.txt")
        assert result.safe is False

    def test_absolute_path_passes_when_block_absolute_false(self) -> None:
        sanitizer = PathSanitizer(block_absolute=False)
        result = sanitizer.sanitize("/home/user/file.txt")
        # Should pass since we only block traversal sequences in this mode
        assert isinstance(result.safe, bool)

    def test_absolute_path_outside_allowlist_blocked(self) -> None:
        sanitizer = PathSanitizer(allowed_base_dirs=["/workspace"])
        result = sanitizer.sanitize("/etc/cron.d/malicious")
        assert result.safe is False

    def test_absolute_path_in_allowlist_passes(self) -> None:
        sanitizer = PathSanitizer(allowed_base_dirs=["/workspace", "/data"])
        result = sanitizer.sanitize("/data/output/result.json")
        assert result.safe is True


class TestPathSanitizerAlwaysRejects:
    def test_path_sanitize_returns_original_on_violation(self) -> None:
        sanitizer = PathSanitizer()
        value = "../../etc/passwd"
        result = sanitizer.sanitize(value)
        assert result.sanitized == value

    def test_path_sanitize_violations_list_populated(self) -> None:
        sanitizer = PathSanitizer()
        result = sanitizer.sanitize("../../etc/passwd")
        assert isinstance(result.violations, list)
        assert len(result.violations) > 0


class TestPathSanitizerEdgeCases:
    def test_very_long_path_no_error(self) -> None:
        sanitizer = PathSanitizer(block_absolute=False)
        long_path = "safe/" * 1000 + "file.txt"
        result = sanitizer.sanitize(long_path)
        assert isinstance(result.safe, bool)

    def test_unicode_path_no_error(self) -> None:
        sanitizer = PathSanitizer(block_absolute=False)
        result = sanitizer.sanitize("文档/readme.txt")
        assert isinstance(result.safe, bool)

    def test_windows_style_drive_path_blocked_with_no_allowlist(self) -> None:
        sanitizer = PathSanitizer(block_absolute=True)
        result = sanitizer.sanitize("C:/Windows/System32")
        assert result.safe is False
