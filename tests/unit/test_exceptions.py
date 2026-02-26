"""Unit tests for trusted_mcp.core.exceptions."""
from __future__ import annotations

import pytest

from trusted_mcp.core.exceptions import (
    AuditError,
    ConfigError,
    PolicyError,
    ProxyError,
    ScannerError,
    ScannerNotFoundError,
    TrustedMCPError,
)


class TestTrustedMCPError:
    def test_is_exception_subclass(self) -> None:
        assert issubclass(TrustedMCPError, Exception)

    def test_can_raise_and_catch(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise TrustedMCPError("base error")

    def test_message_preserved(self) -> None:
        exc = TrustedMCPError("something went wrong")
        assert str(exc) == "something went wrong"

    def test_empty_message(self) -> None:
        exc = TrustedMCPError()
        assert str(exc) == ""


class TestScannerError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(ScannerError, TrustedMCPError)

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise ScannerError("scanner failed")

    def test_message_preserved(self) -> None:
        exc = ScannerError("regex compile error")
        assert "regex compile error" in str(exc)


class TestPolicyError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(PolicyError, TrustedMCPError)

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise PolicyError("missing required field")

    def test_message_preserved(self) -> None:
        exc = PolicyError("invalid YAML")
        assert "invalid YAML" in str(exc)


class TestProxyError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(ProxyError, TrustedMCPError)

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise ProxyError("connection refused")

    def test_message_preserved(self) -> None:
        exc = ProxyError("transport error")
        assert "transport error" in str(exc)


class TestConfigError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(ConfigError, TrustedMCPError)

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise ConfigError("missing env var")

    def test_message_preserved(self) -> None:
        exc = ConfigError("invalid log level")
        assert "invalid log level" in str(exc)


class TestAuditError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(AuditError, TrustedMCPError)

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise AuditError("file write failed")

    def test_message_preserved(self) -> None:
        exc = AuditError("storage backend error")
        assert "storage backend error" in str(exc)


class TestScannerNotFoundError:
    def test_is_trusted_mcp_error(self) -> None:
        assert issubclass(ScannerNotFoundError, TrustedMCPError)

    def test_stores_scanner_name(self) -> None:
        exc = ScannerNotFoundError("my_scanner", ["regex", "allowlist"])
        assert exc.scanner_name == "my_scanner"

    def test_stores_available_list(self) -> None:
        available = ["regex", "allowlist"]
        exc = ScannerNotFoundError("missing", available)
        assert exc.available == available

    def test_message_contains_scanner_name(self) -> None:
        exc = ScannerNotFoundError("my_scanner", ["regex"])
        assert "my_scanner" in str(exc)

    def test_message_contains_available_scanners(self) -> None:
        exc = ScannerNotFoundError("missing", ["regex", "allowlist"])
        assert "regex" in str(exc)
        assert "allowlist" in str(exc)

    def test_empty_available_list_shows_none(self) -> None:
        exc = ScannerNotFoundError("missing", [])
        assert "(none)" in str(exc)

    def test_available_sorted_in_message(self) -> None:
        exc = ScannerNotFoundError("missing", ["zzz", "aaa", "mmm"])
        message = str(exc)
        aaa_pos = message.index("aaa")
        mmm_pos = message.index("mmm")
        zzz_pos = message.index("zzz")
        assert aaa_pos < mmm_pos < zzz_pos

    def test_caught_by_base_class(self) -> None:
        with pytest.raises(TrustedMCPError):
            raise ScannerNotFoundError("x", [])

    def test_contains_registration_hint(self) -> None:
        exc = ScannerNotFoundError("x", [])
        assert "register" in str(exc).lower()
