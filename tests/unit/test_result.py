"""Unit tests for trusted_mcp.core.result."""
from __future__ import annotations

import pytest

from trusted_mcp.core.result import Action, ChainResult, ScanResult


class TestAction:
    def test_pass_value(self) -> None:
        assert Action.PASS.value == "pass"

    def test_warn_value(self) -> None:
        assert Action.WARN.value == "warn"

    def test_block_value(self) -> None:
        assert Action.BLOCK.value == "block"

    def test_is_str_subclass(self) -> None:
        assert isinstance(Action.PASS, str)
        assert isinstance(Action.WARN, str)
        assert isinstance(Action.BLOCK, str)

    def test_all_members(self) -> None:
        members = {a.value for a in Action}
        assert members == {"pass", "warn", "block"}

    @pytest.mark.parametrize("value,expected", [
        ("pass", Action.PASS),
        ("warn", Action.WARN),
        ("block", Action.BLOCK),
    ])
    def test_lookup_by_value(self, value: str, expected: Action) -> None:
        assert Action(value) == expected


class TestScanResult:
    def test_minimum_construction(self) -> None:
        result = ScanResult(action=Action.PASS)
        assert result.action == Action.PASS
        assert result.reason is None
        assert result.details is None
        assert result.scanner_name is None
        assert result.confidence == 1.0

    def test_full_construction(self) -> None:
        result = ScanResult(
            action=Action.BLOCK,
            reason="SQL injection",
            details={"pattern": "union_select"},
            scanner_name="regex",
            confidence=0.95,
        )
        assert result.action == Action.BLOCK
        assert result.reason == "SQL injection"
        assert result.details == {"pattern": "union_select"}
        assert result.scanner_name == "regex"
        assert result.confidence == 0.95

    def test_confidence_zero_is_valid(self) -> None:
        result = ScanResult(action=Action.PASS, confidence=0.0)
        assert result.confidence == 0.0

    def test_confidence_one_is_valid(self) -> None:
        result = ScanResult(action=Action.PASS, confidence=1.0)
        assert result.confidence == 1.0

    @pytest.mark.parametrize("bad_confidence", [-0.01, 1.01, -1.0, 2.0, 100.0])
    def test_confidence_out_of_range_raises(self, bad_confidence: float) -> None:
        with pytest.raises(ValueError, match="confidence"):
            ScanResult(action=Action.PASS, confidence=bad_confidence)

    def test_warn_result_with_reason(self) -> None:
        result = ScanResult(action=Action.WARN, reason="suspicious content")
        assert result.action == Action.WARN
        assert result.reason == "suspicious content"

    def test_details_dict_stored(self) -> None:
        details: dict[str, object] = {"matched": ["pattern_a"], "score": 3}
        result = ScanResult(action=Action.WARN, details=details)
        assert result.details == details


class TestChainResult:
    def test_minimum_construction_pass(self) -> None:
        result = ChainResult(action=Action.PASS)
        assert result.action == Action.PASS
        assert result.blocking_scanner is None
        assert result.blocking_reason is None
        assert result.blocking_details is None
        assert result.warnings == []
        assert result.all_results == []

    def test_full_block_construction(self) -> None:
        warn = ScanResult(action=Action.WARN, reason="minor issue", scanner_name="pii")
        block = ScanResult(action=Action.BLOCK, reason="SQL injection", scanner_name="regex")
        result = ChainResult(
            action=Action.BLOCK,
            blocking_scanner="regex",
            blocking_reason="SQL injection",
            blocking_details={"pattern": "union_select"},
            warnings=[warn],
            all_results=[warn, block],
        )
        assert result.action == Action.BLOCK
        assert result.blocking_scanner == "regex"
        assert result.blocking_reason == "SQL injection"
        assert len(result.warnings) == 1
        assert len(result.all_results) == 2

    def test_is_blocked_true_when_blocked(self) -> None:
        result = ChainResult(action=Action.BLOCK, blocking_scanner="regex")
        assert result.is_blocked is True

    def test_is_blocked_false_when_pass(self) -> None:
        result = ChainResult(action=Action.PASS)
        assert result.is_blocked is False

    def test_is_blocked_false_when_warn(self) -> None:
        result = ChainResult(action=Action.WARN)
        assert result.is_blocked is False

    def test_has_warnings_true_when_warnings_present(self) -> None:
        warn = ScanResult(action=Action.WARN, reason="minor")
        result = ChainResult(action=Action.WARN, warnings=[warn])
        assert result.has_warnings is True

    def test_has_warnings_false_when_empty(self) -> None:
        result = ChainResult(action=Action.PASS)
        assert result.has_warnings is False

    def test_warning_reasons_returns_all_non_none(self) -> None:
        w1 = ScanResult(action=Action.WARN, reason="issue one")
        w2 = ScanResult(action=Action.WARN, reason=None)
        w3 = ScanResult(action=Action.WARN, reason="issue three")
        result = ChainResult(action=Action.WARN, warnings=[w1, w2, w3])
        reasons = result.warning_reasons()
        assert reasons == ["issue one", "issue three"]

    def test_warning_reasons_empty_when_no_warnings(self) -> None:
        result = ChainResult(action=Action.PASS)
        assert result.warning_reasons() == []

    def test_warnings_default_factory_isolation(self) -> None:
        r1 = ChainResult(action=Action.PASS)
        r2 = ChainResult(action=Action.PASS)
        r1.warnings.append(ScanResult(action=Action.WARN))
        assert len(r2.warnings) == 0

    def test_all_results_default_factory_isolation(self) -> None:
        r1 = ChainResult(action=Action.PASS)
        r2 = ChainResult(action=Action.PASS)
        r1.all_results.append(ScanResult(action=Action.PASS))
        assert len(r2.all_results) == 0
