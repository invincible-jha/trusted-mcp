"""Unit tests for trusted_mcp.audit — logger, formatter, and storage."""
from __future__ import annotations

import asyncio
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from trusted_mcp.audit.formatter import AuditFormatter
from trusted_mcp.audit.logger import AuditEntry, AuditLogger
from trusted_mcp.audit.storage import FileStorage, NullStorage, StdoutStorage
from trusted_mcp.core.result import Action, ChainResult, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_result(
    action: Action = Action.PASS,
    scanner_name: str = "test-scanner",
    reason: str = "",
) -> ScanResult:
    return ScanResult(action=action, scanner_name=scanner_name, reason=reason)


def _make_chain_result(
    action: Action = Action.PASS,
    results: list[ScanResult] | None = None,
) -> ChainResult:
    all_results = results or [_make_scan_result(action)]
    return ChainResult(
        action=action,
        all_results=all_results,
        warnings=[r for r in all_results if r.action == Action.WARN],
    )


def _make_entry(**kwargs: object) -> AuditEntry:
    defaults: dict[str, object] = {
        "tool_name": "test_tool",
        "server_name": "test_server",
        "action": "pass",
        "latency_ms": 12.3,
    }
    defaults.update(kwargs)
    return AuditEntry(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------

class TestAuditEntry:
    def test_defaults(self) -> None:
        entry = AuditEntry()
        assert entry.action == "pass"
        assert entry.event_type == "tool_call"
        assert entry.policy_name == "default"
        assert entry.latency_ms == 0.0

    def test_timestamp_is_set_automatically(self) -> None:
        entry = AuditEntry()
        assert entry.timestamp != ""
        assert "T" in entry.timestamp  # ISO 8601

    def test_request_id_is_uuid(self) -> None:
        entry = AuditEntry()
        # UUID format: 8-4-4-4-12
        parts = entry.request_id.split("-")
        assert len(parts) == 5

    def test_custom_fields(self) -> None:
        entry = _make_entry(tool_name="my_tool", server_name="srv", latency_ms=99.9)
        assert entry.tool_name == "my_tool"
        assert entry.server_name == "srv"
        assert entry.latency_ms == pytest.approx(99.9)


# ---------------------------------------------------------------------------
# AuditLogger internals
# ---------------------------------------------------------------------------

class TestAuditLoggerInternals:
    def _make_logger(self) -> AuditLogger:
        storage = NullStorage()
        return AuditLogger(storage=storage, policy_name="test-policy")

    def test_truncate_short_text_unchanged(self) -> None:
        logger = self._make_logger()
        assert logger._truncate("hello", 10) == "hello"

    def test_truncate_long_text_appends_ellipsis(self) -> None:
        logger = self._make_logger()
        result = logger._truncate("a" * 300, 200)
        assert len(result) == 203  # 200 + "..."
        assert result.endswith("...")

    def test_make_scanner_summary_basic(self) -> None:
        logger = self._make_logger()
        result = _make_scan_result(
            action=Action.WARN,
            scanner_name="regex",
            reason="found injection",
        )
        summary = logger._make_scanner_summary(result)
        assert summary["scanner"] == "regex"
        assert summary["action"] == "warn"
        assert summary["reason"] == "found injection"

    def test_make_scanner_summary_no_reason_omits_key(self) -> None:
        logger = self._make_logger()
        result = _make_scan_result(reason="")
        summary = logger._make_scanner_summary(result)
        assert "reason" not in summary

    def test_make_scanner_summary_unknown_scanner(self) -> None:
        logger = self._make_logger()
        result = ScanResult(action=Action.PASS)
        summary = logger._make_scanner_summary(result)
        assert summary["scanner"] == "unknown"

    def test_build_entry_includes_scanner_results(self) -> None:
        logger = self._make_logger()
        chain = _make_chain_result(
            Action.WARN,
            [_make_scan_result(Action.WARN, "pii", "found email")],
        )
        entry = logger._build_entry(
            tool_name="t",
            server_name="s",
            action="warn",
            chain_result=chain,
        )
        assert len(entry.scanner_results) == 1
        assert entry.scanner_results[0]["scanner"] == "pii"

    def test_build_entry_redacts_request_args(self) -> None:
        logger = self._make_logger()
        long_text = "x" * 300
        entry = logger._build_entry(
            tool_name="t",
            server_name="s",
            action="pass",
            request_args=long_text,
        )
        assert len(entry.request_args_preview) < len(long_text) + 10
        assert entry.request_args_preview.endswith("...")

    def test_build_entry_no_redact_when_disabled(self) -> None:
        storage = NullStorage()
        logger = AuditLogger(storage=storage, redact_args=False)
        long_text = "y" * 300
        entry = logger._build_entry(
            tool_name="t",
            server_name="s",
            action="pass",
            request_args=long_text,
        )
        assert entry.request_args_preview == long_text


# ---------------------------------------------------------------------------
# AuditLogger async methods
# ---------------------------------------------------------------------------

class TestAuditLoggerAsync:
    def _run(self, coro: object) -> object:
        return asyncio.run(coro)  # type: ignore[arg-type]

    def _captured_logger(self) -> tuple[AuditLogger, list[AuditEntry]]:
        captured: list[AuditEntry] = []

        class CapturingStorage(NullStorage):
            async def write(self, entry: AuditEntry) -> None:
                captured.append(entry)

        logger = AuditLogger(CapturingStorage(), policy_name="capture-test")
        return logger, captured

    def test_log_passed_writes_entry_with_action_pass(self) -> None:
        logger, captured = self._captured_logger()
        chain = _make_chain_result()
        self._run(
            logger.log_passed("tool", "srv", chain, request_args="args", response_text="ok")
        )
        assert len(captured) == 1
        assert captured[0].action == "pass"

    def test_log_blocked_writes_entry_with_action_block(self) -> None:
        logger, captured = self._captured_logger()
        chain = _make_chain_result(Action.BLOCK)
        self._run(logger.log_blocked("tool", "srv", chain, request_args="args"))
        assert captured[0].action == "block"

    def test_log_warned_writes_entry_with_action_warn(self) -> None:
        logger, captured = self._captured_logger()
        chain = _make_chain_result(Action.WARN)
        self._run(logger.log_warned("tool", "srv", chain))
        assert captured[0].action == "warn"

    def test_log_error_writes_entry_with_action_error_and_event_type_error(self) -> None:
        logger, captured = self._captured_logger()
        self._run(logger.log_error("tool", "srv", "something broke", latency_ms=5.0))
        assert captured[0].action == "error"
        assert captured[0].event_type == "error"

    def test_log_passed_sets_policy_name(self) -> None:
        logger, captured = self._captured_logger()
        chain = _make_chain_result()
        self._run(logger.log_passed("t", "s", chain))
        assert captured[0].policy_name == "capture-test"

    def test_log_blocked_sets_latency_ms(self) -> None:
        logger, captured = self._captured_logger()
        chain = _make_chain_result(Action.BLOCK)
        self._run(logger.log_blocked("t", "s", chain, latency_ms=42.0))
        assert captured[0].latency_ms == pytest.approx(42.0)


# ---------------------------------------------------------------------------
# AuditFormatter
# ---------------------------------------------------------------------------

class TestAuditFormatter:
    def _entry(self) -> AuditEntry:
        return _make_entry(
            tool_name="my_tool",
            server_name="my_server",
            action="pass",
            latency_ms=50.0,
        )

    def test_format_json_is_parseable(self) -> None:
        entry = self._entry()
        line = AuditFormatter.format_json(entry)
        parsed = json.loads(line)
        assert parsed["tool_name"] == "my_tool"

    def test_format_json_pretty_is_indented(self) -> None:
        entry = self._entry()
        pretty = AuditFormatter.format_json_pretty(entry)
        assert "\n" in pretty
        parsed = json.loads(pretty)
        assert parsed["action"] == "pass"

    def test_format_csv_header_contains_expected_columns(self) -> None:
        header = AuditFormatter.format_csv_header()
        for col in ("timestamp", "tool_name", "server_name", "action", "latency_ms"):
            assert col in header

    def test_format_csv_row_has_correct_field_count(self) -> None:
        entry = self._entry()
        row = AuditFormatter.format_csv_row(entry)
        # Should have 8 comma-separated fields (possibly with quoting)
        import csv
        fields = list(csv.reader([row]))[0]
        assert len(fields) == 8

    def test_format_csv_row_contains_tool_name(self) -> None:
        entry = self._entry()
        row = AuditFormatter.format_csv_row(entry)
        assert "my_tool" in row

    def test_format_table_row_contains_server_and_tool(self) -> None:
        entry = self._entry()
        row = AuditFormatter.format_table_row(entry)
        assert "my_tool" in row
        assert "my_server" in row

    def test_format_table_row_block_action(self) -> None:
        entry = _make_entry(action="block")
        row = AuditFormatter.format_table_row(entry)
        assert "BLOCK" in row

    def test_format_table_row_warn_action(self) -> None:
        entry = _make_entry(action="warn")
        row = AuditFormatter.format_table_row(entry)
        assert "WARN" in row

    def test_format_table_row_pass_action(self) -> None:
        entry = _make_entry(action="pass")
        row = AuditFormatter.format_table_row(entry)
        assert "PASS" in row

    def test_format_table_header_contains_separator(self) -> None:
        header = AuditFormatter.format_table_header()
        assert "---" in header

    def test_format_table_row_short_timestamp(self) -> None:
        entry = _make_entry()
        # Patch a short timestamp to exercise the else branch
        entry = entry.model_copy(update={"timestamp": "short"})
        row = AuditFormatter.format_table_row(entry)
        assert "short" in row


# ---------------------------------------------------------------------------
# AuditStorage backends
# ---------------------------------------------------------------------------

class TestNullStorage:
    async def test_write_is_noop(self) -> None:
        storage = NullStorage()
        entry = _make_entry()
        await storage.write(entry)  # must not raise

    async def test_close_is_noop(self) -> None:
        storage = NullStorage()
        await storage.close()  # must not raise


class TestStdoutStorage:
    async def test_write_outputs_jsonl_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        storage = StdoutStorage()
        entry = _make_entry(tool_name="stdout_tool")
        await storage.write(entry)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["tool_name"] == "stdout_tool"

    async def test_write_flushes_stdout(self) -> None:
        storage = StdoutStorage()
        entry = _make_entry()
        # Should complete without raising
        await storage.write(entry)


class TestFileStorage:
    async def test_write_creates_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        storage = FileStorage(log_file)
        entry = _make_entry(tool_name="file_tool")
        await storage.write(entry)
        assert log_file.exists()

    async def test_write_appends_jsonl(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        storage = FileStorage(log_file)
        for tool in ["tool_a", "tool_b"]:
            await storage.write(_make_entry(tool_name=tool))
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["tool_name"] == "tool_a"

    async def test_write_creates_parent_directories(self, tmp_path: Path) -> None:
        log_file = tmp_path / "logs" / "sub" / "audit.jsonl"
        storage = FileStorage(log_file)
        await storage.write(_make_entry())
        assert log_file.exists()

    async def test_rotation_not_triggered_below_max_size(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        storage = FileStorage(log_file, max_size_mb=100.0)
        # Write one small entry — rotation must not happen
        await storage.write(_make_entry())
        rotated = log_file.with_suffix(".1")
        assert not rotated.exists()

    async def test_rotation_disabled_when_max_size_zero(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        storage = FileStorage(log_file, max_size_mb=0)
        await storage.write(_make_entry())
        # No rotation file should appear
        assert not log_file.with_suffix(".1").exists()

    async def test_rotation_triggered_when_file_exceeds_max_size(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        # Create a "large" existing log file (1 byte threshold)
        log_file.write_text("x" * 10, encoding="utf-8")
        # Use a very small max_size_mb so any file triggers rotation
        storage = FileStorage(log_file, max_size_mb=0.000001)
        await storage.write(_make_entry())
        # Original file should have been rotated
        assert log_file.with_suffix(".1").exists()
