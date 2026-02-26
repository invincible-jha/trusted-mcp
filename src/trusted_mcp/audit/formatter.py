"""Audit log formatting utilities.

Converts AuditEntry objects into various output formats for display,
export, and integration with log management systems.
"""
from __future__ import annotations

import csv
import io
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trusted_mcp.audit.logger import AuditEntry


class AuditFormatter:
    """Formats AuditEntry objects into structured output."""

    @staticmethod
    def format_json(entry: AuditEntry) -> str:
        """Format entry as a single JSON line (JSONL format)."""
        return entry.model_dump_json()

    @staticmethod
    def format_json_pretty(entry: AuditEntry) -> str:
        """Format entry as indented JSON."""
        return json.dumps(entry.model_dump(), indent=2, default=str)

    @staticmethod
    def format_csv_header() -> str:
        """Return CSV header row."""
        return ",".join([
            "timestamp",
            "request_id",
            "tool_name",
            "server_name",
            "action",
            "latency_ms",
            "policy_name",
            "event_type",
        ])

    @staticmethod
    def format_csv_row(entry: AuditEntry) -> str:
        """Format entry as a CSV row."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            entry.timestamp,
            entry.request_id,
            entry.tool_name,
            entry.server_name,
            entry.action,
            f"{entry.latency_ms:.1f}",
            entry.policy_name,
            entry.event_type,
        ])
        return output.getvalue().strip()

    @staticmethod
    def format_table_row(entry: AuditEntry) -> str:
        """Format entry as a fixed-width table row for terminal display."""
        action_display = entry.action.upper()
        if action_display == "BLOCK":
            action_display = f"BLOCK"
        elif action_display == "WARN":
            action_display = f"WARN "
        elif action_display == "PASS":
            action_display = f"PASS "

        time_part = entry.timestamp[11:19] if len(entry.timestamp) > 19 else entry.timestamp
        return (
            f"{time_part}  {action_display}  "
            f"{entry.server_name:20s}  {entry.tool_name:30s}  "
            f"{entry.latency_ms:7.1f}ms"
        )

    @staticmethod
    def format_table_header() -> str:
        """Return table header with separator."""
        header = (
            f"{'TIME':8s}  {'ACTION':5s}  "
            f"{'SERVER':20s}  {'TOOL':30s}  "
            f"{'LATENCY':>9s}"
        )
        separator = "-" * len(header)
        return f"{header}\n{separator}"
