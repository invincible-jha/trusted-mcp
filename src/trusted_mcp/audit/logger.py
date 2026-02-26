"""Structured JSON audit logger for MCP tool calls.

Records every tool call interaction — request, response, scan results,
timing, and policy decisions — in structured format for forensic
analysis and compliance.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from trusted_mcp.audit.storage import AuditStorage
    from trusted_mcp.core.result import ChainResult, ScanResult


class AuditEntry(BaseModel):
    """Structured audit log entry for a single MCP tool call.

    Attributes
    ----------
    timestamp:
        ISO 8601 timestamp of the event.
    request_id:
        Unique identifier for this request (UUID).
    tool_name:
        Name of the tool being called.
    server_name:
        Name of the upstream MCP server.
    action:
        Final decision: "pass", "warn", or "block".
    scanner_results:
        Summary of each scanner's evaluation.
    request_args_preview:
        Redacted preview of request arguments (first 200 chars).
    response_preview:
        First 200 characters of the tool response, if available.
    latency_ms:
        Wall-clock time for the entire proxy pipeline in milliseconds.
    policy_name:
        Name of the active policy configuration.
    event_type:
        Type of audit event: "tool_call", "tool_list", "error".
    """

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = ""
    server_name: str = ""
    action: str = "pass"
    scanner_results: list[dict[str, str | float | bool]] = Field(default_factory=list)
    request_args_preview: str = ""
    response_preview: str = ""
    latency_ms: float = 0.0
    policy_name: str = "default"
    event_type: str = "tool_call"

    model_config = {"arbitrary_types_allowed": False}


class AuditLogger:
    """Async-safe audit logger with configurable storage backend.

    Parameters
    ----------
    storage:
        Backend for persisting audit entries.
    policy_name:
        Name of the active policy (included in every entry).
    redact_args:
        If True, truncate request arguments to 200 chars.
    """

    def __init__(
        self,
        storage: AuditStorage,
        policy_name: str = "default",
        redact_args: bool = True,
    ) -> None:
        self._storage = storage
        self._policy_name = policy_name
        self._redact_args = redact_args
        self._lock = asyncio.Lock()

    def _truncate(self, text: str, max_length: int = 200) -> str:
        """Truncate text to max_length, appending '...' if truncated."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."

    def _make_scanner_summary(
        self, result: ScanResult
    ) -> dict[str, str | float | bool]:
        """Create a summary dict from a ScanResult."""
        summary: dict[str, str | float | bool] = {
            "scanner": result.scanner_name or "unknown",
            "action": result.action.value,
            "confidence": result.confidence,
        }
        if result.reason:
            summary["reason"] = result.reason
        return summary

    def _build_entry(
        self,
        tool_name: str,
        server_name: str,
        action: str,
        chain_result: ChainResult | None = None,
        request_args: str = "",
        response_text: str = "",
        latency_ms: float = 0.0,
        event_type: str = "tool_call",
    ) -> AuditEntry:
        """Build an AuditEntry from the given parameters."""
        scanner_results: list[dict[str, str | float | bool]] = []
        if chain_result is not None:
            for sr in chain_result.all_results:
                scanner_results.append(self._make_scanner_summary(sr))

        return AuditEntry(
            tool_name=tool_name,
            server_name=server_name,
            action=action,
            scanner_results=scanner_results,
            request_args_preview=(
                self._truncate(request_args) if self._redact_args else request_args
            ),
            response_preview=self._truncate(response_text),
            latency_ms=latency_ms,
            policy_name=self._policy_name,
            event_type=event_type,
        )

    async def _write(self, entry: AuditEntry) -> None:
        """Thread-safe write to storage."""
        async with self._lock:
            await self._storage.write(entry)

    async def log_passed(
        self,
        tool_name: str,
        server_name: str,
        chain_result: ChainResult,
        request_args: str = "",
        response_text: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        """Log a tool call that passed all scanners."""
        entry = self._build_entry(
            tool_name=tool_name,
            server_name=server_name,
            action="pass",
            chain_result=chain_result,
            request_args=request_args,
            response_text=response_text,
            latency_ms=latency_ms,
        )
        await self._write(entry)

    async def log_blocked(
        self,
        tool_name: str,
        server_name: str,
        chain_result: ChainResult,
        request_args: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        """Log a tool call that was blocked by a scanner."""
        entry = self._build_entry(
            tool_name=tool_name,
            server_name=server_name,
            action="block",
            chain_result=chain_result,
            request_args=request_args,
            latency_ms=latency_ms,
        )
        await self._write(entry)

    async def log_warned(
        self,
        tool_name: str,
        server_name: str,
        chain_result: ChainResult,
        request_args: str = "",
        response_text: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        """Log a tool call that triggered warnings but was allowed."""
        entry = self._build_entry(
            tool_name=tool_name,
            server_name=server_name,
            action="warn",
            chain_result=chain_result,
            request_args=request_args,
            response_text=response_text,
            latency_ms=latency_ms,
        )
        await self._write(entry)

    async def log_error(
        self,
        tool_name: str,
        server_name: str,
        error: str,
        latency_ms: float = 0.0,
    ) -> None:
        """Log an error during tool call processing."""
        entry = self._build_entry(
            tool_name=tool_name,
            server_name=server_name,
            action="error",
            response_text=error,
            latency_ms=latency_ms,
            event_type="error",
        )
        await self._write(entry)
