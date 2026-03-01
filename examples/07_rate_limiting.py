#!/usr/bin/env python3
"""Example: Rate Limiting

Demonstrates how to use the trusted-mcp reputation registry and
audit logger together to implement per-server rate limiting logic.

Usage:
    python examples/07_rate_limiting.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import time
from collections import defaultdict

import trusted_mcp
from trusted_mcp import (
    AuditLogger,
    StdoutStorage,
    AuditFormatter,
    TrustedProxy,
)


class SimpleRateLimiter:
    """Token-bucket rate limiter for MCP tool calls."""

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self._max_calls = max_calls
        self._window = window_seconds
        self._call_times: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, server_id: str) -> bool:
        now = time.monotonic()
        window_start = now - self._window
        self._call_times[server_id] = [
            t for t in self._call_times[server_id] if t > window_start
        ]
        if len(self._call_times[server_id]) >= self._max_calls:
            return False
        self._call_times[server_id].append(now)
        return True

    def remaining(self, server_id: str) -> int:
        now = time.monotonic()
        window_start = now - self._window
        active = [t for t in self._call_times[server_id] if t > window_start]
        return max(0, self._max_calls - len(active))


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Set up rate limiter (5 calls per 10-second window)
    rate_limiter = SimpleRateLimiter(max_calls=5, window_seconds=10.0)

    # Step 2: Set up trusted-mcp audit logger
    storage = StdoutStorage()
    formatter = AuditFormatter()
    audit_logger = AuditLogger(storage=storage, formatter=formatter)
    proxy = TrustedProxy()

    server_id = "analytics-mcp"
    tool_calls = [
        {"tool": "query_db", "arguments": {"sql": "SELECT count(*) FROM events"}},
        {"tool": "export_csv", "arguments": {"table": "events", "limit": 1000}},
        {"tool": "query_db", "arguments": {"sql": "SELECT * FROM users LIMIT 10"}},
        {"tool": "send_report", "arguments": {"recipient": "analyst@example.com"}},
        {"tool": "query_db", "arguments": {"sql": "SELECT avg(cost) FROM billing"}},
        {"tool": "query_db", "arguments": {"sql": "SELECT * FROM logs LIMIT 100"}},  # should be rate-limited
    ]

    print(f"\nProcessing {len(tool_calls)} tool calls (limit: {rate_limiter._max_calls} per window):")
    allowed_count = 0
    blocked_count = 0

    for call in tool_calls:
        tool_name = str(call["tool"])
        if not rate_limiter.is_allowed(server_id):
            blocked_count += 1
            print(f"  [{tool_name}] RATE LIMITED — remaining capacity: {rate_limiter.remaining(server_id)}")
            continue

        try:
            scan_result = proxy.scan({**call, "source_server": server_id})
            audit_logger.log_tool_call(
                tool_name=tool_name,
                arguments=call["arguments"],
                server=server_id,
            )
            allowed_count += 1
            print(f"  [{tool_name}] ALLOWED — remaining: {rate_limiter.remaining(server_id)}")
        except Exception as error:
            print(f"  [{tool_name}] ERROR: {error}")

    print(f"\nSummary: {allowed_count} allowed, {blocked_count} rate-limited")
    print(f"Audit entries logged: {audit_logger.count()}")


if __name__ == "__main__":
    main()
