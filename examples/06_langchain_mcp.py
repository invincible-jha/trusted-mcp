#!/usr/bin/env python3
"""Example: LangChain MCP Integration

Demonstrates wrapping a LangChain tool with the trusted-mcp audit
logger so every tool call is logged and scanned before execution.

Usage:
    python examples/06_langchain_mcp.py

Requirements:
    pip install trusted-mcp langchain
"""
from __future__ import annotations

try:
    from langchain.tools import BaseTool
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

import trusted_mcp
from trusted_mcp import (
    AuditLogger,
    FileStorage,
    AuditFormatter,
    TrustedProxy,
)
import tempfile
import os


def create_audited_tool_wrapper(
    tool_name: str,
    audit_logger: AuditLogger,
    proxy: TrustedProxy,
) -> "object":
    """Create a wrapper that scans and logs tool calls before execution."""

    def wrapped_tool(arguments: dict[str, object]) -> str:
        # Scan with trusted-mcp
        tool_call = {
            "tool": tool_name,
            "arguments": arguments,
            "source_server": "langchain-tool-bridge",
        }
        try:
            scan_result = proxy.scan(tool_call)
            audit_logger.log_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                server="langchain-tool-bridge",
                scan_allowed=scan_result.allowed,
            )
            if not scan_result.allowed:
                return f"[BLOCKED] Tool call denied: {scan_result.risk_level}"
        except Exception as scan_error:
            return f"[ERROR] Scan failed: {scan_error}"

        # Execute stub logic
        return f"[{tool_name}] executed with args: {list(arguments.keys())}"

    return wrapped_tool


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    if not _LANGCHAIN_AVAILABLE:
        print("langchain not installed — demonstrating audit layer only.")
        print("Install with: pip install langchain")

    # Step 1: Set up audit storage (temp file for demo)
    temp_dir = tempfile.mkdtemp(prefix="trusted_mcp_")
    audit_path = os.path.join(temp_dir, "audit.jsonl")
    storage = FileStorage(path=audit_path)
    formatter = AuditFormatter()
    audit_logger = AuditLogger(storage=storage, formatter=formatter)
    proxy = TrustedProxy()

    print(f"\nAudit log: {audit_path}")

    # Step 2: Create audited wrappers for common tools
    tools: list[tuple[str, dict[str, object]]] = [
        ("web_search", {"query": "trusted MCP security", "limit": 5}),
        ("read_file", {"path": "/tmp/report.txt"}),
        ("send_notification", {"message": "Analysis complete", "channel": "slack"}),
    ]

    print("\nExecuting audited tool calls:")
    for tool_name, args in tools:
        wrapper = create_audited_tool_wrapper(tool_name, audit_logger, proxy)
        result = wrapper(args)
        print(f"  [{tool_name}] -> {result}")

    # Step 3: Report audit summary
    print(f"\nAudit entries logged: {audit_logger.count()}")
    entries = audit_logger.recent(limit=3)
    for entry in entries:
        print(f"  {entry.entry_id[:8]}... | tool={entry.tool_name} | ts={entry.timestamp}")


if __name__ == "__main__":
    main()
