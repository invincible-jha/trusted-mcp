#!/usr/bin/env python3
"""Example: Tool Validation

Demonstrates how to validate MCP tool descriptions and arguments
using the trusted-mcp scanner and audit logger.

Usage:
    python examples/02_tool_validation.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import trusted_mcp
from trusted_mcp import (
    AuditLogger,
    StdoutStorage,
    AuditFormatter,
)


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Set up audit logging with stdout sink
    storage = StdoutStorage()
    formatter = AuditFormatter()
    audit_logger = AuditLogger(storage=storage, formatter=formatter)
    print("Audit logger initialised with stdout storage.")

    # Step 2: Define tool calls to validate
    tool_calls: list[dict[str, object]] = [
        {
            "tool": "read_file",
            "arguments": {"path": "/home/user/document.txt"},
            "server": "filesystem-mcp",
        },
        {
            "tool": "execute_shell",
            "arguments": {"command": "ls -la"},
            "server": "shell-mcp",
        },
        {
            "tool": "web_fetch",
            "arguments": {"url": "https://example.com"},
            "server": "web-mcp",
        },
    ]

    # Step 3: Log and validate each tool call
    print("\nValidating tool calls:")
    for call in tool_calls:
        tool_name = str(call["tool"])
        try:
            entry = audit_logger.log_tool_call(
                tool_name=tool_name,
                arguments=call["arguments"],
                server=str(call["server"]),
            )
            print(f"  [{tool_name}] logged with entry_id={entry.entry_id[:8]}...")
        except Exception as error:
            print(f"  [{tool_name}] validation error: {error}")

    print(f"\nTotal entries logged: {audit_logger.count()}")


if __name__ == "__main__":
    main()
