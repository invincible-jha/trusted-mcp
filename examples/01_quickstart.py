#!/usr/bin/env python3
"""Example: Quickstart

Demonstrates the minimal setup for trusted-mcp using the TrustedProxy
convenience class to scan an MCP tool call.

Usage:
    python examples/01_quickstart.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import trusted_mcp
from trusted_mcp import TrustedProxy


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Create a proxy with default settings
    proxy = TrustedProxy()
    print(f"Proxy created: {proxy}")

    # Step 2: Scan an incoming tool call for safety
    try:
        tool_call = {
            "tool": "web_search",
            "arguments": {"query": "Python best practices"},
            "source_server": "search-mcp-server",
        }
        result = proxy.scan(tool_call)
        print(f"\nTool call scan result:")
        print(f"  Allowed: {result.allowed}")
        print(f"  Risk level: {result.risk_level}")
        if result.findings:
            for finding in result.findings:
                print(f"  Finding: {finding}")
    except Exception as error:
        print(f"Scan error: {error}")

    print("\nQuickstart complete.")


if __name__ == "__main__":
    main()
