"""IDE and client adapters for trusted-mcp proxy.

Generate configuration snippets to route MCP connections through
the trusted-mcp security proxy for various development environments.
"""
from __future__ import annotations

from trusted_mcp.adapters.claude_desktop import ClaudeDesktopAdapter
from trusted_mcp.adapters.cursor import CursorAdapter
from trusted_mcp.adapters.generic import GenericAdapter
from trusted_mcp.adapters.vscode import VSCodeAdapter

__all__ = [
    "ClaudeDesktopAdapter",
    "CursorAdapter",
    "GenericAdapter",
    "VSCodeAdapter",
]
