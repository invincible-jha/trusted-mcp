"""Security interceptors for trusted-mcp.

Interceptors are Scanner subclasses that integrate domain-specific
security features into the interceptor chain. Each interceptor
follows the Scanner ABC and is composable with any other scanner.

Available Interceptors
----------------------
DriftInterceptor
    Detects tool description drift after approval and blocks
    calls from tools whose descriptions have changed.

SanitizeInterceptor
    Runs argument sanitizers on all string arguments before a
    tool call is forwarded to the upstream MCP server.
"""
from __future__ import annotations

from trusted_mcp.interceptors.drift_interceptor import DriftInterceptor
from trusted_mcp.interceptors.sanitize_interceptor import SanitizeInterceptor

__all__ = [
    "DriftInterceptor",
    "SanitizeInterceptor",
]
