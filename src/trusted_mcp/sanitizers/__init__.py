"""Argument injection sanitizers for trusted-mcp.

Provides composable sanitizer classes that validate and optionally
clean tool call arguments before they reach the upstream MCP server.

What These Sanitizers Are NOT
------------------------------
These are defensive pattern-based sanitizers. They are NOT:
- Parameterized query builders (parameterization is the tool's responsibility)
- ML-based payload classifiers (available via plugins)
- Formal language parsers for shell, SQL, or URLs
- Complete injection prevention for all possible attack vectors

Always combine with parameterized queries at the tool layer for SQL,
proper subprocess argument handling for shell, and allowlist-based
path validation for filesystem tools.

Available Sanitizers
---------------------
ShellSanitizer
    Blocks or strips shell metacharacters to prevent command injection.

PathSanitizer
    Blocks path traversal sequences and absolute paths outside an allowlist.

SQLSanitizer
    Detects SQL injection patterns (reject-only; does not modify input).

URLSanitizer
    Restricts URL schemes to http/https and validates URL structure.

SanitizerRegistry
    Maps tool name patterns to sanitizer chains via regex matching.

Example
-------
::

    from trusted_mcp.sanitizers import ShellSanitizer, SanitizerRegistry

    registry = SanitizerRegistry()
    registry.register(".*", [ShellSanitizer()])

    sanitizers = registry.get_sanitizers("my_tool")
    for sanitizer in sanitizers:
        result = sanitizer.sanitize(user_input)
        if not result.safe:
            raise ValueError(f"Injection detected: {result.violations}")
"""
from __future__ import annotations

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult
from trusted_mcp.sanitizers.shell_sanitizer import ShellSanitizer
from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer
from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer
from trusted_mcp.sanitizers.url_sanitizer import URLSanitizer
from trusted_mcp.sanitizers.registry import SanitizerRegistry

__all__ = [
    "Sanitizer",
    "SanitizeResult",
    "ShellSanitizer",
    "PathSanitizer",
    "SQLSanitizer",
    "URLSanitizer",
    "SanitizerRegistry",
]
