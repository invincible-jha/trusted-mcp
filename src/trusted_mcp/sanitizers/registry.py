"""Sanitizer registry — maps tool name patterns to sanitizer chains.

Allows operators to configure which sanitizers apply to which tools
using regex patterns. Tools are matched against registered patterns
in registration order; all matching sanitizer lists are combined.

What This Is NOT
----------------
This is a simple regex-based dispatch table. It is NOT:
- A dynamic policy engine that adapts at runtime (available via plugins)
- A priority-based routing system with conflict resolution
- A hierarchical policy with inheritance

Example
-------
::

    from trusted_mcp.sanitizers.registry import SanitizerRegistry
    from trusted_mcp.sanitizers import ShellSanitizer, PathSanitizer

    registry = SanitizerRegistry()

    # Apply shell sanitizer to all tools
    registry.register(".*", [ShellSanitizer()])

    # Apply path sanitizer to tools with "file" in the name
    registry.register(".*file.*", [PathSanitizer()])

    # Get all sanitizers for a specific tool
    sanitizers = registry.get_sanitizers("read_file")
    # Returns [ShellSanitizer(), PathSanitizer()]
"""
from __future__ import annotations

import logging
import re

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult
from trusted_mcp.sanitizers.shell_sanitizer import ShellSanitizer
from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer
from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer

logger = logging.getLogger(__name__)

# Default tool name pattern groups and their associated sanitizers.
# These are applied unless the registry is initialised with
# ``use_defaults=False``.
_FILE_TOOL_PATTERN = re.compile(
    r".*(?:file|path|read|write|open|load|save|dir|folder|upload|download).*",
    re.IGNORECASE,
)
_DB_TOOL_PATTERN = re.compile(
    r".*(?:sql|query|database|db|table|record|row|select|insert|update|delete).*",
    re.IGNORECASE,
)


class SanitizerRegistry:
    """Maps tool name patterns to ordered chains of Sanitizer instances.

    Registration is order-sensitive: patterns are evaluated in the
    order they were registered. All matching patterns contribute
    their sanitizer lists to the final chain for a given tool name.

    Parameters
    ----------
    use_defaults:
        If True, pre-register sensible default sanitizers:
        - Shell sanitizer for all tools (``".*"`` pattern)
        - Path sanitizer for file-related tools
        - SQL sanitizer for database-related tools
        Defaults to True.
    """

    def __init__(self, use_defaults: bool = True) -> None:
        # List of (compiled_pattern, sanitizers) in registration order
        self._rules: list[tuple[re.Pattern[str], list[Sanitizer]]] = []

        if use_defaults:
            self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default sanitizer mappings.

        Applies shell sanitizer to all tools, path sanitizer to
        file-related tools, and SQL sanitizer to database tools.
        """
        # Shell sanitizer applies to all tools
        self.register(".*", [ShellSanitizer()])
        # Path sanitizer for file/path tools
        self.register(
            r".*(?:file|path|read|write|open|load|save|dir|folder|upload|download).*",
            [PathSanitizer()],
        )
        # SQL sanitizer for database tools
        self.register(
            r".*(?:sql|query|database|db|table|record|row|select|insert|update|delete).*",
            [SQLSanitizer()],
        )

    def register(self, tool_pattern: str, sanitizers: list[Sanitizer]) -> None:
        """Register a list of sanitizers for tools matching a regex pattern.

        Parameters
        ----------
        tool_pattern:
            A regex pattern string matched against tool names. The
            pattern is compiled with ``re.IGNORECASE``.
        sanitizers:
            Ordered list of Sanitizer instances to apply when the
            pattern matches.

        Raises
        ------
        re.error
            If the pattern is not a valid regular expression.
        ValueError
            If the sanitizers list is empty.
        """
        if not sanitizers:
            raise ValueError(
                f"Cannot register empty sanitizer list for pattern {tool_pattern!r}"
            )
        compiled = re.compile(tool_pattern, re.IGNORECASE)
        self._rules.append((compiled, list(sanitizers)))
        logger.debug(
            "Registered %d sanitizer(s) for tool pattern %r",
            len(sanitizers),
            tool_pattern,
        )

    def get_sanitizers(self, tool_name: str) -> list[Sanitizer]:
        """Return all sanitizers applicable to a tool name.

        Evaluates all registered patterns against the tool name and
        collects sanitizers from every matching rule, in registration
        order. Duplicate sanitizer instances are NOT deduplicated.

        Parameters
        ----------
        tool_name:
            The name of the tool to look up sanitizers for.

        Returns
        -------
        list[Sanitizer]
            Ordered list of sanitizers to apply. Empty if no patterns match.
        """
        result: list[Sanitizer] = []
        for pattern, sanitizers in self._rules:
            if pattern.match(tool_name):
                result.extend(sanitizers)
        return result

    def clear(self) -> None:
        """Remove all registered rules from the registry."""
        self._rules.clear()
        logger.debug("Cleared all sanitizer registry rules")

    def rule_count(self) -> int:
        """Return the number of registered rules.

        Returns
        -------
        int
            Number of pattern rules currently registered.
        """
        return len(self._rules)
