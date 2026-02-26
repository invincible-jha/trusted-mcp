"""BasicAllowlistScanner — static tool allowlist and blocklist enforcement.

Provides static policy enforcement over which tools may be called.
Supports two modes:

- ``blocklist`` (default): All tools are allowed except those explicitly
  listed in the blocklist.
- ``allowlist``: Only tools explicitly listed in the allowlist may be
  called; everything else is blocked.

Wildcard matching uses Python's ``fnmatch`` module, so patterns like
``"github:*"`` or ``"filesystem:read_*"`` are supported.

What This Scanner Is NOT
------------------------
- NOT a dynamic tool reputation system (available via plugins)
- NOT a time-of-day or context-aware policy engine (available via plugins)
- Static configuration only; lists are loaded at startup and do not
  change at runtime.

Example YAML configuration
--------------------------
::

    scanners:
      - name: allowlist
        enabled: true
        settings:
          mode: blocklist
          tools:
            block:
              - "shell:execute_command"
              - "filesystem:delete_file"
              - "filesystem:write_*"

    # Allowlist mode — only these tools are permitted:
      - name: allowlist
        enabled: true
        settings:
          mode: allowlist
          tools:
            allow:
              - "filesystem:read_file"
              - "github:*"
              - "web:search"
"""
from __future__ import annotations

import fnmatch
import logging
from typing import Literal

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition

logger = logging.getLogger(__name__)


class BasicAllowlistScanner(Scanner):
    """Static tool allowlist / blocklist enforcement.

    Evaluates ``server_name:tool_name`` identifiers against configured
    allow and block lists. Wildcard patterns (``*``, ``?``) are supported
    via ``fnmatch``.

    Configuration
    -------------
    settings dict keys:

    ``mode``: "blocklist" | "allowlist" (default "blocklist")
        Operating mode.

    ``tools``: dict
        May contain ``allow`` and/or ``block`` lists of tool ID patterns.
        Each pattern is ``"server_name:tool_name"`` or ``"server_name:*"``.

    What This Scanner Is NOT
    ------------------------
    - NOT a dynamic tool reputation system (available via plugins)
    - NOT context-aware policy — purely static list comparison
    """

    name = "allowlist"

    def __init__(self, settings: dict[str, object] | None = None) -> None:
        config = settings or {}
        raw_mode = config.get("mode", "blocklist")
        self._mode: Literal["allowlist", "blocklist"] = (
            "allowlist" if str(raw_mode) == "allowlist" else "blocklist"
        )

        tools_config = config.get("tools", {})
        if not isinstance(tools_config, dict):
            tools_config = {}

        raw_allow = tools_config.get("allow", [])
        raw_block = tools_config.get("block", [])

        self._allow_patterns: list[str] = (
            [str(p) for p in raw_allow] if isinstance(raw_allow, list) else []
        )
        self._block_patterns: list[str] = (
            [str(p) for p in raw_block] if isinstance(raw_block, list) else []
        )

        logger.debug(
            "AllowlistScanner initialised: mode=%s, allow=%d patterns, block=%d patterns",
            self._mode,
            len(self._allow_patterns),
            len(self._block_patterns),
        )

    def _tool_id(self, server_name: str, tool_name: str) -> str:
        """Build the canonical tool identifier used for pattern matching."""
        return f"{server_name}:{tool_name}"

    def _matches_any(self, tool_id: str, patterns: list[str]) -> bool:
        """Return True if the tool ID matches any of the given patterns.

        Parameters
        ----------
        tool_id:
            Canonical tool identifier (``server:tool``).
        patterns:
            List of fnmatch-compatible patterns.

        Returns
        -------
        bool
            True if at least one pattern matches.
        """
        return any(fnmatch.fnmatch(tool_id, pattern) for pattern in patterns)

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Enforce allowlist / blocklist policy on a tool call request.

        Parameters
        ----------
        request:
            The tool call request to evaluate.

        Returns
        -------
        ScanResult
            BLOCK if the tool is explicitly blocked or (in allowlist mode)
            not in the allow list. PASS otherwise.
        """
        tool_id = self._tool_id(request.server_name, request.tool_name)

        # Explicit blocklist check always runs regardless of mode
        if self._block_patterns and self._matches_any(tool_id, self._block_patterns):
            return ScanResult(
                action=Action.BLOCK,
                reason=f"Tool {tool_id!r} is in the blocklist",
                details={"tool_id": tool_id, "mode": self._mode},
                scanner_name=self.name,
            )

        if self._mode == "allowlist":
            if not self._allow_patterns:
                # Empty allowlist with allowlist mode blocks everything
                return ScanResult(
                    action=Action.BLOCK,
                    reason=(
                        f"Tool {tool_id!r} is not permitted: allowlist is empty "
                        "(no tools are allowed)"
                    ),
                    details={"tool_id": tool_id, "mode": "allowlist"},
                    scanner_name=self.name,
                )
            if not self._matches_any(tool_id, self._allow_patterns):
                return ScanResult(
                    action=Action.BLOCK,
                    reason=f"Tool {tool_id!r} is not in the allowlist",
                    details={
                        "tool_id": tool_id,
                        "mode": "allowlist",
                        "allowed_patterns": self._allow_patterns,
                    },
                    scanner_name=self.name,
                )

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Apply allowlist / blocklist policy to a tool definition.

        Used when processing the tool list from the upstream server to
        filter out blocked tools before they are advertised to the client.

        Parameters
        ----------
        tool:
            The tool definition to evaluate.

        Returns
        -------
        ScanResult
            BLOCK if the tool should be suppressed; PASS otherwise.
        """
        tool_id = self._tool_id(tool.server_name, tool.name)

        if self._block_patterns and self._matches_any(tool_id, self._block_patterns):
            return ScanResult(
                action=Action.BLOCK,
                reason=f"Tool {tool_id!r} is in the blocklist",
                details={"tool_id": tool_id},
                scanner_name=self.name,
            )

        if self._mode == "allowlist" and self._allow_patterns:
            if not self._matches_any(tool_id, self._allow_patterns):
                return ScanResult(
                    action=Action.BLOCK,
                    reason=f"Tool {tool_id!r} is not in the allowlist",
                    details={"tool_id": tool_id},
                    scanner_name=self.name,
                )

        return ScanResult(action=Action.PASS, scanner_name=self.name)
