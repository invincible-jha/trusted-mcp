"""Interceptor chain — ordered pipeline of security scanners.

The InterceptorChain is the core execution engine of trusted-mcp. It
holds an ordered list of Scanner instances and applies each one to
every tool call request, response, or tool definition.

Chain Semantics
---------------
- Scanners execute in registration order.
- If any scanner returns BLOCK, the chain short-circuits immediately
  and returns that BLOCK result without running remaining scanners.
- If any scanner returns WARN, the warning is accumulated and the
  chain continues to the next scanner.
- If all scanners return PASS, the chain returns a PASS ChainResult
  with all accumulated warnings attached.

Example
-------
::

    from trusted_mcp.core.interceptor import InterceptorChain
    from trusted_mcp.core.policy import ScannerConfig

    configs = [
        ScannerConfig(name="regex", enabled=True),
        ScannerConfig(name="allowlist", enabled=True,
                      settings={"mode": "blocklist"}),
    ]
    chain = InterceptorChain(configs)

    result = await chain.scan_request(request)
    if result.is_blocked:
        print(f"Blocked by {result.blocking_scanner}: {result.blocking_reason}")
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from trusted_mcp.core.policy import ScannerConfig
from trusted_mcp.core.result import Action, ChainResult, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class InterceptorChain:
    """Ordered chain of security scanners applied to every MCP interaction.

    Scanners are loaded from ScannerConfig objects at construction time.
    Only enabled scanners are included in the chain.

    Parameters
    ----------
    scanner_configs:
        Ordered list of scanner configurations from the policy.
    scanners:
        Optional list of pre-instantiated Scanner objects. If provided,
        scanner_configs is ignored. Useful for testing.

    Raises
    ------
    ScannerNotFoundError
        If a scanner name in scanner_configs is not registered.
    """

    def __init__(
        self,
        scanner_configs: list[ScannerConfig] | None = None,
        scanners: list[Scanner] | None = None,
    ) -> None:
        if scanners is not None:
            self._scanners: list[Scanner] = scanners
        else:
            self._scanners = self._load_scanners(scanner_configs or [])

    def _load_scanners(self, configs: list[ScannerConfig]) -> list[Scanner]:
        """Instantiate scanner objects from configuration.

        Only enabled scanner configs are instantiated.

        Parameters
        ----------
        configs:
            Scanner configs from the policy file.

        Returns
        -------
        list[Scanner]
            Instantiated scanner objects in config order.
        """
        # Import here to avoid circular imports at module load time
        from trusted_mcp.plugins.registry import scanner_registry

        loaded: list[Scanner] = []
        for config in configs:
            if not config.enabled:
                logger.debug("Scanner %r is disabled; skipping", config.name)
                continue
            scanner_class = scanner_registry.get(config.name)
            instance = scanner_class(config.settings)  # type: ignore[call-arg]
            loaded.append(instance)
            logger.debug("Loaded scanner %r", config.name)
        return loaded

    @property
    def scanners(self) -> list[Scanner]:
        """The ordered list of active scanner instances."""
        return list(self._scanners)

    def add_scanner(self, scanner: Scanner) -> None:
        """Append a scanner to the end of the chain at runtime.

        Parameters
        ----------
        scanner:
            The scanner instance to add.
        """
        self._scanners.append(scanner)

    async def scan_request(self, request: ToolCallRequest) -> ChainResult:
        """Run all scanners against a tool call request.

        Parameters
        ----------
        request:
            The outgoing tool call request to evaluate.

        Returns
        -------
        ChainResult
            Aggregate result with action, blocking info (if blocked),
            and all accumulated warnings.
        """
        warnings: list[ScanResult] = []
        all_results: list[ScanResult] = []

        for scanner in self._scanners:
            try:
                result = await scanner.scan_request(request)
            except Exception as exc:
                logger.exception(
                    "Scanner %r raised an unexpected error during scan_request: %s",
                    scanner.name,
                    exc,
                )
                # Treat scanner errors as warnings to avoid silent security bypasses
                error_result = ScanResult(
                    action=Action.WARN,
                    reason=f"Scanner {scanner.name!r} encountered an internal error: {exc}",
                    scanner_name=scanner.name,
                )
                warnings.append(error_result)
                all_results.append(error_result)
                continue

            if result.scanner_name is None:
                result = ScanResult(
                    action=result.action,
                    reason=result.reason,
                    details=result.details,
                    scanner_name=scanner.name,
                    confidence=result.confidence,
                )
            all_results.append(result)

            if result.action == Action.BLOCK:
                logger.warning(
                    "Request BLOCKED by scanner %r: %s (tool=%s, server=%s)",
                    scanner.name,
                    result.reason,
                    request.tool_name,
                    request.server_name,
                )
                return ChainResult(
                    action=Action.BLOCK,
                    blocking_scanner=scanner.name,
                    blocking_reason=result.reason,
                    blocking_details=result.details,
                    warnings=warnings,
                    all_results=all_results,
                )

            if result.action == Action.WARN:
                logger.warning(
                    "Request WARNED by scanner %r: %s (tool=%s, server=%s)",
                    scanner.name,
                    result.reason,
                    request.tool_name,
                    request.server_name,
                )
                warnings.append(result)

        final_action = Action.WARN if warnings else Action.PASS
        return ChainResult(
            action=final_action,
            warnings=warnings,
            all_results=all_results,
        )

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ChainResult:
        """Run all scanners against a tool call response.

        Parameters
        ----------
        request:
            The original tool call request.
        response:
            The response returned by the upstream MCP server.

        Returns
        -------
        ChainResult
            Aggregate result with action, blocking info (if blocked),
            and all accumulated warnings.
        """
        warnings: list[ScanResult] = []
        all_results: list[ScanResult] = []

        for scanner in self._scanners:
            try:
                result = await scanner.scan_response(request, response)
            except Exception as exc:
                logger.exception(
                    "Scanner %r raised an unexpected error during scan_response: %s",
                    scanner.name,
                    exc,
                )
                error_result = ScanResult(
                    action=Action.WARN,
                    reason=f"Scanner {scanner.name!r} encountered an internal error: {exc}",
                    scanner_name=scanner.name,
                )
                warnings.append(error_result)
                all_results.append(error_result)
                continue

            if result.scanner_name is None:
                result = ScanResult(
                    action=result.action,
                    reason=result.reason,
                    details=result.details,
                    scanner_name=scanner.name,
                    confidence=result.confidence,
                )
            all_results.append(result)

            if result.action == Action.BLOCK:
                logger.warning(
                    "Response BLOCKED by scanner %r: %s (tool=%s, server=%s)",
                    scanner.name,
                    result.reason,
                    request.tool_name,
                    request.server_name,
                )
                return ChainResult(
                    action=Action.BLOCK,
                    blocking_scanner=scanner.name,
                    blocking_reason=result.reason,
                    blocking_details=result.details,
                    warnings=warnings,
                    all_results=all_results,
                )

            if result.action == Action.WARN:
                logger.warning(
                    "Response WARNED by scanner %r: %s (tool=%s, server=%s)",
                    scanner.name,
                    result.reason,
                    request.tool_name,
                    request.server_name,
                )
                warnings.append(result)

        final_action = Action.WARN if warnings else Action.PASS
        return ChainResult(
            action=final_action,
            warnings=warnings,
            all_results=all_results,
        )

    async def scan_tool_descriptions(
        self, tools: list[ToolDefinition]
    ) -> dict[str, ChainResult]:
        """Run all scanners against a list of tool definitions.

        Parameters
        ----------
        tools:
            The tool definitions fetched from an upstream MCP server.

        Returns
        -------
        dict[str, ChainResult]
            Mapping of ``"server_name:tool_name"`` to ChainResult for
            each tool that had at least one non-PASS result.
            Tools where all scanners returned PASS are not included.
        """
        flagged: dict[str, ChainResult] = {}

        for tool in tools:
            warnings: list[ScanResult] = []
            all_results: list[ScanResult] = []
            blocked = False
            block_result: ScanResult | None = None

            for scanner in self._scanners:
                try:
                    result = await scanner.scan_tool_description(tool)
                except Exception as exc:
                    logger.exception(
                        "Scanner %r error in scan_tool_description for tool %r: %s",
                        scanner.name,
                        tool.name,
                        exc,
                    )
                    error_result = ScanResult(
                        action=Action.WARN,
                        reason=f"Scanner {scanner.name!r} error: {exc}",
                        scanner_name=scanner.name,
                    )
                    warnings.append(error_result)
                    all_results.append(error_result)
                    continue

                if result.scanner_name is None:
                    result = ScanResult(
                        action=result.action,
                        reason=result.reason,
                        details=result.details,
                        scanner_name=scanner.name,
                        confidence=result.confidence,
                    )
                all_results.append(result)

                if result.action == Action.BLOCK:
                    blocked = True
                    block_result = result
                    break
                if result.action == Action.WARN:
                    warnings.append(result)

            tool_key = f"{tool.server_name}:{tool.name}"
            if blocked and block_result is not None:
                flagged[tool_key] = ChainResult(
                    action=Action.BLOCK,
                    blocking_scanner=block_result.scanner_name,
                    blocking_reason=block_result.reason,
                    blocking_details=block_result.details,
                    warnings=warnings,
                    all_results=all_results,
                )
            elif warnings:
                flagged[tool_key] = ChainResult(
                    action=Action.WARN,
                    warnings=warnings,
                    all_results=all_results,
                )

        return flagged
