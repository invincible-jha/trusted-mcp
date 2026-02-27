"""DriftInterceptor — plug drift detection into the interceptor chain.

Integrates the DriftDetector into the Scanner chain. Before each tool
call, checks whether the tool's current description matches the approved
hash. If drift is detected, blocks or warns depending on configuration.

What This Is NOT
----------------
This interceptor only checks whether the tool DESCRIPTION has changed.
It does NOT:
- Verify behavioral drift during execution (available via plugins)
- Correlate drift across multiple sessions (available via plugins)
- Detect drift in tool input_schema changes (available via plugins)

Example
-------
::

    from trusted_mcp.interceptors.drift_interceptor import DriftInterceptor
    from trusted_mcp.drift import DriftDetector

    detector = DriftDetector()
    detector.approve("srv:my_tool", "Reads a file safely.")

    interceptor = DriftInterceptor(detector=detector, action="block")
    chain = InterceptorChain(scanners=[interceptor])
"""
from __future__ import annotations

import logging
from typing import Literal

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition
from trusted_mcp.drift.detector import DriftDetector

logger = logging.getLogger(__name__)


class DriftInterceptor(Scanner):
    """Scanner that blocks or warns when tool descriptions drift from approved state.

    Integrates DriftDetector into the interceptor chain. Call
    ``detector.approve(tool_key, description)`` before adding this
    interceptor to the chain. The interceptor checks drift in
    ``scan_tool_description`` before tool calls reach the LLM.

    For ``scan_request``, drift detection relies on the description
    having been passed in via ``scan_tool_description`` first (which
    is how the proxy workflow operates). Standalone request scanning
    without prior description scanning will pass through.

    Parameters
    ----------
    detector:
        DriftDetector instance. If None, creates one with default settings.
    action:
        What to do when drift is detected:
        - ``"block"``: Return Action.BLOCK, preventing the tool call.
        - ``"warn"``: Return Action.WARN, logging but allowing the call.
        - ``"log"``: Return Action.PASS, silently logging the drift.
    warn_unapproved:
        If True, emit Action.WARN for tools with no approved hash.
        If False, tools without an approved hash pass through silently.
        Defaults to False.
    """

    name = "drift"

    def __init__(
        self,
        detector: DriftDetector | None = None,
        action: Literal["block", "warn", "log"] = "block",
        warn_unapproved: bool = False,
        settings: dict[str, object] | None = None,
    ) -> None:
        config = settings or {}
        raw_action = str(config.get("action", action))
        if raw_action not in ("block", "warn", "log"):
            logger.warning(
                "DriftInterceptor: unknown action %r; defaulting to 'block'", raw_action
            )
            raw_action = "block"

        self._action: Literal["block", "warn", "log"] = raw_action  # type: ignore[assignment]
        self._warn_unapproved: bool = bool(config.get("warn_unapproved", warn_unapproved))
        self._detector: DriftDetector = detector if detector is not None else DriftDetector()

    def _action_to_result(
        self, tool_key: str, reason: str, details: dict[str, object]
    ) -> ScanResult:
        """Convert the configured action into a ScanResult.

        Parameters
        ----------
        tool_key:
            The tool identifier for the result details.
        reason:
            Human-readable reason for the action.
        details:
            Structured details for the audit log.

        Returns
        -------
        ScanResult
            BLOCK, WARN, or PASS depending on configured action.
        """
        if self._action == "block":
            return ScanResult(
                action=Action.BLOCK,
                reason=reason,
                details=details,
                scanner_name=self.name,
            )
        if self._action == "warn":
            return ScanResult(
                action=Action.WARN,
                reason=reason,
                details=details,
                scanner_name=self.name,
            )
        # "log" — silently pass through
        logger.warning("Drift detected (log-only mode) for %r: %s", tool_key, reason)
        return ScanResult(action=Action.PASS, scanner_name=self.name, details=details)

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Pass through — drift is detected at tool description time.

        This implementation always returns PASS because drift detection
        requires the tool description, which is only available via
        ``scan_tool_description``. The proxy workflow calls
        ``scan_tool_descriptions`` before executing any tool call.

        Parameters
        ----------
        request:
            The tool call request (not used for drift detection).

        Returns
        -------
        ScanResult
            Always Action.PASS.
        """
        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Check tool description against approved hash.

        Computes the drift result for the tool and returns BLOCK, WARN,
        or PASS depending on the configured action and drift state.

        Parameters
        ----------
        tool:
            The tool definition to check for description drift.

        Returns
        -------
        ScanResult
            BLOCK / WARN / PASS based on drift state and configured action.
        """
        tool_key = f"{tool.server_name}:{tool.name}"
        drift_result = self._detector.check(tool_key, tool.description)

        if drift_result.unapproved:
            if self._warn_unapproved:
                return ScanResult(
                    action=Action.WARN,
                    reason=f"Tool {tool_key!r} has no approved description hash",
                    details={"tool_key": tool_key, "status": "unapproved"},
                    scanner_name=self.name,
                )
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        if drift_result.drifted:
            reason = (
                f"Tool description drift detected for {tool_key!r} "
                f"(severity={drift_result.severity})"
            )
            details: dict[str, object] = {
                "tool_key": tool_key,
                "severity": drift_result.severity,
                "status": "drifted",
            }
            if drift_result.diff is not None:
                details["diff"] = drift_result.diff

            return self._action_to_result(tool_key, reason, details)

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        """Pass through — drift is not detected at response time.

        Parameters
        ----------
        request:
            The original tool call request.
        response:
            The response returned by the upstream server.

        Returns
        -------
        ScanResult
            Always Action.PASS.
        """
        return ScanResult(action=Action.PASS, scanner_name=self.name)
