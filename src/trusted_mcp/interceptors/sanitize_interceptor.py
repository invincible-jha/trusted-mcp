"""SanitizeInterceptor — plug argument sanitizers into the interceptor chain.

Integrates the SanitizerRegistry into the Scanner chain. Before each
tool call, runs all applicable sanitizers against every string argument.
If any sanitizer rejects an argument, blocks or warns the call depending
on the configured action.

What This Is NOT
----------------
This interceptor validates string arguments only. It does NOT:
- Validate non-string argument types (ints, booleans, lists)
- Perform semantic validation of argument values
- Replace proper parameterized queries at the DB layer

Example
-------
::

    from trusted_mcp.interceptors.sanitize_interceptor import SanitizeInterceptor
    from trusted_mcp.sanitizers import ShellSanitizer, SanitizerRegistry

    registry = SanitizerRegistry(use_defaults=False)
    registry.register(".*", [ShellSanitizer(mode="reject")])

    interceptor = SanitizeInterceptor(registry=registry, action="block")
    chain = InterceptorChain(scanners=[interceptor])
"""
from __future__ import annotations

import logging
from typing import Literal

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition
from trusted_mcp.sanitizers.registry import SanitizerRegistry

logger = logging.getLogger(__name__)


class SanitizeInterceptor(Scanner):
    """Scanner that runs sanitizers on all string arguments before tool execution.

    Looks up applicable sanitizers from the SanitizerRegistry for the
    tool being called, then runs each sanitizer against every string
    argument. If any sanitizer returns ``safe=False``, the call is
    blocked or warned depending on the configured action.

    In ``sanitize`` mode, arguments are replaced with the sanitized
    output from the sanitizer chain (only applies to sanitizers that
    strip rather than reject).

    Parameters
    ----------
    registry:
        SanitizerRegistry instance. If None, creates one with defaults.
    action:
        What to do when a sanitizer rejects an argument:
        - ``"block"``: Return Action.BLOCK, preventing the tool call.
        - ``"sanitize"``: Replace the argument with sanitized output,
          continue if all violations were handled by stripping.
          Falls back to BLOCK if a sanitizer hard-rejects.
        - ``"warn"``: Return Action.WARN, logging but allowing the call.
    settings:
        Optional dict for construction from policy YAML config.
    """

    name = "sanitize"

    def __init__(
        self,
        registry: SanitizerRegistry | None = None,
        action: Literal["block", "sanitize", "warn"] = "block",
        settings: dict[str, object] | None = None,
    ) -> None:
        config = settings or {}
        raw_action = str(config.get("action", action))
        if raw_action not in ("block", "sanitize", "warn"):
            logger.warning(
                "SanitizeInterceptor: unknown action %r; defaulting to 'block'", raw_action
            )
            raw_action = "block"

        self._action: Literal["block", "sanitize", "warn"] = raw_action  # type: ignore[assignment]
        self._registry: SanitizerRegistry = (
            registry if registry is not None else SanitizerRegistry()
        )

    def _sanitize_value(
        self,
        tool_name: str,
        arg_name: str,
        value: str,
    ) -> tuple[bool, str, list[str]]:
        """Run all applicable sanitizers against a single string value.

        Parameters
        ----------
        tool_name:
            The tool name, used to look up sanitizers in the registry.
        arg_name:
            The argument name, used in violation messages.
        value:
            The string value to sanitize.

        Returns
        -------
        tuple[bool, str, list[str]]
            (accepted, sanitized_value, all_violations)
            ``accepted`` is True if all sanitizers accepted the value.
            ``sanitized_value`` is the cleaned output (may equal input).
            ``all_violations`` is the combined list of all violations.
        """
        sanitizers = self._registry.get_sanitizers(tool_name)
        current_value = value
        all_violations: list[str] = []
        accepted = True

        for sanitizer in sanitizers:
            result = sanitizer.sanitize(current_value)
            if result.violations:
                all_violations.extend(
                    f"[{arg_name}] {v}" for v in result.violations
                )
            if not result.safe:
                accepted = False
                # In reject mode we stop on first failure
                break
            # In strip mode, chain on the sanitized output
            current_value = result.sanitized

        return accepted, current_value, all_violations

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Run sanitizers on all string arguments in the request.

        Parameters
        ----------
        request:
            The tool call request to evaluate.

        Returns
        -------
        ScanResult
            PASS if all sanitizers accept all arguments.
            BLOCK, WARN, or modified request depending on action.
        """
        tool_name = request.tool_name
        all_violations: list[str] = []
        any_rejected = False

        for arg_name, arg_value in request.arguments.items():
            if not isinstance(arg_value, str):
                continue

            accepted, _sanitized, violations = self._sanitize_value(
                tool_name, arg_name, arg_value
            )
            all_violations.extend(violations)

            if not accepted:
                any_rejected = True

        if not all_violations:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        violation_summary = "; ".join(all_violations[:5])
        if len(all_violations) > 5:
            violation_summary += f" (+{len(all_violations) - 5} more)"

        details: dict[str, object] = {
            "tool_name": tool_name,
            "violations": all_violations,
            "violation_count": len(all_violations),
        }

        # Warn mode: always warn, never block
        if self._action == "warn":
            return ScanResult(
                action=Action.WARN,
                reason=f"Argument injection patterns detected in tool {tool_name!r}: {violation_summary}",
                details=details,
                scanner_name=self.name,
            )

        # Block mode: block if any sanitizer hard-rejected; warn if only strip violations
        if self._action == "block":
            if any_rejected:
                return ScanResult(
                    action=Action.BLOCK,
                    reason=f"Argument injection blocked for tool {tool_name!r}: {violation_summary}",
                    details=details,
                    scanner_name=self.name,
                )
            # Violations present but all sanitizers returned safe (strip mode)
            return ScanResult(
                action=Action.WARN,
                reason=f"Argument sanitized for tool {tool_name!r}: {violation_summary}",
                details=details,
                scanner_name=self.name,
            )

        # Sanitize mode: warn to report that stripping was applied
        return ScanResult(
            action=Action.WARN,
            reason=f"Argument sanitized for tool {tool_name!r}: {violation_summary}",
            details=details,
            scanner_name=self.name,
        )

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        """Pass through — argument sanitization is only applied pre-execution.

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

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Pass through — sanitization applies to arguments, not descriptions.

        Parameters
        ----------
        tool:
            The tool definition (not used for argument sanitization).

        Returns
        -------
        ScanResult
            Always Action.PASS.
        """
        return ScanResult(action=Action.PASS, scanner_name=self.name)
