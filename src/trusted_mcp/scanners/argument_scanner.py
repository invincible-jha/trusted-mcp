# Copyright 2024 AumOS Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""BasicArgumentScanner — tool argument validation against configured rules.

Validates tool call arguments against per-tool rules that specify
expected types, numeric ranges, string length limits, required fields,
and explicit allowed value sets.

This is a commodity implementation performing static validation only.
It is NOT a semantic argument analyser; deeper analysis is available via plugins.

Example YAML configuration
--------------------------
::

    scanners:
      - name: argument
        enabled: true
        settings:
          strict_types: true
          rules:
            - tool_pattern: "filesystem:write_file"
              param_name: "path"
              param_type: "str"
              max_length: 4096
              required: true
            - tool_pattern: "calculator:*"
              param_name: "value"
              param_type: "float"
              min_val: -1000000
              max_val: 1000000
            - tool_pattern: "web:search"
              param_name: "engine"
              param_type: "str"
              allowed_values:
                - "google"
                - "bing"
                - "duckduckgo"
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Literal

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest

logger = logging.getLogger(__name__)

_VALID_TYPES = frozenset({"str", "int", "float", "bool", "list", "dict", "null"})

_PYTHON_TYPE_MAP: dict[str, type] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list": list,
    "dict": dict,
}


@dataclass
class ArgumentRule:
    """Validation rule for a single parameter of a specific tool.

    Attributes
    ----------
    tool_pattern:
        fnmatch-compatible pattern for ``server_name:tool_name``.
        Use ``"*:*"`` to apply to all tools.
    param_name:
        The argument key this rule applies to.
    param_type:
        Expected Python type name: "str", "int", "float", "bool",
        "list", "dict", or "null". None disables type checking.
    min_val:
        Minimum value for numeric types (inclusive).
    max_val:
        Maximum value for numeric types (inclusive).
    max_length:
        Maximum length for string or list arguments.
    required:
        If True, the argument must be present in the request.
    allowed_values:
        Explicit list of accepted values. Empty list disables this check.
    """

    tool_pattern: str
    param_name: str
    param_type: str | None = None
    min_val: float | None = None
    max_val: float | None = None
    max_length: int | None = None
    required: bool = False
    allowed_values: list[object] = field(default_factory=list)


def _parse_rule(raw: object) -> ArgumentRule | None:
    """Parse a rule dict from settings into an ArgumentRule dataclass.

    Parameters
    ----------
    raw:
        Raw dict from the YAML settings.

    Returns
    -------
    ArgumentRule | None
        Parsed rule, or None if the dict was malformed.
    """
    if not isinstance(raw, dict):
        logger.warning("Skipping argument rule: expected dict, got %s", type(raw).__name__)
        return None

    tool_pattern = raw.get("tool_pattern")
    param_name = raw.get("param_name")

    if not isinstance(tool_pattern, str) or not tool_pattern:
        logger.warning("Skipping argument rule: 'tool_pattern' must be a non-empty string")
        return None
    if not isinstance(param_name, str) or not param_name:
        logger.warning("Skipping argument rule: 'param_name' must be a non-empty string")
        return None

    raw_type = raw.get("param_type")
    param_type: str | None = None
    if raw_type is not None:
        if str(raw_type) not in _VALID_TYPES:
            logger.warning(
                "Skipping argument rule for %r: unknown param_type %r (valid: %s)",
                param_name,
                raw_type,
                ", ".join(sorted(_VALID_TYPES)),
            )
            return None
        param_type = str(raw_type)

    raw_min = raw.get("min_val")
    raw_max = raw.get("max_val")
    raw_maxlen = raw.get("max_length")
    raw_required = raw.get("required", False)
    raw_allowed = raw.get("allowed_values", [])

    try:
        min_val = float(raw_min) if raw_min is not None else None
        max_val = float(raw_max) if raw_max is not None else None
        max_length = int(raw_maxlen) if raw_maxlen is not None else None
    except (TypeError, ValueError) as exc:
        logger.warning("Skipping argument rule for %r: invalid numeric value: %s", param_name, exc)
        return None

    allowed_values: list[object] = list(raw_allowed) if isinstance(raw_allowed, list) else []

    return ArgumentRule(
        tool_pattern=tool_pattern,
        param_name=param_name,
        param_type=param_type,
        min_val=min_val,
        max_val=max_val,
        max_length=max_length,
        required=bool(raw_required),
        allowed_values=allowed_values,
    )


class BasicArgumentScanner(Scanner):
    """Validates tool call arguments against configurable rules.

    Rules are matched against the ``server_name:tool_name`` identifier
    using fnmatch glob patterns, then each matched rule's constraints
    are checked against the corresponding argument value.

    Configuration
    -------------
    settings dict keys:

    ``strict_types``: bool (default False)
        If True, missing required parameters and type mismatches that
        would produce a WARN are escalated to BLOCK.

    ``rules``: list[dict]
        List of argument rule definitions. Each dict may contain:
        - tool_pattern (required): fnmatch pattern for "server:tool"
        - param_name (required): argument key to validate
        - param_type: expected type ("str","int","float","bool","list","dict","null")
        - min_val: minimum numeric value
        - max_val: maximum numeric value
        - max_length: maximum string or list length
        - required: bool — argument must be present
        - allowed_values: list of accepted values

    What This Scanner Is NOT
    ------------------------
    - NOT semantic argument analysis (available via plugins)
    - NOT ML-based anomaly detection (available via plugins)
    - Static rule validation only
    """

    name = "argument"

    def __init__(self, settings: dict[str, object] | None = None) -> None:
        config = settings or {}
        self._strict_types = bool(config.get("strict_types", False))

        raw_rules = config.get("rules", [])
        self._rules: list[ArgumentRule] = []
        if isinstance(raw_rules, list):
            for raw in raw_rules:
                rule = _parse_rule(raw)
                if rule is not None:
                    self._rules.append(rule)

        logger.debug(
            "ArgumentScanner initialised: %d rules, strict_types=%s",
            len(self._rules),
            self._strict_types,
        )

    def _matching_rules(self, tool_id: str) -> list[ArgumentRule]:
        """Return all rules whose tool_pattern matches the given tool ID.

        Parameters
        ----------
        tool_id:
            Canonical ``server_name:tool_name`` identifier.

        Returns
        -------
        list[ArgumentRule]
            All rules that match in configuration order.
        """
        return [r for r in self._rules if fnmatch.fnmatch(tool_id, r.tool_pattern)]

    def _validate_argument(
        self, rule: ArgumentRule, value: object
    ) -> tuple[Literal["pass", "warn", "block"], str]:
        """Validate a single argument value against a rule.

        Parameters
        ----------
        rule:
            The rule to apply.
        value:
            The argument value to validate.

        Returns
        -------
        tuple[str, str]
            (outcome, reason) where outcome is "pass", "warn", or "block".
        """
        param = rule.param_name

        # Type check
        if rule.param_type is not None and rule.param_type != "null":
            expected_type = _PYTHON_TYPE_MAP.get(rule.param_type)
            if expected_type is not None and not isinstance(value, expected_type):
                # bool is a subclass of int — treat bool as int if param_type is int
                if not (rule.param_type == "int" and isinstance(value, bool)):
                    return (
                        "block" if self._strict_types else "warn",
                        f"Argument '{param}' expected type '{rule.param_type}', "
                        f"got '{type(value).__name__}'",
                    )

        # Null type: value must be None
        if rule.param_type == "null" and value is not None:
            return (
                "block" if self._strict_types else "warn",
                f"Argument '{param}' expected null, got '{type(value).__name__}'",
            )

        # Numeric range checks
        if rule.min_val is not None and isinstance(value, (int, float)) and not isinstance(value, bool):
            if float(value) < rule.min_val:
                return (
                    "block",
                    f"Argument '{param}' value {value} is below minimum {rule.min_val}",
                )

        if rule.max_val is not None and isinstance(value, (int, float)) and not isinstance(value, bool):
            if float(value) > rule.max_val:
                return (
                    "block",
                    f"Argument '{param}' value {value} exceeds maximum {rule.max_val}",
                )

        # String / list length checks
        if rule.max_length is not None and isinstance(value, (str, list)):
            if len(value) > rule.max_length:
                return (
                    "block",
                    f"Argument '{param}' length {len(value)} exceeds maximum {rule.max_length}",
                )

        # Allowed values check
        if rule.allowed_values and value not in rule.allowed_values:
            allowed_display = ", ".join(repr(v) for v in rule.allowed_values[:10])
            return (
                "block",
                f"Argument '{param}' value {value!r} is not in allowed values: {allowed_display}",
            )

        return ("pass", "")

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Validate tool call arguments against configured rules.

        Parameters
        ----------
        request:
            The tool call request to evaluate.

        Returns
        -------
        ScanResult
            PASS if all rules pass, WARN for soft violations,
            BLOCK for hard violations.
        """
        if not self._rules:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        tool_id = f"{request.server_name}:{request.tool_name}"
        matching = self._matching_rules(tool_id)

        if not matching:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        violations: list[str] = []
        highest_outcome: Literal["pass", "warn", "block"] = "pass"

        for rule in matching:
            # Required check
            if rule.required and rule.param_name not in request.arguments:
                outcome: Literal["pass", "warn", "block"] = (
                    "block" if self._strict_types else "warn"
                )
                reason = f"Required argument '{rule.param_name}' is missing"
                violations.append(reason)
                if outcome == "block":
                    highest_outcome = "block"
                elif highest_outcome == "pass":
                    highest_outcome = "warn"
                continue

            if rule.param_name not in request.arguments:
                continue

            value = request.arguments[rule.param_name]
            outcome, reason = self._validate_argument(rule, value)
            if outcome != "pass":
                violations.append(reason)
                if outcome == "block":
                    highest_outcome = "block"
                elif highest_outcome == "pass":
                    highest_outcome = "warn"

        if highest_outcome == "block":
            return ScanResult(
                action=Action.BLOCK,
                reason=f"Argument validation failed: {violations[0]}",
                details={"tool_id": tool_id, "violations": violations},
                scanner_name=self.name,
            )

        if highest_outcome == "warn":
            return ScanResult(
                action=Action.WARN,
                reason=f"Argument validation warning: {violations[0]}",
                details={"tool_id": tool_id, "violations": violations},
                scanner_name=self.name,
            )

        return ScanResult(action=Action.PASS, scanner_name=self.name)
