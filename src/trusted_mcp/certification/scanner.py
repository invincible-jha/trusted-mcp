"""CertificationScanner — higher-level orchestrator for MCP server certification.

This module provides :class:`CertificationScanner`, which evaluates a set of
:class:`~trusted_mcp.core.scanner.ToolDefinition` objects against the
certification requirements defined in :mod:`trusted_mcp.certification.levels`.

It is NOT a :class:`~trusted_mcp.core.scanner.Scanner` subclass — it operates
at a higher level (whole-server evaluation) rather than per-request interception.

Example
-------
::

    from trusted_mcp.certification.scanner import CertificationScanner
    from trusted_mcp.core.scanner import ToolDefinition

    tools = [
        ToolDefinition(
            name="search",
            server_name="my-server",
            description="Search the web for information.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
    ]
    scanner = CertificationScanner()
    result = scanner.evaluate(tools)
    print(result.level)   # CertificationLevel.BRONZE (at minimum)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from trusted_mcp.certification.levels import (
    CERTIFICATION_REQUIREMENTS,
    CertificationLevel,
    CertificationRequirement,
    determine_certification_level,
)
from trusted_mcp.core.scanner import ToolDefinition

# ---------------------------------------------------------------------------
# Prompt-injection patterns reused from BasicRegexScanner heuristics
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)",
        r"(new|updated?|revised?)\s+(instructions?|system\s+prompt)",
        r"(show|reveal|repeat|echo)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?)",
        r"(pretend|act|roleplay)\s+(you\s+are|as\s+if)\s+(a\s+)?(different|unrestricted|jailbroken)",
        r"(enable|activate)\s+(developer|admin|god|jailbreak)\s+mode",
        r"\bDAN\b.*\b(mode|jailbreak|unrestricted)",
        r"(</?(system|user|assistant|instruction)>|\[INST\]|\[/INST\])",
    ]
)

# Patterns that indicate PII in text
_PII_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in [
        r"\b\d{3}-\d{2}-\d{4}\b",                                           # SSN
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",             # email
        r"\bAKIA[0-9A-Z]{16}\b",                                             # AWS key
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # CC
    ]
)


@dataclass
class CheckDetail:
    """Result detail for a single certification check.

    Attributes
    ----------
    requirement_name:
        The name of the :class:`CertificationRequirement` evaluated.
    passed:
        True if the check passed.
    reason:
        Human-readable explanation when *passed* is False.
    details:
        Structured diagnostic data (offending tool names, counts, etc.).
    """

    requirement_name: str
    passed: bool
    reason: str | None = None
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class CertificationResult:
    """Result of a full certification evaluation for an MCP server.

    Attributes
    ----------
    server_name:
        Name of the MCP server that was evaluated.
    level:
        Highest certification level achieved.
    passed_requirements:
        Names of requirements that passed.
    failed_requirements:
        Names of requirements that failed.
    check_details:
        Per-requirement diagnostic detail.
    tool_count:
        Number of tool definitions that were evaluated.
    """

    server_name: str
    level: CertificationLevel
    passed_requirements: set[str]
    failed_requirements: set[str]
    check_details: list[CheckDetail]
    tool_count: int


class CertificationScanner:
    """Higher-level orchestrator that evaluates MCP tool definitions against
    the trusted-mcp certification framework.

    Unlike the per-request :class:`~trusted_mcp.core.scanner.Scanner` subclasses,
    this class operates over a *collection* of tool definitions representing an
    entire MCP server and produces a :class:`CertificationResult` rather than a
    :class:`~trusted_mcp.core.result.ScanResult`.

    Parameters
    ----------
    config:
        Optional configuration dict. Supported keys:

        - ``require_authentication`` (bool): Signal that the server implements
          authentication. Defaults to False (forces Silver/Gold to fail unless
          explicitly declared).
        - ``require_authorization`` (bool): Signal that the server enforces
          per-tool authorization. Defaults to False.
        - ``require_audit_logging`` (bool): Signal that the server logs all
          tool invocations. Defaults to False.
        - ``require_session_security`` (bool): Signal that session tokens are
          cryptographically secure. Defaults to False.
        - ``require_schema_stability`` (bool): Signal that schemas are
          version-pinned. Defaults to False.
        - ``require_dependency_verification`` (bool): Signal that dependencies
          are audited. Defaults to False.

    Notes
    -----
    The infrastructure-level checks (authentication, authorization, audit
    logging, session security, schema stability, dependency verification) cannot
    be determined by inspecting tool descriptions alone — they require operator
    attestation via the config dict. This mirrors how real-world certification
    programs (SOC 2, ISO 27001) rely on documented controls alongside automated
    scanning.
    """

    def __init__(self, config: dict[str, object] | None = None) -> None:
        cfg = config or {}
        self._require_authentication: bool = bool(cfg.get("require_authentication", False))
        self._require_authorization: bool = bool(cfg.get("require_authorization", False))
        self._require_audit_logging: bool = bool(cfg.get("require_audit_logging", False))
        self._require_session_security: bool = bool(cfg.get("require_session_security", False))
        self._require_schema_stability: bool = bool(cfg.get("require_schema_stability", False))
        self._require_dependency_verification: bool = bool(
            cfg.get("require_dependency_verification", False)
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_injection_resistance(
        self, tools: list[ToolDefinition]
    ) -> CheckDetail:
        """Check that no tool description contains known injection patterns.

        Parameters
        ----------
        tools:
            Tool definitions to inspect.

        Returns
        -------
        CheckDetail
            Passes when no injection patterns match any description.
        """
        offending: list[str] = []
        for tool in tools:
            text = tool.description
            if any(pattern.search(text) for pattern in _INJECTION_PATTERNS):
                offending.append(f"{tool.server_name}:{tool.name}")

        if offending:
            return CheckDetail(
                requirement_name="Prompt Injection Resistance",
                passed=False,
                reason=f"{len(offending)} tool(s) contain injection patterns",
                details={"offending_tools": offending},
            )
        return CheckDetail(requirement_name="Prompt Injection Resistance", passed=True)

    def check_input_validation(
        self, tools: list[ToolDefinition]
    ) -> CheckDetail:
        """Check that all tools declare a non-empty input_schema.

        Parameters
        ----------
        tools:
            Tool definitions to inspect.

        Returns
        -------
        CheckDetail
            Passes when every tool has a non-empty ``input_schema``.
        """
        # An empty tool list trivially satisfies the check.
        missing: list[str] = []
        for tool in tools:
            schema = tool.input_schema
            # Require at least a "type" or "properties" key as a meaningful schema
            if not schema or not (
                "type" in schema or "properties" in schema or "anyOf" in schema or "oneOf" in schema
            ):
                missing.append(f"{tool.server_name}:{tool.name}")

        if missing:
            return CheckDetail(
                requirement_name="Input Validation Completeness",
                passed=False,
                reason=f"{len(missing)} tool(s) lack a declared input schema",
                details={"tools_without_schema": missing},
            )
        return CheckDetail(requirement_name="Input Validation Completeness", passed=True)

    def check_tool_description_integrity(
        self, tools: list[ToolDefinition]
    ) -> CheckDetail:
        """Verify that tool descriptions are non-empty and produce stable hashes.

        In a live context, these hashes would be compared against a stored
        baseline. Here we verify the necessary condition: every tool has a
        non-empty description that can be hashed.

        Parameters
        ----------
        tools:
            Tool definitions to inspect.

        Returns
        -------
        CheckDetail
            Passes when all tools have non-empty, hashable descriptions.
        """
        empty_descriptions: list[str] = []
        hashes: dict[str, str] = {}
        for tool in tools:
            tool_key = f"{tool.server_name}:{tool.name}"
            if not tool.description.strip():
                empty_descriptions.append(tool_key)
            else:
                hashes[tool_key] = hashlib.sha256(
                    tool.description.encode("utf-8")
                ).hexdigest()

        if empty_descriptions:
            return CheckDetail(
                requirement_name="Tool Description Integrity",
                passed=False,
                reason=f"{len(empty_descriptions)} tool(s) have empty descriptions (cannot hash)",
                details={"tools_without_description": empty_descriptions},
            )
        return CheckDetail(
            requirement_name="Tool Description Integrity",
            passed=True,
            details={"hashed_tools": len(hashes)},
        )

    def check_pii_handling(
        self, tools: list[ToolDefinition]
    ) -> CheckDetail:
        """Check that no tool description exposes PII patterns.

        Parameters
        ----------
        tools:
            Tool definitions to inspect.

        Returns
        -------
        CheckDetail
            Passes when no PII patterns are detected in any description.
        """
        offending: list[str] = []
        for tool in tools:
            if any(p.search(tool.description) for p in _PII_PATTERNS):
                offending.append(f"{tool.server_name}:{tool.name}")

        if offending:
            return CheckDetail(
                requirement_name="PII Handling",
                passed=False,
                reason=f"{len(offending)} tool description(s) contain PII patterns",
                details={"offending_tools": offending},
            )
        return CheckDetail(requirement_name="PII Handling", passed=True)

    def _check_attested(self, requirement_name: str, flag: bool) -> CheckDetail:
        """Evaluate an infrastructure requirement that requires operator attestation.

        Parameters
        ----------
        requirement_name:
            The :class:`CertificationRequirement` name being evaluated.
        flag:
            True when the operator has attested compliance via config.

        Returns
        -------
        CheckDetail
        """
        if flag:
            return CheckDetail(requirement_name=requirement_name, passed=True)
        return CheckDetail(
            requirement_name=requirement_name,
            passed=False,
            reason=(
                f"'{requirement_name}' requires operator attestation via scanner config. "
                "Set the corresponding flag in the CertificationScanner config dict."
            ),
        )

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def evaluate(self, tools: list[ToolDefinition]) -> CertificationResult:
        """Run all checks and return a :class:`CertificationResult`.

        Runs every check in :data:`~trusted_mcp.certification.levels.CERTIFICATION_REQUIREMENTS`
        order and aggregates results into the highest achieved certification level.

        Parameters
        ----------
        tools:
            Tool definitions representing the MCP server under evaluation.
            May be empty — an empty list satisfies no schema requirement but
            passes the injection/PII/integrity checks trivially.

        Returns
        -------
        CertificationResult
            Full evaluation result including per-check diagnostics.
        """
        server_name = tools[0].server_name if tools else "unknown"

        details: list[CheckDetail] = []

        # Automated checks (derived from tool definitions)
        details.append(self.check_injection_resistance(tools))
        details.append(self.check_input_validation(tools))
        details.append(self.check_tool_description_integrity(tools))
        details.append(self.check_pii_handling(tools))

        # Attested checks (operator-declared via config)
        details.append(
            self._check_attested("Authentication Implemented", self._require_authentication)
        )
        details.append(
            self._check_attested("Permission Boundaries Enforced", self._require_authorization)
        )
        details.append(
            self._check_attested("Audit Logging", self._require_audit_logging)
        )
        details.append(
            self._check_attested("Session Security", self._require_session_security)
        )
        details.append(
            self._check_attested("Schema Stability Verification", self._require_schema_stability)
        )
        details.append(
            self._check_attested("Dependency Verification", self._require_dependency_verification)
        )

        # Aggregate into passed / failed sets
        passed: set[str] = {d.requirement_name for d in details if d.passed}
        failed: set[str] = {d.requirement_name for d in details if not d.passed}

        # Validate that every CERTIFICATION_REQUIREMENTS entry was checked
        all_requirement_names: set[str] = {r.name for r in CERTIFICATION_REQUIREMENTS}
        evaluated_names: set[str] = passed | failed
        unchecked = all_requirement_names - evaluated_names
        if unchecked:  # pragma: no cover — safety net only
            for req_name in unchecked:
                failed.add(req_name)

        level = determine_certification_level(passed)

        return CertificationResult(
            server_name=server_name,
            level=level,
            passed_requirements=passed,
            failed_requirements=failed,
            check_details=details,
            tool_count=len(tools),
        )
