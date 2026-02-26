"""Result types for scanner evaluations.

Defines the three-level action enum (PASS / WARN / BLOCK) and the
dataclasses that carry scanner and chain-level results through the
interceptor pipeline.

Example
-------
::

    from trusted_mcp.core.result import Action, ScanResult, ChainResult

    result = ScanResult(action=Action.BLOCK, reason="SQL injection detected")
    print(result.action.value)  # "block"

    chain = ChainResult(
        action=Action.WARN,
        warnings=[result],
    )
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Action(str, Enum):
    """The three possible outcomes of a scanner evaluation.

    Values are lowercase strings so they serialise naturally to JSON
    and YAML without extra conversion.
    """

    PASS = "pass"
    """The scanner found nothing suspicious. Execution may continue."""

    WARN = "warn"
    """The scanner found something suspicious but non-blocking.
    A warning is accumulated and execution continues.
    """

    BLOCK = "block"
    """The scanner found something that must be stopped.
    The interceptor chain short-circuits immediately on this result.
    """


@dataclass
class ScanResult:
    """Result of a single scanner evaluation.

    Produced by every Scanner.scan_request(), scan_response(), and
    scan_tool_description() call. The chain collects these and decides
    the aggregate action.

    Attributes
    ----------
    action:
        PASS, WARN, or BLOCK.
    reason:
        Human-readable explanation for the action, if not PASS.
    details:
        Structured extra data (matched pattern names, offending fields,
        etc.) for audit logging and UI display.
    scanner_name:
        Name of the scanner that produced this result.
    confidence:
        0.0–1.0 confidence score for the action. Commodity scanners
        always return 1.0; this field exists so the interface is
        compatible with plugin scanners that may return lower
        confidence estimates.
    """

    action: Action
    reason: str | None = None
    details: dict[str, object] | None = None
    scanner_name: str | None = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )


@dataclass
class ChainResult:
    """Aggregate result from an entire interceptor chain run.

    After running all scanners, the chain collapses individual
    ScanResult objects into a single ChainResult that the proxy
    uses to decide whether to forward, warn, or block.

    Attributes
    ----------
    action:
        The final aggregate action — BLOCK if any scanner blocked,
        WARN if any warned and none blocked, PASS if all passed.
    blocking_scanner:
        Name of the scanner that triggered the BLOCK, if applicable.
    blocking_reason:
        Human-readable reason from the blocking scanner.
    blocking_details:
        Structured details from the blocking scanner.
    warnings:
        All WARN-level results accumulated during the chain run.
    all_results:
        Every ScanResult in chain execution order, for full audit trail.
    """

    action: Action
    blocking_scanner: str | None = None
    blocking_reason: str | None = None
    blocking_details: dict[str, object] | None = None
    warnings: list[ScanResult] = field(default_factory=list)
    all_results: list[ScanResult] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        """Return True if the chain result is a BLOCK."""
        return self.action == Action.BLOCK

    @property
    def has_warnings(self) -> bool:
        """Return True if any scanner produced a WARN result."""
        return bool(self.warnings)

    def warning_reasons(self) -> list[str]:
        """Return all warning reason strings, filtering out None values."""
        return [w.reason for w in self.warnings if w.reason is not None]
