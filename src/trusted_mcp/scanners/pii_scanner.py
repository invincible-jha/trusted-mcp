"""Basic PII scanner for tool responses.

Scans tool call responses for common PII patterns before they reach
the LLM context. Uses regex matching for SSN, email, phone, credit
card, IP addresses, and cloud credentials.

What This Is NOT
----------------
This is basic regex PII detection, NOT:
- Named Entity Recognition (NER) based detection (available via plugins)
- Context-aware PII classification (available via plugins)
- Automated PII redaction pipeline (available via plugins)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse


@dataclass(frozen=True)
class PIIPattern:
    """Definition of a PII detection regex pattern.

    Attributes
    ----------
    name:
        Identifier for this PII type.
    pattern:
        Regular expression to match.
    pii_type:
        Category of PII (ssn, email, phone, credit_card, etc.).
    redaction:
        Replacement string for redaction.
    """

    name: str
    pattern: str
    pii_type: str
    redaction: str = "[REDACTED]"


# All patterns target commonly known PII formats
_DEFAULT_PII_PATTERNS: tuple[PIIPattern, ...] = (
    PIIPattern(
        name="ssn",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        pii_type="ssn",
        redaction="[REDACTED:SSN]",
    ),
    PIIPattern(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        pii_type="email",
        redaction="[REDACTED:EMAIL]",
    ),
    PIIPattern(
        name="phone_us",
        pattern=r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        pii_type="phone",
        redaction="[REDACTED:PHONE]",
    ),
    PIIPattern(
        name="credit_card",
        pattern=r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        pii_type="credit_card",
        redaction="[REDACTED:CC]",
    ),
    PIIPattern(
        name="ip_address",
        pattern=r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        pii_type="ip_address",
        redaction="[REDACTED:IP]",
    ),
    PIIPattern(
        name="aws_access_key",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        pii_type="cloud_credential",
        redaction="[REDACTED:AWS_KEY]",
    ),
    PIIPattern(
        name="date_of_birth",
        pattern=r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b",
        pii_type="dob",
        redaction="[REDACTED:DOB]",
    ),
    PIIPattern(
        name="passport",
        pattern=r"\b[A-Z]{1,2}\d{6,9}\b",
        pii_type="passport",
        redaction="[REDACTED:PASSPORT]",
    ),
)


class BasicPIIScanner(Scanner):
    """Commodity regex PII scanner for tool responses.

    Scans tool call response content for common PII patterns and
    either blocks or warns depending on configuration.

    Parameters
    ----------
    settings:
        Optional configuration dict. Supported keys:

        - ``action_on_detect`` (str): ``"block"`` or ``"warn"``.
          Defaults to ``"warn"``.
        - ``scan_requests`` (bool): Also scan outgoing requests.
          Defaults to False.
        - ``pii_types`` (list[str]): PII types to scan for.
          Defaults to all types. Options: ssn, email, phone,
          credit_card, ip_address, cloud_credential, dob, passport.
    """

    name: str = "pii"

    def __init__(self, settings: dict[str, object] | None = None) -> None:
        settings = settings or {}
        action_str = str(settings.get("action_on_detect", "warn")).lower()
        self._block_on_detect = action_str == "block"
        self._scan_requests = bool(settings.get("scan_requests", False))

        active_types: set[str] | None = None
        raw_types = settings.get("pii_types")
        if isinstance(raw_types, list):
            active_types = {str(t) for t in raw_types}

        self._patterns: list[tuple[PIIPattern, re.Pattern[str]]] = []
        for pattern_def in _DEFAULT_PII_PATTERNS:
            if active_types is None or pattern_def.pii_type in active_types:
                self._patterns.append(
                    (pattern_def, re.compile(pattern_def.pattern))
                )

    def _scan_text(self, text: str) -> list[PIIPattern]:
        """Return all PII patterns that match in the given text."""
        matches: list[PIIPattern] = []
        for pattern_def, compiled in self._patterns:
            if compiled.search(text):
                matches.append(pattern_def)
        return matches

    @staticmethod
    def _extract_response_text(response: ToolCallResponse) -> str:
        """Extract scannable text from a tool call response."""
        content = response.content
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            return str(content)
        if isinstance(content, list):
            return " ".join(str(item) for item in content)
        return str(content)

    @staticmethod
    def _extract_request_text(request: ToolCallRequest) -> str:
        """Extract scannable text from a tool call request."""
        parts: list[str] = []
        for value in request.arguments.values():
            parts.append(str(value))
        return " ".join(parts)

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Optionally scan outgoing request arguments for PII."""
        if not self._scan_requests:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        text = self._extract_request_text(request)
        matches = self._scan_text(text)

        if not matches:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        pii_types_found = sorted({m.pii_type for m in matches})
        action = Action.BLOCK if self._block_on_detect else Action.WARN
        return ScanResult(
            action=action,
            reason=f"PII detected in request arguments: {', '.join(pii_types_found)}",
            scanner_name=self.name,
            details={"pii_types": pii_types_found, "direction": "request"},
        )

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        """Scan tool response content for PII before it reaches the LLM."""
        text = self._extract_response_text(response)
        matches = self._scan_text(text)

        if not matches:
            return ScanResult(action=Action.PASS, scanner_name=self.name)

        pii_types_found = sorted({m.pii_type for m in matches})
        action = Action.BLOCK if self._block_on_detect else Action.WARN
        return ScanResult(
            action=action,
            reason=f"PII detected in tool response: {', '.join(pii_types_found)}",
            scanner_name=self.name,
            details={"pii_types": pii_types_found, "direction": "response"},
        )

    def redact(self, text: str) -> str:
        """Replace PII patterns in text with redaction placeholders."""
        result = text
        for pattern_def, compiled in self._patterns:
            result = compiled.sub(pattern_def.redaction, result)
        return result
