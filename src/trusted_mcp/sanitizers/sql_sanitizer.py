"""SQL injection detection sanitizer.

Detects common SQL injection patterns in argument strings. This
sanitizer operates in reject-only mode — it does not attempt to
modify SQL-containing inputs because doing so would change semantics
in unpredictable ways.

References
----------
- OWASP Testing Guide OTG-INPVAL-005: Testing for SQL Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- OWASP SQL Injection Prevention Cheat Sheet

What This Is NOT
----------------
This is pattern-based SQL injection detection. It is NOT:
- A parameterized query builder (use parameterized queries at the tool layer)
- A complete defense for all SQL injection vectors
- An alternative to database-level prepared statements

Parameterized queries at the tool implementation layer are the ONLY
complete defense against SQL injection. This sanitizer is defense-in-depth.

Example
-------
::

    from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer

    sanitizer = SQLSanitizer()
    result = sanitizer.sanitize("' OR 1=1 --")
    print(result.safe)       # False
    print(result.violations) # ["SQL injection: tautology condition detected"]
"""
from __future__ import annotations

import re

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult

# SQL injection detection patterns.
# These are from publicly available OWASP literature.
_SQL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "tautology condition",
        re.compile(
            r"'\s*(or|and)\s*'?\d"
            r"|'\s*or\s*'1'\s*=\s*'1"
            r"|'\s*or\s*1\s*=\s*1"
            r"|\bor\s+1\s*=\s*1\b",
            re.IGNORECASE,
        ),
    ),
    (
        "stacked query via semicolon",
        re.compile(
            r";\s*(insert|update|delete|drop|create|alter|exec|execute|select|truncate)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive DDL/DML statement",
        re.compile(
            r"\b(drop|truncate|delete\s+from)\s+(table|database|schema|view|index)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNION SELECT injection",
        re.compile(
            r"\bunion\s+(all\s+)?select\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL comment termination",
        re.compile(
            r"(--\s*$|#\s*$|/\*.*?\*/)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "comment-based injection marker",
        re.compile(
            r"/\*\*/|/\*.*?\*/",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "blind SQL injection probe",
        re.compile(
            r"\bselect\s+.+\s+from\b"
            r"|\bwaitfor\s+delay\b"
            r"|\bsleep\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "stored procedure execution",
        re.compile(
            r"\b(exec|execute)\s+(sp_|xp_)",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL string quote escape",
        re.compile(
            r"'[^']*'[^']*'",
        ),
    ),
]


class SQLSanitizer(Sanitizer):
    """Detects SQL injection patterns in argument strings (reject-only).

    This sanitizer always operates in reject mode. It returns
    ``safe=False`` when any SQL injection pattern is detected.
    The original value is always returned unchanged.

    Thread Safety
    -------------
    Stateless — the same instance can handle concurrent requests.
    """

    def _find_violations(self, value: str) -> list[str]:
        """Identify all SQL injection violations in the value.

        Parameters
        ----------
        value:
            The input string to analyze.

        Returns
        -------
        list[str]
            Descriptions of each SQL injection pattern found.
        """
        violations: list[str] = []
        for description, pattern in _SQL_PATTERNS:
            if pattern.search(value):
                violations.append(f"SQL injection: {description} detected")
        return violations

    def sanitize(self, value: str) -> SanitizeResult:
        """Check a string argument for SQL injection patterns.

        Always rejects rather than modifying the input, because
        modifying SQL strings to remove injection attempts would
        change the legitimate query semantics.

        Parameters
        ----------
        value:
            The argument value to validate.

        Returns
        -------
        SanitizeResult
            ``safe=True`` if no SQL injection patterns detected.
            ``safe=False`` if any pattern matches.
        """
        if not value:
            return SanitizeResult(safe=True, original=value, sanitized=value)

        violations = self._find_violations(value)

        if violations:
            return SanitizeResult(
                safe=False,
                original=value,
                sanitized=value,
                violations=violations,
            )

        return SanitizeResult(safe=True, original=value, sanitized=value)
