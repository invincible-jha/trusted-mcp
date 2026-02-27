"""Shell metacharacter sanitizer for command injection prevention.

Detects and optionally strips shell metacharacters from argument
values to prevent command injection vulnerabilities in MCP tools
that pass arguments to shell commands.

References
----------
- OWASP Testing Guide OTG-INPVAL-013: Testing for Command Injection
- CWE-78: Improper Neutralization of Special Elements used in an OS Command

What This Is NOT
----------------
This is pattern-based shell metachar detection. It is NOT:
- A shell parser or tokenizer
- A complete defense for all shell injection vectors
- A substitute for avoiding shell=True in subprocess calls

Always prefer subprocess with argument lists (not shell=True) at the
tool implementation layer. This sanitizer is a defense-in-depth layer.

Example
-------
::

    from trusted_mcp.sanitizers.shell_sanitizer import ShellSanitizer

    # Strip mode: removes dangerous characters
    sanitizer = ShellSanitizer(mode="strip")
    result = sanitizer.sanitize("hello; rm -rf /")
    print(result.safe)       # True (in strip mode, stripped input is safe)
    print(result.sanitized)  # "hello rm -rf /"

    # Reject mode: rejects any input containing dangerous characters
    sanitizer = ShellSanitizer(mode="reject")
    result = sanitizer.sanitize("hello; rm -rf /")
    print(result.safe)       # False
"""
from __future__ import annotations

import re
from typing import Literal

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult

# Shell metacharacters that enable command injection.
# These are characters with special meaning in POSIX shells.
_SHELL_METACHAR_PATTERN = re.compile(
    r"[;&|`$<>\\!{}()\[\]*?~]"
    r"|&&"
    r"|\|\|"
    r"|\$\("
    r"|\$\{"
    r"|`[^`]*`"
)

# Compiled patterns used for individual violation detection
_VIOLATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("semicolon command separator", re.compile(r";")),
    ("pipe operator", re.compile(r"\|")),
    ("background execution operator", re.compile(r"&(?!&)")),
    ("logical AND operator", re.compile(r"&&")),
    ("logical OR operator", re.compile(r"\|\|")),
    ("backtick command substitution", re.compile(r"`")),
    ("dollar sign variable/substitution", re.compile(r"\$")),
    ("output redirection", re.compile(r">")),
    ("input redirection", re.compile(r"<")),
    ("backslash escape", re.compile(r"\\")),
    ("brace expansion", re.compile(r"[{}]")),
    ("subshell grouping", re.compile(r"[()]")),
    ("glob expansion", re.compile(r"[*?]")),
    ("bracket expression", re.compile(r"[\[\]]")),
    ("tilde expansion", re.compile(r"~")),
    ("exclamation history expansion", re.compile(r"!")),
]


class ShellSanitizer(Sanitizer):
    """Blocks or strips shell metacharacters from argument strings.

    Two operating modes:

    - ``strip``: Removes all detected shell metacharacters. The
      sanitized output is returned and ``safe=True`` is set.
    - ``reject``: Returns ``safe=False`` if any shell metacharacter
      is found. The original value is returned unchanged.

    Parameters
    ----------
    mode:
        Operating mode: ``"strip"`` or ``"reject"``.
        Defaults to ``"strip"``.

    Thread Safety
    -------------
    Stateless — the same instance can handle concurrent requests.
    """

    def __init__(self, mode: Literal["strip", "reject"] = "strip") -> None:
        if mode not in ("strip", "reject"):
            raise ValueError(f"ShellSanitizer mode must be 'strip' or 'reject', got {mode!r}")
        self._mode: Literal["strip", "reject"] = mode

    def _find_violations(self, value: str) -> list[str]:
        """Identify all shell metacharacter violations in the value.

        Parameters
        ----------
        value:
            The input string to analyze.

        Returns
        -------
        list[str]
            Human-readable description of each violation found.
        """
        violations: list[str] = []
        for description, pattern in _VIOLATION_PATTERNS:
            if pattern.search(value):
                violations.append(f"Shell injection: {description} detected")
        return violations

    def sanitize(self, value: str) -> SanitizeResult:
        """Sanitize a string argument for shell safety.

        Parameters
        ----------
        value:
            The argument value to sanitize.

        Returns
        -------
        SanitizeResult
            In ``strip`` mode: violations listed, sanitized output has
            metacharacters removed, ``safe=True``.
            In ``reject`` mode: violations listed, ``safe=False`` if any
            metacharacter found, original value returned unchanged.

        Important — strip mode semantics
        ---------------------------------
        In ``strip`` mode, ``safe=True`` means the output is safe to pass
        to a shell command, but the value **may have been semantically
        altered**. Dangerous metacharacters are silently removed, so the
        sanitized string may carry a different meaning than the original
        (e.g. ``"hello; rm -rf /"`` becomes ``"hello rm -rf /"``). Callers
        must check ``result.was_modified`` and decide whether the altered
        value is still acceptable for their use-case. When semantic
        equivalence is required, use ``mode="reject"`` instead.
        """
        if not value:
            return SanitizeResult(safe=True, original=value, sanitized=value)

        violations = self._find_violations(value)

        if not violations:
            return SanitizeResult(safe=True, original=value, sanitized=value)

        if self._mode == "reject":
            return SanitizeResult(
                safe=False,
                original=value,
                sanitized=value,
                violations=violations,
            )

        # Strip mode: remove all metacharacters
        sanitized = _SHELL_METACHAR_PATTERN.sub("", value)
        # Collapse multiple spaces left by removal
        sanitized = re.sub(r"  +", " ", sanitized).strip()

        return SanitizeResult(
            safe=True,
            original=value,
            sanitized=sanitized,
            violations=violations,
            was_modified=(sanitized != value),
        )
