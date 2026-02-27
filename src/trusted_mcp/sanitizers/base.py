"""Sanitizer abstract base class and shared result type.

Defines the plugin boundary that all sanitizers must satisfy.
Sanitizers are composable: a value can be passed through multiple
sanitizer instances in sequence, with each building on the output
of the previous (in ``sanitize`` mode) or short-circuiting on
the first rejection (in ``reject`` mode).

Example
-------
::

    from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult

    class MySanitizer(Sanitizer):
        def sanitize(self, value: str) -> SanitizeResult:
            cleaned = value.replace("bad", "")
            violations = ["found 'bad'" for _ in range(value.count("bad"))]
            return SanitizeResult(
                safe=len(violations) == 0,
                original=value,
                sanitized=cleaned,
                violations=violations,
            )
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class SanitizeResult:
    """Result of a sanitizer evaluation on a single string value.

    Attributes
    ----------
    safe:
        True if the value was accepted (no violations, or all violations
        were stripped in ``strip`` mode). False if the value was rejected.
    original:
        The original input string before any modification.
    sanitized:
        The cleaned output string. Equal to ``original`` if no changes
        were made or if the sanitizer is in ``reject`` mode.
    violations:
        List of human-readable descriptions of each violation found.
        Empty if ``safe`` is True and no stripping was performed.
    was_modified:
        True if ``sanitized`` differs from ``original`` (i.e. characters
        were stripped). Always ``False`` in ``reject`` mode. Callers in
        ``strip`` mode should check this field: ``safe=True`` means the
        output is safe to use, but the value may have been semantically
        altered — the stripped value may no longer carry the same meaning
        as the original.
    """

    safe: bool
    original: str
    sanitized: str
    violations: list[str] = field(default_factory=list)
    was_modified: bool = False


class Sanitizer(ABC):
    """Abstract base class for all argument sanitizers.

    Subclasses implement ``sanitize`` to either:
    - Strip dangerous characters/patterns (``strip`` mode).
    - Reject inputs that contain dangerous patterns (``reject`` mode).

    All sanitizers must be stateless and thread-safe so that a single
    instance can be shared across multiple concurrent requests.
    """

    @abstractmethod
    def sanitize(self, value: str) -> SanitizeResult:
        """Sanitize a single string argument value.

        Parameters
        ----------
        value:
            The raw argument string to evaluate.

        Returns
        -------
        SanitizeResult
            ``safe=True`` if the value is acceptable (possibly with
            characters stripped). ``safe=False`` if the value must be
            rejected entirely.
        """
        ...
