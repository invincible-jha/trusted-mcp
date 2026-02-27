"""URL scheme restriction sanitizer.

Validates URL arguments to restrict dangerous schemes (``file://``,
``data://``, ``javascript:``, ``ftp://``) and verify basic URL
structure. Only ``http://`` and ``https://`` are permitted by default.

References
----------
- OWASP Testing Guide: Testing for URL Redirect
- CWE-601: URL Redirection to Untrusted Site
- CWE-116: Improper Encoding/Escaping of Output (for javascript: URLs)

What This Is NOT
----------------
This is a URL scheme allowlist enforcer. It is NOT:
- A complete SSRF (Server-Side Request Forgery) defense
- An IP blocklist for private/internal network ranges
- A full URL parser that validates all RFC 3986 components

For SSRF protection, also validate that resolved IPs are not in
RFC 1918 private ranges (10.x, 172.16.x, 192.168.x) and block
localhost/loopback targets at the network layer.

Example
-------
::

    from trusted_mcp.sanitizers.url_sanitizer import URLSanitizer

    sanitizer = URLSanitizer()
    result = sanitizer.sanitize("file:///etc/passwd")
    print(result.safe)       # False
    print(result.violations) # ["URL scheme 'file' is not permitted"]

    result = sanitizer.sanitize("https://example.com/api")
    print(result.safe)       # True
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult

# Default set of permitted URL schemes
_DEFAULT_ALLOWED_SCHEMES: frozenset[str] = frozenset(["http", "https"])

# Schemes that are always dangerous regardless of allowlist
_ALWAYS_BLOCKED_SCHEMES: frozenset[str] = frozenset(
    [
        "javascript",
        "data",
        "vbscript",
        "file",
    ]
)

# Basic URL structure pattern — must have a scheme and a host
_URL_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


class URLSanitizer(Sanitizer):
    """Validates URL arguments against a permitted scheme allowlist.

    Rejects URLs with dangerous schemes (``file://``, ``data://``,
    ``javascript:``) and any scheme not in the configured allowlist.
    Default allowlist: ``{"http", "https"}``.

    Parameters
    ----------
    allowed_schemes:
        Set of permitted URL schemes (lowercase). Defaults to
        ``{"http", "https"}``.
    require_url_structure:
        If True, reject values that look like URLs (contain ``://``)
        but fail to parse into a valid scheme + host. Defaults to True.

    Thread Safety
    -------------
    Stateless — the same instance can handle concurrent requests.
    """

    def __init__(
        self,
        allowed_schemes: set[str] | None = None,
        require_url_structure: bool = True,
    ) -> None:
        self._allowed_schemes: frozenset[str] = (
            frozenset(s.lower() for s in allowed_schemes)
            if allowed_schemes is not None
            else _DEFAULT_ALLOWED_SCHEMES
        )
        self._require_url_structure = require_url_structure

    def _find_violations(self, value: str) -> list[str]:
        """Identify all URL scheme violations in the value.

        Parameters
        ----------
        value:
            The URL string to analyze.

        Returns
        -------
        list[str]
            Descriptions of each violation found.
        """
        violations: list[str] = []
        stripped = value.strip()

        # Quick check: does the value look like it has a URL scheme?
        has_scheme_pattern = _URL_HAS_SCHEME.match(stripped)

        # Check for dangerous schemes that use a bare colon instead of ://
        # (javascript:, vbscript:, data:).  These must be caught before the
        # has_scheme_pattern guard because they do not contain "://".
        _BARE_COLON_BLOCKED: tuple[tuple[str, str], ...] = (
            ("javascript", "XSS risk"),
            ("vbscript", "XSS risk"),
            ("data", "data URI injection risk"),
        )
        for scheme_name, reason in _BARE_COLON_BLOCKED:
            if re.match(rf"{re.escape(scheme_name)}\s*:", stripped, re.IGNORECASE):
                violations.append(
                    f"URL scheme '{scheme_name}' is not permitted ({reason})"
                )
                return violations

        if not has_scheme_pattern:
            # No scheme detected — not a URL, pass through
            return violations

        try:
            parsed = urlparse(stripped)
            scheme = parsed.scheme.lower() if parsed.scheme else ""

            if scheme in _ALWAYS_BLOCKED_SCHEMES:
                violations.append(
                    f"URL scheme {scheme!r} is not permitted (high security risk)"
                )
            elif scheme not in self._allowed_schemes:
                violations.append(
                    f"URL scheme {scheme!r} is not in the permitted scheme list "
                    f"(allowed: {', '.join(sorted(self._allowed_schemes))})"
                )

            # Validate basic URL structure for permitted schemes
            if not violations and self._require_url_structure:
                if not parsed.netloc:
                    violations.append(
                        f"URL with scheme {scheme!r} is missing a hostname"
                    )

        except Exception:
            violations.append("URL could not be parsed: malformed URL structure")

        return violations

    def sanitize(self, value: str) -> SanitizeResult:
        """Validate a URL argument against the permitted scheme allowlist.

        Always operates in reject mode — URLs with disallowed schemes
        are rejected rather than modified.

        Parameters
        ----------
        value:
            The URL argument value to validate.

        Returns
        -------
        SanitizeResult
            ``safe=True`` if the URL passes scheme validation.
            ``safe=False`` if any scheme violation is detected.
        """
        if not value or not value.strip():
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
