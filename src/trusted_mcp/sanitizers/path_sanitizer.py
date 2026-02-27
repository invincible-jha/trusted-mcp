"""Path traversal sanitizer for filesystem security.

Detects path traversal sequences (``../``, ``..\\``) and blocks
access to absolute paths outside a configured allowlist of permitted
base directories.

References
----------
- OWASP Testing Guide OTG-AUTHZ-001: Testing for Path Traversal
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

What This Is NOT
----------------
This is pattern-based path traversal detection. It is NOT:
- A filesystem ACL (use OS-level permissions for real enforcement)
- A complete defense for all path traversal vectors (e.g., symlinks)
- A substitute for chroot/jail at the OS level

Always resolve and validate paths at the tool implementation layer
using ``pathlib.Path.resolve()`` and checking against permitted
root directories.

Example
-------
::

    from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer

    sanitizer = PathSanitizer(allowed_base_dirs=["/workspace", "/data"])
    result = sanitizer.sanitize("../../etc/passwd")
    print(result.safe)   # False
    print(result.violations)  # ["Path traversal: '../' sequence detected"]
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

from trusted_mcp.sanitizers.base import Sanitizer, SanitizeResult

# Patterns for path traversal detection
_UNIX_TRAVERSAL = re.compile(r"\.\./")
_WINDOWS_TRAVERSAL = re.compile(r"\.\.[/\\]")
_ENCODED_TRAVERSAL = re.compile(
    r"(%2e%2e[%2f/\\]|\.\.%2f|%2e\.%2f|%252e%252e)",
    re.IGNORECASE,
)

# Sensitive Unix paths that should always be blocked
_SENSITIVE_UNIX_PATHS = re.compile(
    r"^(/etc/passwd|/etc/shadow|/etc/hosts|/proc/|/sys/|/dev/|/root/)",
    re.IGNORECASE,
)


class PathSanitizer(Sanitizer):
    """Blocks path traversal sequences and unauthorized absolute paths.

    Always rejects in ``reject`` mode — path sanitization by stripping
    is not supported because modifying a path changes its semantics in
    ways that are difficult to reason about safely.

    Parameters
    ----------
    allowed_base_dirs:
        Optional list of permitted base directory paths. If provided,
        absolute paths that do not start with any of these directories
        are blocked. If empty, no allowlist enforcement is applied.
    block_absolute:
        If True, block all absolute paths that are not in
        ``allowed_base_dirs``. If ``allowed_base_dirs`` is provided,
        this is effectively True for unlisted paths. Defaults to True.

    Thread Safety
    -------------
    Stateless — the same instance can handle concurrent requests.
    """

    def __init__(
        self,
        allowed_base_dirs: list[str] | None = None,
        block_absolute: bool = True,
    ) -> None:
        self._allowed_base_dirs: list[str] = [
            d.rstrip("/\\") for d in (allowed_base_dirs or [])
        ]
        self._block_absolute = block_absolute

    def _find_violations(self, value: str) -> list[str]:
        """Identify all path traversal violations in the value.

        Parameters
        ----------
        value:
            The path string to analyze.

        Returns
        -------
        list[str]
            Descriptions of detected violations.
        """
        violations: list[str] = []

        if _UNIX_TRAVERSAL.search(value):
            violations.append("Path traversal: '../' sequence detected")

        if _WINDOWS_TRAVERSAL.search(value):
            violations.append(r"Path traversal: '..\' sequence detected")

        if _ENCODED_TRAVERSAL.search(value):
            violations.append("Path traversal: URL-encoded traversal sequence detected")

        # Check for '..' without trailing separator (e.g., at end of path)
        if re.search(r"\.\.([\\/]|$)", value):
            if not any(v.startswith("Path traversal:") for v in violations):
                violations.append("Path traversal: '..' directory reference detected")

        if _SENSITIVE_UNIX_PATHS.match(value):
            violations.append(f"Path traversal: access to sensitive system path blocked")

        # Check absolute paths against allowlist
        is_absolute = value.startswith("/") or (
            len(value) >= 2 and value[1] == ":"
        )
        if is_absolute and not violations:
            if self._allowed_base_dirs:
                allowed = any(
                    value.startswith(base_dir) or value.startswith(base_dir + "/")
                    or value.startswith(base_dir + "\\")
                    for base_dir in self._allowed_base_dirs
                )
                if not allowed:
                    violations.append(
                        f"Path traversal: absolute path not in allowlist"
                    )
            elif self._block_absolute:
                violations.append(
                    "Path traversal: absolute path blocked (no allowlist configured)"
                )

        return violations

    def sanitize(self, value: str) -> SanitizeResult:
        """Check a path string for traversal attempts.

        Path sanitization always operates in reject mode — a path with
        traversal sequences is always rejected rather than modified,
        because stripping path components changes the intended target.

        Parameters
        ----------
        value:
            The path argument value to validate.

        Returns
        -------
        SanitizeResult
            ``safe=True`` if the path passes all checks.
            ``safe=False`` if any traversal or sensitive-path violation
            is detected.
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
