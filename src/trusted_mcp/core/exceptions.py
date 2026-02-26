"""Custom exception hierarchy for trusted-mcp.

All exceptions raised by the trusted-mcp library derive from
TrustedMCPError, making it easy for callers to catch any library
error with a single except clause.

Example
-------
::

    from trusted_mcp.core.exceptions import TrustedMCPError, PolicyError

    try:
        proxy.load_policy("nonexistent.yaml")
    except PolicyError as exc:
        print(f"Policy load failed: {exc}")
    except TrustedMCPError as exc:
        print(f"General library error: {exc}")
"""
from __future__ import annotations


class TrustedMCPError(Exception):
    """Base exception for all trusted-mcp errors.

    All exceptions raised by the trusted-mcp library are subclasses
    of this base, so callers can catch any library error with::

        except TrustedMCPError:
            ...
    """


class ScannerError(TrustedMCPError):
    """Raised when a scanner encounters an internal error during scanning.

    This is distinct from a BLOCK result — it means the scanner itself
    failed to execute (e.g., a regex compile error, corrupted pattern
    file, or unexpected exception inside the scanner logic).
    """


class PolicyError(TrustedMCPError):
    """Raised when a policy file is invalid, missing, or cannot be parsed.

    Covers YAML parse errors, schema validation failures, and missing
    required policy fields.
    """


class ProxyError(TrustedMCPError):
    """Raised when the proxy server encounters a transport or lifecycle error.

    Covers connection failures to the upstream MCP server, transport
    negotiation errors, and proxy startup/shutdown failures.
    """


class ConfigError(TrustedMCPError):
    """Raised when configuration is invalid or missing required fields.

    Covers environment variable parsing errors, invalid types in config
    values, and conflicting configuration options.
    """


class ScannerNotFoundError(TrustedMCPError):
    """Raised when a requested scanner name is not in the registry.

    Parameters
    ----------
    name:
        The scanner name that was not found.
    available:
        List of currently registered scanner names.
    """

    def __init__(self, name: str, available: list[str]) -> None:
        self.scanner_name = name
        self.available = available
        available_str = ", ".join(repr(n) for n in sorted(available)) if available else "(none)"
        super().__init__(
            f"Scanner {name!r} is not registered. Available scanners: {available_str}. "
            "Install a plugin package or register the scanner manually via "
            "ScannerRegistry.register_class()."
        )


class AuditError(TrustedMCPError):
    """Raised when the audit logging system encounters an error.

    Covers file write failures, storage backend connection errors,
    and log rotation failures.
    """
