"""Convenience API for trusted-mcp — 3-line quickstart.

Example
-------
::

    from trusted_mcp import TrustedProxy
    proxy = TrustedProxy()
    # proxy is ready to use with default security policy

"""
from __future__ import annotations

from typing import Any

from trusted_mcp.core.policy import PolicyConfig, ProxyConfig, ScannerConfig
from trusted_mcp.core.proxy import TrustedMCPProxy


class TrustedProxy:
    """Zero-config wrapper around TrustedMCPProxy for the 80% use case.

    Provides a simple interface that works out-of-the-box with sensible
    defaults. Pass ``config_path`` to load a custom YAML policy file.

    Parameters
    ----------
    config_path:
        Optional path to a YAML policy file. If None, a default policy
        with PII scanning and regex scanning enabled is used.

    Example
    -------
    ::

        from trusted_mcp import TrustedProxy
        proxy = TrustedProxy()
        # or with a custom policy:
        proxy = TrustedProxy(config_path="my-policy.yaml")
    """

    def __init__(self, config_path: str | None = None) -> None:
        # Ensure all built-in scanners are registered with the global scanner_registry
        # before constructing the proxy.  The authoritative registry instance lives in
        # trusted_mcp.plugins.registry (used by InterceptorChain), NOT in
        # trusted_mcp.plugins.__init__ (a separate instance).
        from trusted_mcp.plugins.registry import scanner_registry
        from trusted_mcp.scanners.regex_scanner import BasicRegexScanner
        from trusted_mcp.scanners.allowlist_scanner import BasicAllowlistScanner
        from trusted_mcp.scanners.argument_scanner import BasicArgumentScanner
        from trusted_mcp.scanners.description_hash import DescriptionHashScanner
        from trusted_mcp.scanners.pii_scanner import BasicPIIScanner

        _builtins = [
            ("regex", BasicRegexScanner),
            ("allowlist", BasicAllowlistScanner),
            ("argument", BasicArgumentScanner),
            ("description_hash", DescriptionHashScanner),
            ("pii", BasicPIIScanner),
        ]
        for _scanner_name, _scanner_class in _builtins:
            if _scanner_name not in scanner_registry:
                scanner_registry.register_class(_scanner_name, _scanner_class)

        if config_path is not None:
            self._proxy = TrustedMCPProxy.from_policy_file(config_path)
        else:
            policy = PolicyConfig(
                name="quickstart-default",
                proxy=ProxyConfig(),
                scanners=[
                    ScannerConfig(
                        name="regex",
                        enabled=True,
                        settings={"sensitivity": "medium"},
                    ),
                    ScannerConfig(
                        name="pii",
                        enabled=True,
                        settings={
                            "action_on_detect": "warn",
                            "patterns": ["email", "phone", "credit_card"],
                        },
                    ),
                ],
            )
            self._proxy = TrustedMCPProxy(policy=policy)

    @property
    def proxy(self) -> TrustedMCPProxy:
        """The underlying TrustedMCPProxy instance."""
        return self._proxy

    @property
    def policy(self) -> PolicyConfig:
        """The active policy configuration."""
        return self._proxy.policy

    @property
    def is_running(self) -> bool:
        """True if the proxy is currently running."""
        return self._proxy.is_running

    def scan_request(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Synchronously scan a tool call request (convenience wrapper).

        Parameters
        ----------
        tool_name:
            Name of the tool being called.
        arguments:
            Arguments passed to the tool.

        Returns
        -------
        dict[str, Any]
            Result dict with ``action`` (PASS/WARN/BLOCK) and ``warnings``.
        """
        import asyncio
        from trusted_mcp.core.scanner import ToolCallRequest

        request = ToolCallRequest(
            tool_name=tool_name,
            server_name="quickstart",
            arguments=arguments,
        )
        chain_result = asyncio.run(self._proxy.interceptor.scan_request(request))
        return {
            "action": chain_result.action.value.upper(),
            "warnings": chain_result.warnings,
            "blocking_reason": chain_result.blocking_reason,
        }

    def __repr__(self) -> str:
        return (
            f"TrustedProxy(policy={self._proxy.policy.name!r}, "
            f"scanners={len(self._proxy.policy.active_scanners())})"
        )
