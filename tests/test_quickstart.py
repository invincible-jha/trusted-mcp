"""Test that the 3-line quickstart API works for trusted-mcp."""
from __future__ import annotations


def test_quickstart_import() -> None:
    from trusted_mcp import TrustedProxy

    proxy = TrustedProxy()
    assert proxy is not None


def test_quickstart_has_policy() -> None:
    from trusted_mcp import TrustedProxy

    proxy = TrustedProxy()
    assert proxy.policy is not None
    assert proxy.policy.name == "quickstart-default"


def test_quickstart_not_running_by_default() -> None:
    from trusted_mcp import TrustedProxy

    proxy = TrustedProxy()
    assert proxy.is_running is False


def test_quickstart_scan_request_pass() -> None:
    from trusted_mcp import TrustedProxy

    proxy = TrustedProxy()
    result = proxy.scan_request("search", {"query": "Python type hints"})
    assert "action" in result
    assert result["action"] in ("PASS", "WARN", "BLOCK")


def test_quickstart_repr() -> None:
    from trusted_mcp import TrustedProxy

    proxy = TrustedProxy()
    text = repr(proxy)
    assert "TrustedProxy" in text
    assert "quickstart-default" in text


def test_quickstart_underlying_proxy() -> None:
    from trusted_mcp import TrustedProxy
    from trusted_mcp.core.proxy import TrustedMCPProxy

    proxy = TrustedProxy()
    assert isinstance(proxy.proxy, TrustedMCPProxy)
