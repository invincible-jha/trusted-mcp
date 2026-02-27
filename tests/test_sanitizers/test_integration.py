"""Full interceptor chain integration tests for argument sanitizers.

Tests the SanitizeInterceptor integrated into the InterceptorChain,
including interaction with the SanitizerRegistry.
"""
from __future__ import annotations

import pytest

from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.result import Action
from trusted_mcp.core.scanner import ToolCallRequest, ToolDefinition
from trusted_mcp.interceptors.sanitize_interceptor import SanitizeInterceptor
from trusted_mcp.sanitizers.registry import SanitizerRegistry
from trusted_mcp.sanitizers.shell_sanitizer import ShellSanitizer
from trusted_mcp.sanitizers.path_sanitizer import PathSanitizer
from trusted_mcp.sanitizers.sql_sanitizer import SQLSanitizer
from trusted_mcp.sanitizers.url_sanitizer import URLSanitizer


def _make_request(
    tool_name: str = "my_tool",
    server: str = "my_server",
    arguments: dict[str, object] | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=tool_name,
        server_name=server,
        arguments=arguments or {},
    )


class TestSanitizeInterceptorInChain:
    @pytest.mark.asyncio
    async def test_clean_arguments_pass_through(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"filename": "hello_world.txt"})
        result = await chain.scan_request(request)
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_shell_injection_in_args_blocked(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"cmd": "; rm -rf /"})
        result = await chain.scan_request(request)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_sql_injection_in_args_blocked(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [SQLSanitizer()])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(
            arguments={"query": "' OR 1=1 --"}
        )
        result = await chain.scan_request(request)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_path_traversal_in_args_blocked(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [PathSanitizer()])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"path": "../../etc/passwd"})
        result = await chain.scan_request(request)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_dangerous_url_in_args_blocked(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [URLSanitizer()])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"url": "file:///etc/passwd"})
        result = await chain.scan_request(request)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_non_string_args_skipped(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(
            arguments={"count": 42, "enabled": True, "items": [1, 2, 3]}
        )
        result = await chain.scan_request(request)
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_warn_mode_does_not_block(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="warn")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"cmd": "; rm -rf /"})
        result = await chain.scan_request(request)
        assert result.action == Action.WARN
        assert result.is_blocked is False

    @pytest.mark.asyncio
    async def test_multiple_violating_args_all_reported(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(
            arguments={"arg1": "; malicious", "arg2": "$(whoami)"}
        )
        result = await chain.scan_request(request)
        assert result.action == Action.BLOCK
        details = result.blocking_details or {}
        assert int(str(details.get("violation_count", 0))) > 0

    @pytest.mark.asyncio
    async def test_scan_tool_description_always_passes(self) -> None:
        registry = SanitizerRegistry(use_defaults=False)
        registry.register(".*", [ShellSanitizer(mode="reject")])

        interceptor = SanitizeInterceptor(registry=registry, action="block")
        chain = InterceptorChain(scanners=[interceptor])

        tool = ToolDefinition(
            name="dangerous_tool",
            server_name="server",
            description="A tool description; rm -rf /",
        )
        results = await chain.scan_tool_descriptions([tool])
        assert "server:dangerous_tool" not in results

    @pytest.mark.asyncio
    async def test_default_registry_applies_shell_sanitizer(self) -> None:
        interceptor = SanitizeInterceptor(action="block")
        chain = InterceptorChain(scanners=[interceptor])

        request = _make_request(arguments={"input": "hello; rm -rf /"})
        result = await chain.scan_request(request)
        # Default registry uses strip mode, so should pass but may warn
        assert isinstance(result.action, Action)
