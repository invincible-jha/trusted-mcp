"""Unit tests for trusted_mcp.core.interceptor — extended coverage."""
from __future__ import annotations

import asyncio

import pytest

from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.result import Action, ChainResult, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


def _request(
    tool_name: str = "t",
    server_name: str = "s",
    arguments: dict[str, object] | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=tool_name,
        server_name=server_name,
        arguments=arguments or {},
    )


def _response(
    content: object = "ok",
    tool_name: str = "t",
    server_name: str = "s",
) -> ToolCallResponse:
    return ToolCallResponse(tool_name=tool_name, server_name=server_name, content=content)


def _tool(
    name: str = "tool",
    server_name: str = "srv",
    description: str = "desc",
) -> ToolDefinition:
    return ToolDefinition(name=name, server_name=server_name, description=description)


class _StaticScanner(Scanner):
    """Scanner that always returns a preset result."""

    def __init__(
        self,
        action: Action = Action.PASS,
        reason: str = "",
        name: str = "static",
    ) -> None:
        self._action = action
        self._reason = reason
        self.name = name

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=self._action, reason=self._reason, scanner_name=self.name)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        return ScanResult(action=self._action, reason=self._reason, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        return ScanResult(action=self._action, reason=self._reason, scanner_name=self.name)


class _ExplodingScanner(Scanner):
    """Scanner that always raises."""

    def __init__(self, name: str = "exploding") -> None:
        self.name = name

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        raise RuntimeError(f"{self.name} exploded during scan_request")

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        raise RuntimeError(f"{self.name} exploded during scan_response")

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        raise RuntimeError(f"{self.name} exploded during scan_tool_description")


class _NullNameScanner(Scanner):
    """Scanner whose ScanResult has scanner_name=None to exercise the rename path."""

    def __init__(self, action: Action = Action.PASS, name: str = "null-name") -> None:
        self._action = action
        self.name = name

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=self._action, scanner_name=None)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        return ScanResult(action=self._action, scanner_name=None)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        return ScanResult(action=self._action, scanner_name=None)


# ---------------------------------------------------------------------------
# InterceptorChain — scan_request
# ---------------------------------------------------------------------------

class TestInterceptorChainScanRequest:
    def test_empty_chain_returns_pass(self) -> None:
        chain = InterceptorChain(scanners=[])
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.PASS

    def test_all_pass_returns_pass(self) -> None:
        chain = InterceptorChain(
            scanners=[_StaticScanner(Action.PASS), _StaticScanner(Action.PASS)]
        )
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.PASS

    def test_warn_scanner_accumulates_warning(self) -> None:
        chain = InterceptorChain(
            scanners=[
                _StaticScanner(Action.WARN, "soft issue"),
                _StaticScanner(Action.PASS),
            ]
        )
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.WARN
        assert len(result.warnings) == 1

    def test_block_scanner_short_circuits(self) -> None:
        runs: list[str] = []

        class TrackingScanner(Scanner):
            def __init__(self, name: str) -> None:
                self.name = name

            async def scan_request(self, request: ToolCallRequest) -> ScanResult:
                runs.append(self.name)
                return ScanResult(action=Action.PASS, scanner_name=self.name)

        chain = InterceptorChain(
            scanners=[
                _StaticScanner(Action.BLOCK, "blocked!", "blocker"),
                TrackingScanner("should-not-run"),
            ]
        )
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.BLOCK
        assert result.blocking_scanner == "blocker"
        assert "should-not-run" not in runs

    def test_block_returns_blocking_reason(self) -> None:
        chain = InterceptorChain(
            scanners=[_StaticScanner(Action.BLOCK, "reason-text", "blocker")]
        )
        result = _run(chain.scan_request(_request()))
        assert result.blocking_reason == "reason-text"

    def test_exploding_scanner_treated_as_warn(self) -> None:
        chain = InterceptorChain(scanners=[_ExplodingScanner()])
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.WARN
        assert len(result.warnings) == 1

    def test_null_scanner_name_is_filled_in(self) -> None:
        chain = InterceptorChain(
            scanners=[_NullNameScanner(Action.PASS, "renamed")]
        )
        result = _run(chain.scan_request(_request()))
        names = [r.scanner_name for r in result.all_results]
        assert "renamed" in names

    def test_all_results_contains_all_scanner_outputs(self) -> None:
        chain = InterceptorChain(
            scanners=[
                _StaticScanner(Action.PASS, name="s1"),
                _StaticScanner(Action.WARN, name="s2"),
            ]
        )
        result = _run(chain.scan_request(_request()))
        assert len(result.all_results) == 2

    def test_add_scanner_appends_to_chain(self) -> None:
        chain = InterceptorChain(scanners=[])
        chain.add_scanner(_StaticScanner(Action.WARN, "added-warn", "added"))
        result = _run(chain.scan_request(_request()))
        assert result.action == Action.WARN

    def test_scanners_property_returns_copy(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner()])
        scanners = chain.scanners
        scanners.clear()
        assert len(chain.scanners) == 1


# ---------------------------------------------------------------------------
# InterceptorChain — scan_response
# ---------------------------------------------------------------------------

class TestInterceptorChainScanResponse:
    def test_empty_chain_returns_pass(self) -> None:
        chain = InterceptorChain(scanners=[])
        result = _run(chain.scan_response(_request(), _response()))
        assert result.action == Action.PASS

    def test_warn_accumulates(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner(Action.WARN, "pii found")])
        result = _run(chain.scan_response(_request(), _response()))
        assert result.action == Action.WARN

    def test_block_short_circuits_response(self) -> None:
        chain = InterceptorChain(
            scanners=[
                _StaticScanner(Action.BLOCK, "blocked-resp", "resp-blocker"),
                _StaticScanner(Action.PASS),
            ]
        )
        result = _run(chain.scan_response(_request(), _response()))
        assert result.action == Action.BLOCK
        assert result.blocking_scanner == "resp-blocker"
        assert len(result.all_results) == 1

    def test_exploding_scanner_response_treated_as_warn(self) -> None:
        chain = InterceptorChain(scanners=[_ExplodingScanner()])
        result = _run(chain.scan_response(_request(), _response()))
        assert result.action == Action.WARN

    def test_null_scanner_name_filled_in_response(self) -> None:
        chain = InterceptorChain(
            scanners=[_NullNameScanner(Action.WARN, "resp-null")]
        )
        result = _run(chain.scan_response(_request(), _response()))
        names = [r.scanner_name for r in result.all_results]
        assert "resp-null" in names


# ---------------------------------------------------------------------------
# InterceptorChain — scan_tool_descriptions
# ---------------------------------------------------------------------------

class TestInterceptorChainScanToolDescriptions:
    def test_empty_tools_returns_empty_dict(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner(Action.PASS)])
        result = _run(chain.scan_tool_descriptions([]))
        assert result == {}

    def test_all_pass_returns_empty_flagged_dict(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner(Action.PASS)])
        tools = [_tool("t1"), _tool("t2")]
        result = _run(chain.scan_tool_descriptions(tools))
        assert result == {}

    def test_warn_tool_included_in_flagged(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner(Action.WARN, "new tool")])
        tools = [_tool("t1", "srv")]
        result = _run(chain.scan_tool_descriptions(tools))
        assert "srv:t1" in result
        assert result["srv:t1"].action == Action.WARN

    def test_block_tool_included_in_flagged(self) -> None:
        chain = InterceptorChain(
            scanners=[_StaticScanner(Action.BLOCK, "rug pull!", "hash-scanner")]
        )
        tools = [_tool("danger", "evil_srv")]
        result = _run(chain.scan_tool_descriptions(tools))
        assert "evil_srv:danger" in result
        assert result["evil_srv:danger"].action == Action.BLOCK

    def test_block_short_circuits_per_tool(self) -> None:
        runs: list[str] = []

        class TrackingScanner(Scanner):
            def __init__(self, name: str) -> None:
                self.name = name

            async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
                runs.append(self.name)
                return ScanResult(action=Action.PASS, scanner_name=self.name)

            async def scan_request(self, request: ToolCallRequest) -> ScanResult:
                return ScanResult(action=Action.PASS, scanner_name=self.name)

            async def scan_response(
                self, request: ToolCallRequest, response: ToolCallResponse
            ) -> ScanResult:
                return ScanResult(action=Action.PASS, scanner_name=self.name)

        chain = InterceptorChain(
            scanners=[
                _StaticScanner(Action.BLOCK, "blocked", "blocker"),
                TrackingScanner("should-not-run"),
            ]
        )
        _run(chain.scan_tool_descriptions([_tool()]))
        assert "should-not-run" not in runs

    def test_exploding_scanner_in_tool_description_treated_as_warn(self) -> None:
        chain = InterceptorChain(scanners=[_ExplodingScanner()])
        tools = [_tool("t")]
        result = _run(chain.scan_tool_descriptions(tools))
        assert "srv:t" in result
        assert result["srv:t"].action == Action.WARN

    def test_null_scanner_name_filled_in_tool_description(self) -> None:
        chain = InterceptorChain(
            scanners=[_NullNameScanner(Action.WARN, "td-null")]
        )
        tools = [_tool("t", "srv")]
        result = _run(chain.scan_tool_descriptions(tools))
        entry = result["srv:t"]
        names = [r.scanner_name for r in entry.all_results]
        assert "td-null" in names

    def test_multiple_tools_independently_evaluated(self) -> None:
        chain = InterceptorChain(scanners=[_StaticScanner(Action.WARN)])
        tools = [_tool("t1", "s"), _tool("t2", "s"), _tool("t3", "s")]
        result = _run(chain.scan_tool_descriptions(tools))
        assert len(result) == 3
