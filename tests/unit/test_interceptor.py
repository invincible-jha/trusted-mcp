"""Unit tests for trusted_mcp.core.interceptor."""
from __future__ import annotations

import pytest

from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.result import Action, ChainResult, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition


# ---------------------------------------------------------------------------
# Test scanners
# ---------------------------------------------------------------------------

class PassScanner(Scanner):
    name = "pass_scanner"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.PASS, scanner_name=self.name)


class WarnScanner(Scanner):
    name = "warn_scanner"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.WARN, reason="suspicious", scanner_name=self.name)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        return ScanResult(action=Action.WARN, reason="response warning", scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        return ScanResult(action=Action.WARN, reason="description warning", scanner_name=self.name)


class BlockScanner(Scanner):
    name = "block_scanner"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.BLOCK, reason="blocked!", scanner_name=self.name)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        return ScanResult(action=Action.BLOCK, reason="response blocked!", scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        return ScanResult(action=Action.BLOCK, reason="description blocked!", scanner_name=self.name)


class ErrorScanner(Scanner):
    name = "error_scanner"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        raise RuntimeError("scanner internal error")


class NamelessResultScanner(Scanner):
    """Returns a ScanResult with scanner_name=None."""
    name = "nameless"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.PASS, scanner_name=None)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_request() -> ToolCallRequest:
    return ToolCallRequest(tool_name="search", server_name="web")


def _make_response() -> ToolCallResponse:
    return ToolCallResponse(tool_name="search", server_name="web", content="result")


def _make_tool() -> ToolDefinition:
    return ToolDefinition(name="search", server_name="web", description="Search the web")


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestInterceptorChainConstruction:
    def test_empty_scanner_list(self) -> None:
        chain = InterceptorChain(scanners=[])
        assert chain.scanners == []

    def test_scanners_property_returns_copy(self) -> None:
        scanner = PassScanner()
        chain = InterceptorChain(scanners=[scanner])
        scanners_copy = chain.scanners
        scanners_copy.clear()
        assert len(chain.scanners) == 1

    def test_add_scanner_appends_to_end(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner()])
        chain.add_scanner(WarnScanner())
        assert len(chain.scanners) == 2
        assert chain.scanners[1].name == "warn_scanner"

    def test_add_scanner_to_empty_chain(self) -> None:
        chain = InterceptorChain(scanners=[])
        chain.add_scanner(PassScanner())
        assert len(chain.scanners) == 1


# ---------------------------------------------------------------------------
# scan_request
# ---------------------------------------------------------------------------

class TestScanRequest:
    @pytest.mark.asyncio
    async def test_empty_chain_returns_pass(self) -> None:
        chain = InterceptorChain(scanners=[])
        result = await chain.scan_request(_make_request())
        assert result.action == Action.PASS
        assert result.all_results == []

    @pytest.mark.asyncio
    async def test_all_pass_returns_pass(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner(), PassScanner()])
        result = await chain.scan_request(_make_request())
        assert result.action == Action.PASS
        assert result.warnings == []

    @pytest.mark.asyncio
    async def test_one_warn_returns_warn(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner(), WarnScanner()])
        result = await chain.scan_request(_make_request())
        assert result.action == Action.WARN
        assert len(result.warnings) == 1
        assert result.warnings[0].reason == "suspicious"

    @pytest.mark.asyncio
    async def test_block_short_circuits_chain(self) -> None:
        execution_order: list[str] = []

        class OrderedPassScanner(Scanner):
            name = "ordered_pass"

            async def scan_request(self, request: ToolCallRequest) -> ScanResult:
                execution_order.append("pass")
                return ScanResult(action=Action.PASS, scanner_name=self.name)

        class OrderedBlockScanner(Scanner):
            name = "ordered_block"

            async def scan_request(self, request: ToolCallRequest) -> ScanResult:
                execution_order.append("block")
                return ScanResult(action=Action.BLOCK, reason="stop", scanner_name=self.name)

        class ShouldNotRunScanner(Scanner):
            name = "should_not_run"

            async def scan_request(self, request: ToolCallRequest) -> ScanResult:
                execution_order.append("should_not_run")
                return ScanResult(action=Action.PASS, scanner_name=self.name)

        chain = InterceptorChain(
            scanners=[OrderedPassScanner(), OrderedBlockScanner(), ShouldNotRunScanner()]
        )
        result = await chain.scan_request(_make_request())
        assert result.action == Action.BLOCK
        assert result.blocking_scanner == "ordered_block"
        assert result.blocking_reason == "stop"
        assert "should_not_run" not in execution_order

    @pytest.mark.asyncio
    async def test_block_result_contains_accumulated_warnings(self) -> None:
        chain = InterceptorChain(scanners=[WarnScanner(), BlockScanner()])
        result = await chain.scan_request(_make_request())
        assert result.action == Action.BLOCK
        assert len(result.warnings) == 1
        assert result.warnings[0].scanner_name == "warn_scanner"

    @pytest.mark.asyncio
    async def test_all_results_tracked(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner(), WarnScanner()])
        result = await chain.scan_request(_make_request())
        assert len(result.all_results) == 2

    @pytest.mark.asyncio
    async def test_scanner_error_treated_as_warn(self) -> None:
        chain = InterceptorChain(scanners=[ErrorScanner()])
        result = await chain.scan_request(_make_request())
        assert result.action == Action.WARN
        assert len(result.warnings) == 1
        assert "internal error" in result.warnings[0].reason

    @pytest.mark.asyncio
    async def test_scanner_error_does_not_stop_chain(self) -> None:
        chain = InterceptorChain(scanners=[ErrorScanner(), PassScanner()])
        result = await chain.scan_request(_make_request())
        # ErrorScanner adds a WARN; PassScanner adds a PASS
        # Final action should be WARN due to accumulated error warning
        assert result.action == Action.WARN

    @pytest.mark.asyncio
    async def test_nameless_result_gets_scanner_name_injected(self) -> None:
        chain = InterceptorChain(scanners=[NamelessResultScanner()])
        result = await chain.scan_request(_make_request())
        assert result.all_results[0].scanner_name == "nameless"

    @pytest.mark.asyncio
    async def test_multiple_warns_all_accumulated(self) -> None:
        chain = InterceptorChain(
            scanners=[WarnScanner(), WarnScanner(), WarnScanner()]
        )
        result = await chain.scan_request(_make_request())
        assert result.action == Action.WARN
        assert len(result.warnings) == 3


# ---------------------------------------------------------------------------
# scan_response
# ---------------------------------------------------------------------------

class TestScanResponse:
    @pytest.mark.asyncio
    async def test_empty_chain_returns_pass(self) -> None:
        chain = InterceptorChain(scanners=[])
        result = await chain.scan_response(_make_request(), _make_response())
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_warn_response_accumulated(self) -> None:
        chain = InterceptorChain(scanners=[WarnScanner()])
        result = await chain.scan_response(_make_request(), _make_response())
        assert result.action == Action.WARN
        assert result.warnings[0].reason == "response warning"

    @pytest.mark.asyncio
    async def test_block_response_short_circuits(self) -> None:
        chain = InterceptorChain(scanners=[BlockScanner()])
        result = await chain.scan_response(_make_request(), _make_response())
        assert result.action == Action.BLOCK
        assert result.blocking_reason == "response blocked!"


# ---------------------------------------------------------------------------
# scan_tool_descriptions
# ---------------------------------------------------------------------------

class TestScanToolDescriptions:
    @pytest.mark.asyncio
    async def test_empty_tools_returns_empty_dict(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner()])
        result = await chain.scan_tool_descriptions([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_all_pass_returns_empty_dict(self) -> None:
        chain = InterceptorChain(scanners=[PassScanner()])
        tools = [_make_tool()]
        result = await chain.scan_tool_descriptions(tools)
        assert result == {}

    @pytest.mark.asyncio
    async def test_warn_tool_included_in_result(self) -> None:
        chain = InterceptorChain(scanners=[WarnScanner()])
        tools = [_make_tool()]
        result = await chain.scan_tool_descriptions(tools)
        assert "web:search" in result
        assert result["web:search"].action == Action.WARN

    @pytest.mark.asyncio
    async def test_block_tool_included_in_result(self) -> None:
        chain = InterceptorChain(scanners=[BlockScanner()])
        tools = [_make_tool()]
        result = await chain.scan_tool_descriptions(tools)
        assert "web:search" in result
        assert result["web:search"].action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_tool_key_format_server_colon_name(self) -> None:
        chain = InterceptorChain(scanners=[WarnScanner()])
        tool = ToolDefinition(name="my_tool", server_name="my_server", description="desc")
        result = await chain.scan_tool_descriptions([tool])
        assert "my_server:my_tool" in result

    @pytest.mark.asyncio
    async def test_multiple_tools_each_evaluated(self) -> None:
        chain = InterceptorChain(scanners=[WarnScanner()])
        tools = [
            ToolDefinition(name="tool_a", server_name="srv", description="d"),
            ToolDefinition(name="tool_b", server_name="srv", description="d"),
        ]
        result = await chain.scan_tool_descriptions(tools)
        assert "srv:tool_a" in result
        assert "srv:tool_b" in result
