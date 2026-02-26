"""Unit tests for trusted_mcp.core.scanner (ABC and Pydantic models)."""
from __future__ import annotations

import pytest

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import (
    Scanner,
    ToolCallRequest,
    ToolCallResponse,
    ToolDefinition,
)


# ---------------------------------------------------------------------------
# Concrete Scanner for testing the ABC contract
# ---------------------------------------------------------------------------

class MinimalScanner(Scanner):
    """Minimal concrete scanner that always passes."""

    name = "minimal"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.PASS, scanner_name=self.name)


class BlockingScanner(Scanner):
    """Concrete scanner that always blocks."""

    name = "blocking"

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        return ScanResult(action=Action.BLOCK, reason="always blocked", scanner_name=self.name)


# ---------------------------------------------------------------------------
# ToolCallRequest
# ---------------------------------------------------------------------------

class TestToolCallRequest:
    def test_minimum_construction(self) -> None:
        req = ToolCallRequest(tool_name="search", server_name="web")
        assert req.tool_name == "search"
        assert req.server_name == "web"
        assert req.arguments == {}
        assert req.request_id == ""
        assert req.raw_message is None

    def test_with_arguments(self) -> None:
        req = ToolCallRequest(
            tool_name="read_file",
            server_name="filesystem",
            arguments={"path": "/tmp/test.txt"},
        )
        assert req.arguments == {"path": "/tmp/test.txt"}

    def test_with_request_id(self) -> None:
        req = ToolCallRequest(
            tool_name="tool",
            server_name="server",
            request_id="abc-123",
        )
        assert req.request_id == "abc-123"

    def test_with_raw_message(self) -> None:
        raw = b'{"jsonrpc":"2.0"}'
        req = ToolCallRequest(
            tool_name="tool",
            server_name="server",
            raw_message=raw,
        )
        assert req.raw_message == raw

    def test_missing_tool_name_raises(self) -> None:
        with pytest.raises(Exception):
            ToolCallRequest(server_name="web")  # type: ignore[call-arg]

    def test_missing_server_name_raises(self) -> None:
        with pytest.raises(Exception):
            ToolCallRequest(tool_name="search")  # type: ignore[call-arg]

    def test_model_copy_preserves_values(self) -> None:
        req = ToolCallRequest(tool_name="t", server_name="s", request_id="old")
        new_req = req.model_copy(update={"request_id": "new"})
        assert new_req.request_id == "new"
        assert new_req.tool_name == "t"


# ---------------------------------------------------------------------------
# ToolCallResponse
# ---------------------------------------------------------------------------

class TestToolCallResponse:
    def test_minimum_construction(self) -> None:
        resp = ToolCallResponse(tool_name="search", server_name="web")
        assert resp.tool_name == "search"
        assert resp.server_name == "web"
        assert resp.content == ""
        assert resp.is_error is False
        assert resp.request_id == ""
        assert resp.blocked_reason is None

    def test_with_string_content(self) -> None:
        resp = ToolCallResponse(tool_name="t", server_name="s", content="hello")
        assert resp.content == "hello"

    def test_with_dict_content(self) -> None:
        resp = ToolCallResponse(tool_name="t", server_name="s", content={"key": "value"})
        assert resp.content == {"key": "value"}

    def test_with_list_content(self) -> None:
        resp = ToolCallResponse(tool_name="t", server_name="s", content=["a", "b"])
        assert resp.content == ["a", "b"]

    def test_error_response(self) -> None:
        resp = ToolCallResponse(tool_name="t", server_name="s", is_error=True, content="err")
        assert resp.is_error is True

    def test_blocked_factory_method(self) -> None:
        resp = ToolCallResponse.blocked("SQL injection detected")
        assert resp.is_error is True
        assert resp.blocked_reason == "SQL injection detected"
        assert resp.server_name == "trusted-mcp-proxy"
        assert isinstance(resp.content, dict)
        assert resp.content.get("error") == "blocked"
        assert resp.content.get("reason") == "SQL injection detected"

    def test_blocked_factory_empty_tool_name(self) -> None:
        resp = ToolCallResponse.blocked("reason")
        assert resp.tool_name == ""


# ---------------------------------------------------------------------------
# ToolDefinition
# ---------------------------------------------------------------------------

class TestToolDefinition:
    def test_minimum_construction(self) -> None:
        tool = ToolDefinition(name="search", server_name="web")
        assert tool.name == "search"
        assert tool.server_name == "web"
        assert tool.description == ""
        assert tool.input_schema == {}

    def test_with_description(self) -> None:
        tool = ToolDefinition(
            name="read_file",
            server_name="filesystem",
            description="Read a file from the filesystem",
        )
        assert tool.description == "Read a file from the filesystem"

    def test_with_input_schema(self) -> None:
        schema: dict[str, object] = {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }
        tool = ToolDefinition(name="t", server_name="s", input_schema=schema)
        assert tool.input_schema == schema


# ---------------------------------------------------------------------------
# Scanner ABC
# ---------------------------------------------------------------------------

class TestScannerABC:
    def test_cannot_instantiate_abstract_class(self) -> None:
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]

    def test_concrete_subclass_can_be_instantiated(self) -> None:
        scanner = MinimalScanner()
        assert scanner.name == "minimal"

    @pytest.mark.asyncio
    async def test_scan_request_abstract_must_be_implemented(self) -> None:
        scanner = MinimalScanner()
        req = ToolCallRequest(tool_name="t", server_name="s")
        result = await scanner.scan_request(req)
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_scan_response_default_returns_pass(self) -> None:
        scanner = MinimalScanner()
        req = ToolCallRequest(tool_name="t", server_name="s")
        resp = ToolCallResponse(tool_name="t", server_name="s")
        result = await scanner.scan_response(req, resp)
        assert result.action == Action.PASS
        assert result.scanner_name == "minimal"

    @pytest.mark.asyncio
    async def test_scan_tool_description_default_returns_pass(self) -> None:
        scanner = MinimalScanner()
        tool = ToolDefinition(name="t", server_name="s")
        result = await scanner.scan_tool_description(tool)
        assert result.action == Action.PASS
        assert result.scanner_name == "minimal"

    @pytest.mark.asyncio
    async def test_blocking_scanner_returns_block(self) -> None:
        scanner = BlockingScanner()
        req = ToolCallRequest(tool_name="t", server_name="s")
        result = await scanner.scan_request(req)
        assert result.action == Action.BLOCK
        assert result.reason == "always blocked"
