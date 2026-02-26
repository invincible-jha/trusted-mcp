"""Scanner abstract base class and MCP data models.

This module defines:

- The plugin boundary: Scanner ABC that all scanner implementations must satisfy.
- Pydantic v2 models for MCP tool call requests, responses, and tool definitions.

Writing a Custom Scanner
------------------------
::

    from trusted_mcp.core.scanner import Scanner, ScanResult, Action

    class MyScanner(Scanner):
        name = "my_scanner"

        async def scan_request(self, request: ToolCallRequest) -> ScanResult:
            if is_suspicious(request.arguments):
                return ScanResult(action=Action.BLOCK, reason="Suspicious argument")
            return ScanResult(action=Action.PASS)

    # Register with the global scanner registry
    from trusted_mcp.plugins.registry import scanner_registry
    scanner_registry.register_class("my_scanner", MyScanner)

What is NOT in this module
--------------------------
- Tool Trust Decay algorithm (not included in this package)
- ML-based prompt injection classifier (not included in this package)
- Session-linking / cross-session attack correlation (not included in this package)
- Behavioral drift detection (not included in this package)
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from trusted_mcp.core.result import Action, ScanResult


class ToolCallRequest(BaseModel):
    """Pydantic model representing an outgoing MCP tool call request.

    Attributes
    ----------
    tool_name:
        The name of the tool being called.
    server_name:
        The name of the MCP server that owns the tool.
    arguments:
        The arguments passed to the tool, as a key/value mapping.
    request_id:
        A unique identifier for this request (UUID recommended).
    raw_message:
        The raw MCP protocol message bytes, if available.
    """

    tool_name: str
    server_name: str
    arguments: dict[str, object] = Field(default_factory=dict)
    request_id: str = ""
    raw_message: bytes | None = None

    model_config = {"arbitrary_types_allowed": False}


class ToolCallResponse(BaseModel):
    """Pydantic model representing an incoming MCP tool call response.

    Attributes
    ----------
    tool_name:
        The name of the tool that was called.
    server_name:
        The name of the MCP server that executed the tool.
    content:
        The response content returned by the tool.
    is_error:
        True if the tool returned an error result.
    request_id:
        The request ID this response corresponds to.
    blocked_reason:
        If the proxy itself blocked this response, the reason is stored here.
    """

    tool_name: str
    server_name: str
    content: str | dict[str, object] | list[object] = ""
    is_error: bool = False
    request_id: str = ""
    blocked_reason: str | None = None

    model_config = {"arbitrary_types_allowed": False}

    @classmethod
    def blocked(cls, reason: str) -> "ToolCallResponse":
        """Create a synthetic blocked response for a tool call.

        Parameters
        ----------
        reason:
            The human-readable reason the tool call was blocked.

        Returns
        -------
        ToolCallResponse
            A response indicating the call was blocked by the proxy.
        """
        return cls(
            tool_name="",
            server_name="trusted-mcp-proxy",
            content={"error": "blocked", "reason": reason},
            is_error=True,
            blocked_reason=reason,
        )


class ToolDefinition(BaseModel):
    """Pydantic model representing an MCP tool definition from a server.

    Attributes
    ----------
    name:
        The tool's registered name.
    server_name:
        The MCP server that provides this tool.
    description:
        The human-readable description (used by the LLM to decide when
        to call the tool — the primary target of tool poisoning attacks).
    input_schema:
        JSON Schema object describing the tool's expected arguments.
    """

    name: str
    server_name: str
    description: str = ""
    input_schema: dict[str, object] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": False}


class Scanner(ABC):
    """Abstract base class for all trusted-mcp security scanners.

    This is the plugin boundary. All built-in commodity scanners in
    trusted_mcp.scanners and all plugin scanners in downstream
    packages must subclass Scanner and implement at minimum
    scan_request().

    Class Attributes
    ----------------
    name:
        A unique string identifier for this scanner. Used in policy
        YAML and in audit log entries. Must be overridden by subclasses.

    Methods
    -------
    scan_request(request):
        Required. Called before a tool call is forwarded upstream.
    scan_response(request, response):
        Optional. Called after the upstream response arrives.
        Default implementation returns PASS.
    scan_tool_description(tool):
        Optional. Called when the proxy fetches the tool list from
        the upstream server. Default implementation returns PASS.

    What is NOT This Class
    ----------------------
    This ABC defines only the commodity plugin boundary. It is NOT:
    - A reasoning-layer invariant analyser
    - An ML-based trained model classifier
    - A cross-session attack correlation engine
    - Additional scanner implementations available via plugins
    """

    name: str = "base"

    @abstractmethod
    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Scan an outgoing tool call request.

        Called before the tool call is forwarded to the upstream MCP
        server. Returning BLOCK prevents the call entirely.

        Parameters
        ----------
        request:
            The tool call request to evaluate.

        Returns
        -------
        ScanResult
            PASS to allow, WARN to allow with a logged warning, or
            BLOCK to stop the call.
        """
        ...

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        """Scan an incoming tool call response.

        Called after the upstream MCP server returns a response.
        Returning BLOCK replaces the response with a blocked error before
        it reaches the LLM.

        Parameters
        ----------
        request:
            The original tool call request.
        response:
            The response returned by the upstream server.

        Returns
        -------
        ScanResult
            Default implementation always returns PASS.
        """
        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Scan a tool definition for poisoning or tampering.

        Called when the proxy fetches the tool list from an upstream
        server, before the definitions are forwarded to the client.

        Parameters
        ----------
        tool:
            The tool definition to evaluate.

        Returns
        -------
        ScanResult
            Default implementation always returns PASS.
        """
        return ScanResult(action=Action.PASS, scanner_name=self.name)
