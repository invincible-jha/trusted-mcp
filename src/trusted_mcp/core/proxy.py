"""TrustedMCPProxy — transparent MCP security proxy.

Sits between an MCP client (Claude Desktop, Cursor, VS Code, or any
custom client) and one or more upstream MCP servers, intercepting every
tool call and tool listing.

Architecture
------------
::

    MCP Client (Claude Desktop / Cursor / VS Code / custom)
        |
        v
    +-----------------------+
    |  TrustedMCPProxy      |  <-- this module
    |  - InterceptorChain   |
    |  - AuditLogger        |
    +-----------+-----------+
                |
                v (forwarded only if all scanners PASS)
    +-----------------------+
    |  Upstream MCP Server  |
    +-----------------------+

Supported Transports
--------------------
- stdio: Local subprocess MCP servers (most common for desktop clients).
- SSE:   Remote HTTP/SSE MCP servers.

What is NOT This Module
-----------------------
- Tool Trust Decay algorithm (not included in this package)
- Session-linking / cross-session correlation (not included in this package)
- Advanced threat intelligence feed integration (not included in this package)
- ML-based classifier inference (not included in this package)
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING

from trusted_mcp.core.exceptions import ProxyError
from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.policy import PolicyConfig, ProxyConfig, ScannerConfig, load_policy
from trusted_mcp.core.result import Action
from trusted_mcp.core.scanner import ToolCallRequest, ToolCallResponse, ToolDefinition

if TYPE_CHECKING:
    from trusted_mcp.audit.logger import AuditLogger

logger = logging.getLogger(__name__)


class UpstreamConnection:
    """Minimal abstraction over the upstream MCP server connection.

    In a full implementation this would wrap the mcp SDK's client
    session. Here it provides the interface that TrustedMCPProxy
    depends on, making it easy to swap in a real or mock connection.

    Parameters
    ----------
    server_name:
        Human-readable name for the upstream server.
    transport:
        "stdio" or "sse".
    upstream_url:
        URL for SSE transport; ignored for stdio.
    """

    def __init__(
        self,
        server_name: str,
        transport: str = "stdio",
        upstream_url: str | None = None,
    ) -> None:
        self.server_name = server_name
        self.transport = transport
        self.upstream_url = upstream_url
        self._connected = False

    async def connect(self) -> None:
        """Establish the connection to the upstream MCP server."""
        logger.info(
            "Connecting to upstream MCP server %r via %s",
            self.server_name,
            self.transport,
        )
        # Real implementation would use mcp.ClientSession here.
        self._connected = True

    async def disconnect(self) -> None:
        """Close the connection to the upstream MCP server."""
        self._connected = False
        logger.info("Disconnected from upstream MCP server %r", self.server_name)

    @property
    def is_connected(self) -> bool:
        """True if the connection is currently established."""
        return self._connected

    async def list_tools(self) -> list[ToolDefinition]:
        """Fetch the tool list from the upstream server.

        Returns
        -------
        list[ToolDefinition]
            All tool definitions advertised by the upstream server.
        """
        if not self._connected:
            raise ProxyError(f"Not connected to upstream server {self.server_name!r}")
        # Placeholder — real implementation calls mcp session list_tools()
        return []

    async def call_tool(
        self, request: ToolCallRequest, timeout_ms: int = 30000
    ) -> ToolCallResponse:
        """Forward a tool call to the upstream server.

        Parameters
        ----------
        request:
            The tool call request to forward.
        timeout_ms:
            Timeout in milliseconds.

        Returns
        -------
        ToolCallResponse
            The response from the upstream server.

        Raises
        ------
        ProxyError
            If the call fails or times out.
        """
        if not self._connected:
            raise ProxyError(f"Not connected to upstream server {self.server_name!r}")

        try:
            async with asyncio.timeout(timeout_ms / 1000):
                # Placeholder — real implementation calls mcp session call_tool()
                return ToolCallResponse(
                    tool_name=request.tool_name,
                    server_name=self.server_name,
                    content="",
                    request_id=request.request_id,
                )
        except TimeoutError as exc:
            raise ProxyError(
                f"Tool call to {request.tool_name!r} on {self.server_name!r} "
                f"timed out after {timeout_ms}ms"
            ) from exc


class TrustedMCPProxy:
    """Transparent MCP security proxy.

    Intercepts all tool_call requests and responses, runs them through
    the configured scanner chain, and either forwards to the upstream
    MCP server or blocks them.

    Parameters
    ----------
    policy:
        The loaded and validated policy configuration.
    audit_logger:
        Optional audit logger. If None, audit logging is disabled.
    upstream:
        Optional pre-constructed upstream connection. Used primarily
        in tests to inject a mock connection.

    Example
    -------
    ::

        from trusted_mcp.core.policy import load_policy
        from trusted_mcp.core.proxy import TrustedMCPProxy

        policy = load_policy("policy.yaml")
        proxy = TrustedMCPProxy(policy=policy)

        await proxy.start()
        # proxy is now running; stop with Ctrl+C or proxy.stop()
        await proxy.stop()
    """

    def __init__(
        self,
        policy: PolicyConfig,
        audit_logger: "AuditLogger | None" = None,
        upstream: UpstreamConnection | None = None,
    ) -> None:
        self._policy = policy
        self._audit_logger = audit_logger
        self._interceptor = InterceptorChain(policy.active_scanners())
        self._upstream = upstream
        self._running = False

    @classmethod
    def from_policy_file(cls, path: str) -> "TrustedMCPProxy":
        """Construct a proxy by loading a policy from a YAML file.

        Parameters
        ----------
        path:
            Path to the policy YAML file.

        Returns
        -------
        TrustedMCPProxy
            Configured proxy instance (not yet started).
        """
        policy = load_policy(path)
        return cls(policy=policy)

    @property
    def policy(self) -> PolicyConfig:
        """The active policy configuration."""
        return self._policy

    @property
    def interceptor(self) -> InterceptorChain:
        """The active interceptor chain."""
        return self._interceptor

    @property
    def is_running(self) -> bool:
        """True if the proxy is currently running."""
        return self._running

    async def start(self, transport: str | None = None) -> None:
        """Start the proxy and connect to the upstream MCP server.

        Parameters
        ----------
        transport:
            Override the policy's transport setting. "stdio" or "sse".

        Raises
        ------
        ProxyError
            If the proxy is already running or the upstream connection
            fails.
        """
        if self._running:
            raise ProxyError("Proxy is already running")

        effective_transport = transport or self._policy.proxy.transport

        if self._upstream is None:
            server_name = "upstream"
            self._upstream = UpstreamConnection(
                server_name=server_name,
                transport=effective_transport,
                upstream_url=self._policy.proxy.upstream,
            )

        try:
            await self._upstream.connect()
        except Exception as exc:
            raise ProxyError(f"Failed to connect to upstream MCP server: {exc}") from exc

        self._running = True
        logger.info(
            "TrustedMCPProxy started (transport=%s, policy=%s, scanners=%d)",
            effective_transport,
            self._policy.name,
            len(self._interceptor.scanners),
        )

    async def stop(self) -> None:
        """Stop the proxy and disconnect from the upstream server."""
        if not self._running:
            return

        if self._upstream is not None:
            await self._upstream.disconnect()

        self._running = False
        logger.info("TrustedMCPProxy stopped")

    async def handle_tool_call(self, request: ToolCallRequest) -> ToolCallResponse:
        """Intercept, scan, forward (or block) a tool call.

        This is the central hot path of the proxy.

        1. Assign a request ID if not present.
        2. Pre-scan the request arguments through the interceptor chain.
        3. If blocked, log and return a synthetic blocked response.
        4. Forward to the upstream MCP server.
        5. Post-scan the response through the interceptor chain.
        6. If response blocked, log and return a synthetic blocked response.
        7. Log the final result and return.

        Parameters
        ----------
        request:
            The incoming tool call request from the MCP client.

        Returns
        -------
        ToolCallResponse
            Either the upstream response or a synthetic blocked response.
        """
        if not request.request_id:
            request = request.model_copy(update={"request_id": str(uuid.uuid4())})

        if not self._running or self._upstream is None:
            raise ProxyError("Proxy is not running; call start() first")

        start_time = time.monotonic()

        # Step 1: Pre-scan request
        pre_result = await self._interceptor.scan_request(request)

        if pre_result.action == Action.BLOCK:
            latency_ms = (time.monotonic() - start_time) * 1000
            if self._audit_logger is not None:
                await self._audit_logger.log_blocked_request(
                    request=request,
                    chain_result=pre_result,
                    latency_ms=latency_ms,
                    policy_name=self._policy.name,
                )
            blocked_reason = pre_result.blocking_reason or "Request blocked by scanner"
            return ToolCallResponse.blocked(blocked_reason)

        # Step 2: Forward to upstream
        try:
            response = await self._upstream.call_tool(
                request, timeout_ms=self._policy.proxy.timeout_ms
            )
        except ProxyError:
            raise
        except Exception as exc:
            raise ProxyError(f"Upstream tool call failed: {exc}") from exc

        # Step 3: Post-scan response
        post_result = await self._interceptor.scan_response(request, response)

        latency_ms = (time.monotonic() - start_time) * 1000

        if post_result.action == Action.BLOCK:
            if self._audit_logger is not None:
                await self._audit_logger.log_blocked_response(
                    request=request,
                    response=response,
                    chain_result=post_result,
                    latency_ms=latency_ms,
                    policy_name=self._policy.name,
                )
            blocked_reason = post_result.blocking_reason or "Response blocked by scanner"
            return ToolCallResponse.blocked(blocked_reason)

        # Step 4: Audit log the passed call
        if self._audit_logger is not None:
            combined_warnings = pre_result.warnings + post_result.warnings
            final_action = Action.WARN if combined_warnings else Action.PASS
            await self._audit_logger.log_passed(
                request=request,
                response=response,
                pre_chain=pre_result,
                post_chain=post_result,
                latency_ms=latency_ms,
                policy_name=self._policy.name,
            )

        return response

    async def handle_tool_list(
        self, tools: list[ToolDefinition]
    ) -> list[ToolDefinition]:
        """Intercept a tool listing and verify descriptions.

        Runs scan_tool_description on all tools. Tools flagged as BLOCK
        are filtered out before returning to the client. Tools flagged
        as WARN are passed through with a log entry.

        Parameters
        ----------
        tools:
            Tool definitions from the upstream MCP server.

        Returns
        -------
        list[ToolDefinition]
            The filtered tool list — blocked tools are removed.
        """
        flagged = await self._interceptor.scan_tool_descriptions(tools)
        safe_tools: list[ToolDefinition] = []

        for tool in tools:
            tool_key = f"{tool.server_name}:{tool.name}"
            if tool_key in flagged:
                chain_result = flagged[tool_key]
                if chain_result.action == Action.BLOCK:
                    logger.warning(
                        "Tool %r from server %r BLOCKED (description hash change or policy): %s",
                        tool.name,
                        tool.server_name,
                        chain_result.blocking_reason,
                    )
                    continue  # Do not include in returned list
                else:
                    logger.warning(
                        "Tool %r from server %r has warnings: %s",
                        tool.name,
                        tool.server_name,
                        chain_result.warning_reasons(),
                    )

            safe_tools.append(tool)

        return safe_tools

    async def __aenter__(self) -> "TrustedMCPProxy":
        """Start the proxy as an async context manager."""
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Stop the proxy when the async context manager exits."""
        await self.stop()


def build_proxy_from_configs(
    scanner_configs: list[ScannerConfig],
    proxy_config: ProxyConfig | None = None,
) -> TrustedMCPProxy:
    """Build a TrustedMCPProxy from explicit config objects.

    Convenience factory used by tests and examples when constructing
    a PolicyConfig by hand rather than loading from a YAML file.

    Parameters
    ----------
    scanner_configs:
        List of scanner configurations to include in the chain.
    proxy_config:
        Proxy transport settings. If None, defaults are used.

    Returns
    -------
    TrustedMCPProxy
        Configured proxy (not yet started).
    """
    from trusted_mcp.core.policy import PolicyConfig

    policy = PolicyConfig(
        scanners=scanner_configs,
        proxy=proxy_config or ProxyConfig(),
    )
    return TrustedMCPProxy(policy=policy)
