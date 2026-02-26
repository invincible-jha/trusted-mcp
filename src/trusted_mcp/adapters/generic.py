"""Generic adapter for trusted-mcp proxy.

Provides configuration generation for arbitrary MCP transports
(stdio and SSE) without IDE-specific assumptions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class StdioConfig:
    """Configuration for a stdio-based proxied MCP connection.

    Attributes
    ----------
    command:
        Command to start the trusted-mcp proxy.
    args:
        Arguments for the proxy command.
    env:
        Environment variables to set.
    """

    command: str
    args: list[str]
    env: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        """Convert to a dict suitable for JSON serialization."""
        return {"command": self.command, "args": self.args, "env": self.env}


@dataclass(frozen=True)
class SSEConfig:
    """Configuration for an SSE-based proxied MCP connection.

    Attributes
    ----------
    proxy_url:
        URL of the trusted-mcp proxy SSE endpoint.
    upstream_url:
        URL of the original MCP server SSE endpoint.
    """

    proxy_url: str
    upstream_url: str

    def to_dict(self) -> dict[str, object]:
        """Convert to a dict suitable for JSON serialization."""
        return {"url": self.proxy_url, "upstream": self.upstream_url}


class GenericAdapter:
    """Generic adapter for generating proxy configurations.

    Parameters
    ----------
    policy_path:
        Path to the trusted-mcp policy YAML file.
    proxy_host:
        Host for the SSE proxy server. Defaults to "127.0.0.1".
    proxy_port:
        Port for the SSE proxy server. Defaults to 8765.
    """

    def __init__(
        self,
        policy_path: str = "policy.yaml",
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8765,
    ) -> None:
        self.policy_path = policy_path
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def generate_stdio_config(
        self,
        upstream_command: str,
        upstream_args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> StdioConfig:
        """Generate stdio proxy configuration.

        Parameters
        ----------
        upstream_command:
            Command to start the upstream MCP server.
        upstream_args:
            Arguments for the upstream command.
        env:
            Environment variables.
        """
        args = [
            "proxy",
            "--config", self.policy_path,
            "--transport", "stdio",
            "--upstream-cmd", upstream_command,
        ]
        if upstream_args:
            args.extend(["--upstream-args", json.dumps(upstream_args)])

        return StdioConfig(
            command="trusted-mcp",
            args=args,
            env=env or {},
        )

    def generate_sse_config(
        self,
        upstream_url: str,
    ) -> SSEConfig:
        """Generate SSE proxy configuration.

        Parameters
        ----------
        upstream_url:
            URL of the upstream MCP server's SSE endpoint.
        """
        proxy_url = f"http://{self.proxy_host}:{self.proxy_port}/sse"
        return SSEConfig(proxy_url=proxy_url, upstream_url=upstream_url)

    def generate_launch_command(
        self,
        transport: str = "stdio",
        upstream_command: str = "",
        upstream_url: str = "",
        verbose: bool = False,
    ) -> list[str]:
        """Generate the command line to launch the proxy.

        Parameters
        ----------
        transport:
            "stdio" or "sse".
        upstream_command:
            For stdio: the upstream MCP server command.
        upstream_url:
            For SSE: the upstream MCP server URL.
        verbose:
            Enable verbose logging.
        """
        cmd = ["trusted-mcp", "proxy", "--config", self.policy_path, "--transport", transport]

        if transport == "stdio" and upstream_command:
            cmd.extend(["--upstream-cmd", upstream_command])
        elif transport == "sse" and upstream_url:
            cmd.extend(["--upstream", upstream_url])

        if verbose:
            cmd.append("--verbose")

        return cmd
