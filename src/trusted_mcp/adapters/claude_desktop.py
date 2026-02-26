"""Claude Desktop adapter for trusted-mcp proxy.

Generates and modifies claude_desktop_config.json to route MCP
server connections through the trusted-mcp security proxy.
"""
from __future__ import annotations

import json
import platform
from pathlib import Path


def _default_config_path() -> Path:
    """Return the default Claude Desktop config path for this OS."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if system == "Windows":
        return Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    # Linux / fallback
    return Path.home() / ".config" / "claude" / "claude_desktop_config.json"


class ClaudeDesktopAdapter:
    """Generates Claude Desktop configuration for trusted-mcp proxy.

    Parameters
    ----------
    policy_path:
        Path to the trusted-mcp policy YAML file.
    config_path:
        Path to claude_desktop_config.json. Auto-detected if not provided.
    """

    def __init__(
        self,
        policy_path: str = "policy.yaml",
        config_path: str | Path | None = None,
    ) -> None:
        self.policy_path = policy_path
        self.config_path = Path(config_path) if config_path else _default_config_path()

    def generate_server_config(
        self,
        server_name: str,
        original_command: str,
        original_args: list[str] | None = None,
    ) -> dict[str, object]:
        """Generate a single MCP server config that routes through the proxy.

        Parameters
        ----------
        server_name:
            Name of the MCP server.
        original_command:
            Original command to start the MCP server.
        original_args:
            Original arguments for the MCP server command.

        Returns
        -------
        dict
            Claude Desktop MCP server configuration entry.
        """
        proxy_args = [
            "proxy",
            "--config", self.policy_path,
            "--transport", "stdio",
            "--upstream-cmd", original_command,
        ]
        if original_args:
            proxy_args.extend(["--upstream-args", json.dumps(original_args)])

        return {
            "command": "trusted-mcp",
            "args": proxy_args,
            "env": {},
        }

    def generate_config(
        self,
        servers: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        """Generate a complete claude_desktop_config.json with proxy wrapping.

        Parameters
        ----------
        servers:
            Mapping of server_name → original server config dict.
            Each dict should have "command" and optionally "args" keys.

        Returns
        -------
        dict
            Complete Claude Desktop configuration.
        """
        proxied_servers: dict[str, object] = {}
        for name, original in servers.items():
            cmd = str(original.get("command", ""))
            args = original.get("args")
            arg_list = list(args) if isinstance(args, (list, tuple)) else None
            proxied_servers[name] = self.generate_server_config(
                server_name=name,
                original_command=cmd,
                original_args=arg_list,
            )
        return {"mcpServers": proxied_servers}

    def read_existing_config(self) -> dict[str, object]:
        """Read the existing Claude Desktop config file."""
        if not self.config_path.exists():
            return {}
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def write_config(self, config: dict[str, object]) -> None:
        """Write configuration to the Claude Desktop config file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(config, indent=2),
            encoding="utf-8",
        )
