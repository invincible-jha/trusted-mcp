"""VS Code adapter for trusted-mcp proxy.

Generates .vscode/mcp.json configuration to route MCP server
connections through the trusted-mcp security proxy.
"""
from __future__ import annotations

import json
from pathlib import Path


class VSCodeAdapter:
    """Generates VS Code MCP configuration for trusted-mcp proxy.

    Parameters
    ----------
    policy_path:
        Path to the trusted-mcp policy YAML file.
    project_root:
        Root directory of the project. The .vscode/ directory will be
        created here.
    """

    def __init__(
        self,
        policy_path: str = "policy.yaml",
        project_root: str | Path = ".",
    ) -> None:
        self.policy_path = policy_path
        self.project_root = Path(project_root)

    def generate_server_config(
        self,
        server_name: str,
        original_command: str,
        original_args: list[str] | None = None,
    ) -> dict[str, object]:
        """Generate a proxied MCP server config for VS Code."""
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
            "type": "stdio",
        }

    def generate_config(
        self,
        servers: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        """Generate a complete .vscode/mcp.json configuration."""
        proxied: dict[str, object] = {}
        for name, original in servers.items():
            cmd = str(original.get("command", ""))
            args = original.get("args")
            arg_list = list(args) if isinstance(args, (list, tuple)) else None
            proxied[name] = self.generate_server_config(name, cmd, arg_list)
        return {"servers": proxied}

    def write_config(self, config: dict[str, object]) -> None:
        """Write configuration to .vscode/mcp.json."""
        config_dir = self.project_root / ".vscode"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "mcp.json"
        config_path.write_text(
            json.dumps(config, indent=2),
            encoding="utf-8",
        )

    def read_existing_config(self) -> dict[str, object]:
        """Read existing .vscode/mcp.json if present."""
        config_path = self.project_root / ".vscode" / "mcp.json"
        if not config_path.exists():
            return {}
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}
