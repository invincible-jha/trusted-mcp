"""Unit tests for trusted_mcp adapter modules.

Covers:
- adapters.claude_desktop — ClaudeDesktopAdapter
- adapters.cursor         — CursorAdapter
- adapters.vscode         — VSCodeAdapter
- adapters.generic        — GenericAdapter, StdioConfig, SSEConfig
"""
from __future__ import annotations

import json
import platform
from pathlib import Path

import pytest

from trusted_mcp.adapters.claude_desktop import ClaudeDesktopAdapter, _default_config_path
from trusted_mcp.adapters.cursor import CursorAdapter
from trusted_mcp.adapters.generic import GenericAdapter, SSEConfig, StdioConfig
from trusted_mcp.adapters.vscode import VSCodeAdapter


# ---------------------------------------------------------------------------
# _default_config_path
# ---------------------------------------------------------------------------

class TestDefaultConfigPath:
    def test_returns_path_object(self) -> None:
        path = _default_config_path()
        assert isinstance(path, Path)

    def test_path_ends_with_json(self) -> None:
        path = _default_config_path()
        assert path.suffix == ".json"


# ---------------------------------------------------------------------------
# ClaudeDesktopAdapter
# ---------------------------------------------------------------------------

class TestClaudeDesktopAdapter:
    def test_default_policy_path(self) -> None:
        adapter = ClaudeDesktopAdapter()
        assert adapter.policy_path == "policy.yaml"

    def test_custom_config_path(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "claude_desktop_config.json"
        adapter = ClaudeDesktopAdapter(config_path=custom_path)
        assert adapter.config_path == custom_path

    def test_generate_server_config_no_args(self) -> None:
        adapter = ClaudeDesktopAdapter(policy_path="my-policy.yaml")
        config = adapter.generate_server_config("my-server", "uvx")
        assert config["command"] == "trusted-mcp"
        args = config["args"]
        assert "--upstream-cmd" in args
        assert "uvx" in args
        assert "--upstream-args" not in args

    def test_generate_server_config_with_args(self) -> None:
        adapter = ClaudeDesktopAdapter(policy_path="my-policy.yaml")
        config = adapter.generate_server_config(
            "my-server", "npx", ["@modelcontextprotocol/server-brave-search"]
        )
        args = config["args"]
        assert "--upstream-args" in args
        idx = args.index("--upstream-args")
        parsed = json.loads(args[idx + 1])
        assert parsed == ["@modelcontextprotocol/server-brave-search"]

    def test_generate_config_wraps_all_servers(self) -> None:
        adapter = ClaudeDesktopAdapter()
        servers = {
            "server-a": {"command": "uvx", "args": ["mcp-a"]},
            "server-b": {"command": "node", "args": []},
        }
        config = adapter.generate_config(servers)
        assert "mcpServers" in config
        assert "server-a" in config["mcpServers"]
        assert "server-b" in config["mcpServers"]

    def test_generate_config_server_without_args(self) -> None:
        adapter = ClaudeDesktopAdapter()
        servers = {"s1": {"command": "cmd"}}
        config = adapter.generate_config(servers)
        server_cfg = config["mcpServers"]["s1"]
        assert server_cfg["command"] == "trusted-mcp"

    def test_read_existing_config_returns_empty_when_file_absent(
        self, tmp_path: Path
    ) -> None:
        adapter = ClaudeDesktopAdapter(config_path=tmp_path / "nonexistent.json")
        assert adapter.read_existing_config() == {}

    def test_read_existing_config_parses_valid_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"key": "value"}), encoding="utf-8")
        adapter = ClaudeDesktopAdapter(config_path=config_file)
        result = adapter.read_existing_config()
        assert result == {"key": "value"}

    def test_read_existing_config_returns_empty_for_invalid_json(
        self, tmp_path: Path
    ) -> None:
        config_file = tmp_path / "bad.json"
        config_file.write_text("{bad json", encoding="utf-8")
        adapter = ClaudeDesktopAdapter(config_path=config_file)
        assert adapter.read_existing_config() == {}

    def test_read_existing_config_returns_empty_for_non_dict_json(
        self, tmp_path: Path
    ) -> None:
        config_file = tmp_path / "list.json"
        config_file.write_text('["a", "b"]', encoding="utf-8")
        adapter = ClaudeDesktopAdapter(config_path=config_file)
        assert adapter.read_existing_config() == {}

    def test_write_config_creates_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "sub" / "config.json"
        adapter = ClaudeDesktopAdapter(config_path=config_file)
        adapter.write_config({"mcpServers": {}})
        assert config_file.exists()
        data = json.loads(config_file.read_text(encoding="utf-8"))
        assert "mcpServers" in data

    def test_generate_config_env_field_is_dict(self) -> None:
        adapter = ClaudeDesktopAdapter()
        config = adapter.generate_config({"srv": {"command": "cmd"}})
        server = config["mcpServers"]["srv"]
        assert isinstance(server["env"], dict)


# ---------------------------------------------------------------------------
# CursorAdapter
# ---------------------------------------------------------------------------

class TestCursorAdapter:
    def test_default_policy_path(self) -> None:
        adapter = CursorAdapter()
        assert adapter.policy_path == "policy.yaml"

    def test_generate_server_config_no_args(self) -> None:
        adapter = CursorAdapter(policy_path="p.yaml")
        config = adapter.generate_server_config("s", "cmd")
        assert config["command"] == "trusted-mcp"
        assert "--upstream-args" not in config["args"]

    def test_generate_server_config_with_args(self) -> None:
        adapter = CursorAdapter()
        config = adapter.generate_server_config("s", "npx", ["pkg"])
        assert "--upstream-args" in config["args"]

    def test_generate_config_returns_mcp_servers(self) -> None:
        adapter = CursorAdapter()
        config = adapter.generate_config({"s1": {"command": "c1"}})
        assert "mcpServers" in config
        assert "s1" in config["mcpServers"]

    def test_generate_config_passes_tuple_args(self) -> None:
        adapter = CursorAdapter()
        # args as a tuple should also work
        config = adapter.generate_config({"s": {"command": "c", "args": ("a", "b")}})
        assert "s" in config["mcpServers"]

    def test_generate_config_handles_missing_args_key(self) -> None:
        adapter = CursorAdapter()
        config = adapter.generate_config({"s": {"command": "c"}})
        assert "s" in config["mcpServers"]

    def test_write_config_creates_cursor_dir(self, tmp_path: Path) -> None:
        adapter = CursorAdapter(project_root=tmp_path)
        adapter.write_config({"mcpServers": {}})
        config_path = tmp_path / ".cursor" / "mcp.json"
        assert config_path.exists()

    def test_read_existing_config_returns_empty_when_absent(self, tmp_path: Path) -> None:
        adapter = CursorAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {}

    def test_read_existing_config_parses_valid_json(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(json.dumps({"k": "v"}), encoding="utf-8")
        adapter = CursorAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {"k": "v"}

    def test_read_existing_config_returns_empty_for_bad_json(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text("{bad", encoding="utf-8")
        adapter = CursorAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {}

    def test_read_existing_config_returns_empty_for_non_dict(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text("[1, 2]", encoding="utf-8")
        adapter = CursorAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {}


# ---------------------------------------------------------------------------
# VSCodeAdapter
# ---------------------------------------------------------------------------

class TestVSCodeAdapter:
    def test_default_policy_path(self) -> None:
        adapter = VSCodeAdapter()
        assert adapter.policy_path == "policy.yaml"

    def test_generate_server_config_no_args(self) -> None:
        adapter = VSCodeAdapter()
        config = adapter.generate_server_config("s", "cmd")
        assert config["command"] == "trusted-mcp"
        assert config["type"] == "stdio"
        assert "--upstream-args" not in config["args"]

    def test_generate_server_config_with_args(self) -> None:
        adapter = VSCodeAdapter()
        config = adapter.generate_server_config("s", "npx", ["pkg", "--flag"])
        assert "--upstream-args" in config["args"]

    def test_generate_config_returns_servers_key(self) -> None:
        adapter = VSCodeAdapter()
        config = adapter.generate_config({"s1": {"command": "c1"}})
        assert "servers" in config
        assert "s1" in config["servers"]

    def test_write_config_creates_vscode_dir(self, tmp_path: Path) -> None:
        adapter = VSCodeAdapter(project_root=tmp_path)
        adapter.write_config({"servers": {}})
        config_path = tmp_path / ".vscode" / "mcp.json"
        assert config_path.exists()

    def test_read_existing_config_returns_empty_when_absent(self, tmp_path: Path) -> None:
        adapter = VSCodeAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {}

    def test_read_existing_config_parses_valid_json(self, tmp_path: Path) -> None:
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "mcp.json").write_text(json.dumps({"key": "val"}), encoding="utf-8")
        adapter = VSCodeAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {"key": "val"}

    def test_read_existing_config_returns_empty_for_bad_json(self, tmp_path: Path) -> None:
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "mcp.json").write_text("{bad", encoding="utf-8")
        adapter = VSCodeAdapter(project_root=tmp_path)
        assert adapter.read_existing_config() == {}


# ---------------------------------------------------------------------------
# GenericAdapter, StdioConfig, SSEConfig
# ---------------------------------------------------------------------------

class TestGenericAdapter:
    def test_generate_stdio_config_no_args_no_env(self) -> None:
        adapter = GenericAdapter(policy_path="p.yaml")
        config = adapter.generate_stdio_config("cmd")
        assert isinstance(config, StdioConfig)
        assert config.command == "trusted-mcp"
        assert "--upstream-cmd" in config.args
        assert config.env == {}

    def test_generate_stdio_config_with_upstream_args(self) -> None:
        adapter = GenericAdapter()
        config = adapter.generate_stdio_config("uvx", ["mcp-server"])
        assert "--upstream-args" in config.args

    def test_generate_stdio_config_with_env(self) -> None:
        adapter = GenericAdapter()
        config = adapter.generate_stdio_config("cmd", env={"MY_VAR": "value"})
        assert config.env == {"MY_VAR": "value"}

    def test_generate_sse_config_returns_sse_config(self) -> None:
        adapter = GenericAdapter(proxy_host="0.0.0.0", proxy_port=9000)
        config = adapter.generate_sse_config("http://upstream:8080/sse")
        assert isinstance(config, SSEConfig)
        assert "9000" in config.proxy_url
        assert config.upstream_url == "http://upstream:8080/sse"

    def test_generate_launch_command_stdio(self) -> None:
        adapter = GenericAdapter(policy_path="policy.yaml")
        cmd = adapter.generate_launch_command(
            transport="stdio", upstream_command="mcp-server"
        )
        assert "trusted-mcp" in cmd
        assert "--transport" in cmd
        assert "stdio" in cmd
        assert "--upstream-cmd" in cmd

    def test_generate_launch_command_sse(self) -> None:
        adapter = GenericAdapter()
        cmd = adapter.generate_launch_command(
            transport="sse", upstream_url="http://mcp:8080/sse"
        )
        assert "sse" in cmd
        assert "--upstream" in cmd

    def test_generate_launch_command_verbose_adds_flag(self) -> None:
        adapter = GenericAdapter()
        cmd = adapter.generate_launch_command(transport="stdio", verbose=True)
        assert "--verbose" in cmd

    def test_generate_launch_command_no_upstream_cmd_when_empty(self) -> None:
        adapter = GenericAdapter()
        cmd = adapter.generate_launch_command(transport="stdio", upstream_command="")
        assert "--upstream-cmd" not in cmd


class TestStdioConfig:
    def test_to_dict(self) -> None:
        config = StdioConfig(
            command="trusted-mcp",
            args=["proxy", "--config", "p.yaml"],
            env={"FOO": "bar"},
        )
        data = config.to_dict()
        assert data["command"] == "trusted-mcp"
        assert data["env"] == {"FOO": "bar"}


class TestSSEConfig:
    def test_to_dict(self) -> None:
        config = SSEConfig(
            proxy_url="http://127.0.0.1:8765/sse",
            upstream_url="http://upstream/sse",
        )
        data = config.to_dict()
        assert data["url"] == "http://127.0.0.1:8765/sse"
        assert data["upstream"] == "http://upstream/sse"
