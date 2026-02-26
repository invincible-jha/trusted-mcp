"""Unit tests for trusted_mcp.scanners.allowlist_scanner."""
from __future__ import annotations

import pytest

from trusted_mcp.core.result import Action
from trusted_mcp.core.scanner import ToolCallRequest, ToolDefinition
from trusted_mcp.scanners.allowlist_scanner import BasicAllowlistScanner


def _make_request(tool_name: str, server_name: str) -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool_name, server_name=server_name)


def _make_tool(tool_name: str, server_name: str) -> ToolDefinition:
    return ToolDefinition(name=tool_name, server_name=server_name)


class TestBasicAllowlistScannerConstruction:
    def test_name_attribute(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner.name == "allowlist"

    def test_default_mode_is_blocklist(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._mode == "blocklist"

    def test_explicit_blocklist_mode(self) -> None:
        scanner = BasicAllowlistScanner({"mode": "blocklist"})
        assert scanner._mode == "blocklist"

    def test_allowlist_mode(self) -> None:
        scanner = BasicAllowlistScanner({"mode": "allowlist"})
        assert scanner._mode == "allowlist"

    def test_invalid_mode_defaults_to_blocklist(self) -> None:
        scanner = BasicAllowlistScanner({"mode": "invalid_mode"})
        assert scanner._mode == "blocklist"

    def test_no_settings_empty_patterns(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._allow_patterns == []
        assert scanner._block_patterns == []

    def test_block_patterns_loaded(self) -> None:
        scanner = BasicAllowlistScanner({
            "tools": {"block": ["shell:*", "filesystem:delete_file"]}
        })
        assert len(scanner._block_patterns) == 2
        assert "shell:*" in scanner._block_patterns

    def test_allow_patterns_loaded(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["filesystem:read_file", "web:search"]},
        })
        assert len(scanner._allow_patterns) == 2

    def test_non_list_tools_config_ignored(self) -> None:
        scanner = BasicAllowlistScanner({"tools": "not-a-dict"})
        assert scanner._allow_patterns == []
        assert scanner._block_patterns == []


class TestBlocklistMode:
    @pytest.mark.asyncio
    async def test_unlisted_tool_passes_in_blocklist_mode(self) -> None:
        scanner = BasicAllowlistScanner({"mode": "blocklist", "tools": {"block": []}})
        result = await scanner.scan_request(_make_request("search", "web"))
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_explicitly_blocked_tool_is_blocked(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "blocklist",
            "tools": {"block": ["shell:execute_command"]},
        })
        result = await scanner.scan_request(_make_request("execute_command", "shell"))
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_block_reason_contains_tool_id(self) -> None:
        scanner = BasicAllowlistScanner({
            "tools": {"block": ["shell:execute_command"]}
        })
        result = await scanner.scan_request(_make_request("execute_command", "shell"))
        assert "shell:execute_command" in result.reason

    @pytest.mark.asyncio
    async def test_wildcard_block_pattern(self) -> None:
        scanner = BasicAllowlistScanner({"tools": {"block": ["shell:*"]}})
        result = await scanner.scan_request(_make_request("any_command", "shell"))
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_wildcard_block_does_not_affect_other_servers(self) -> None:
        scanner = BasicAllowlistScanner({"tools": {"block": ["shell:*"]}})
        result = await scanner.scan_request(_make_request("search", "web"))
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_partial_wildcard_block(self) -> None:
        scanner = BasicAllowlistScanner({"tools": {"block": ["filesystem:write_*"]}})
        result_write = await scanner.scan_request(_make_request("write_file", "filesystem"))
        result_read = await scanner.scan_request(_make_request("read_file", "filesystem"))
        assert result_write.action == Action.BLOCK
        assert result_read.action == Action.PASS

    @pytest.mark.asyncio
    async def test_empty_block_list_all_pass(self) -> None:
        scanner = BasicAllowlistScanner({"tools": {"block": []}})
        result = await scanner.scan_request(_make_request("delete_everything", "nuclear"))
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_no_settings_all_pass(self) -> None:
        scanner = BasicAllowlistScanner()
        result = await scanner.scan_request(_make_request("anything", "anywhere"))
        assert result.action == Action.PASS


class TestAllowlistMode:
    @pytest.mark.asyncio
    async def test_listed_tool_passes(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["web:search"]},
        })
        result = await scanner.scan_request(_make_request("search", "web"))
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_unlisted_tool_blocked(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["web:search"]},
        })
        result = await scanner.scan_request(_make_request("delete", "filesystem"))
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_empty_allowlist_blocks_all(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": []},
        })
        result = await scanner.scan_request(_make_request("search", "web"))
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_empty_allowlist_block_reason_explains(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": []},
        })
        result = await scanner.scan_request(_make_request("search", "web"))
        assert "allowlist is empty" in result.reason

    @pytest.mark.asyncio
    async def test_wildcard_allow_pattern(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["github:*"]},
        })
        result = await scanner.scan_request(_make_request("create_issue", "github"))
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_wildcard_allow_does_not_allow_other_servers(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["github:*"]},
        })
        result = await scanner.scan_request(_make_request("create_issue", "gitlab"))
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocklist_checked_even_in_allowlist_mode(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {
                "allow": ["shell:*"],
                "block": ["shell:execute_command"],
            },
        })
        result = await scanner.scan_request(_make_request("execute_command", "shell"))
        assert result.action == Action.BLOCK


class TestScanToolDescription:
    @pytest.mark.asyncio
    async def test_blocklisted_tool_definition_blocked(self) -> None:
        scanner = BasicAllowlistScanner({"tools": {"block": ["shell:*"]}})
        tool = _make_tool("run", "shell")
        result = await scanner.scan_tool_description(tool)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_allowlisted_tool_definition_passes(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["web:search"]},
        })
        tool = _make_tool("search", "web")
        result = await scanner.scan_tool_description(tool)
        assert result.action == Action.PASS

    @pytest.mark.asyncio
    async def test_not_in_allowlist_blocked(self) -> None:
        scanner = BasicAllowlistScanner({
            "mode": "allowlist",
            "tools": {"allow": ["web:search"]},
        })
        tool = _make_tool("delete", "filesystem")
        result = await scanner.scan_tool_description(tool)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocklist_mode_with_no_block_passes_everything(self) -> None:
        scanner = BasicAllowlistScanner({"mode": "blocklist", "tools": {"allow": ["web:*"]}})
        tool = _make_tool("anything", "anything_server")
        result = await scanner.scan_tool_description(tool)
        assert result.action == Action.PASS


class TestToolIdBuilding:
    def test_tool_id_format(self) -> None:
        scanner = BasicAllowlistScanner()
        tool_id = scanner._tool_id("filesystem", "read_file")
        assert tool_id == "filesystem:read_file"

    def test_matches_any_with_exact_pattern(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._matches_any("web:search", ["web:search"]) is True

    def test_matches_any_with_wildcard_pattern(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._matches_any("web:search", ["web:*"]) is True

    def test_matches_any_with_no_match(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._matches_any("web:search", ["filesystem:*"]) is False

    def test_matches_any_empty_patterns(self) -> None:
        scanner = BasicAllowlistScanner()
        assert scanner._matches_any("web:search", []) is False
