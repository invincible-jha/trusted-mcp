"""Unit tests for trusted_mcp advanced scanners.

Covers:
- scanners.argument_scanner  — BasicArgumentScanner
- scanners.description_hash  — DescriptionHashScanner
- scanners.pii_scanner       — BasicPIIScanner
- plugins.registry           — PluginRegistry, PluginNotFoundError, PluginAlreadyRegisteredError
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from trusted_mcp.core.result import Action
from trusted_mcp.core.scanner import ToolCallRequest, ToolCallResponse, ToolDefinition
from trusted_mcp.plugins.registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
)
from trusted_mcp.scanners.argument_scanner import (
    ArgumentRule,
    BasicArgumentScanner,
    _parse_rule,
)
from trusted_mcp.scanners.description_hash import DescriptionHashScanner
from trusted_mcp.scanners.pii_scanner import BasicPIIScanner


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _run(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


def _request(
    tool_name: str = "my_tool",
    server_name: str = "my_server",
    arguments: dict[str, object] | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=tool_name,
        server_name=server_name,
        arguments=arguments or {},
    )


def _response(
    content: object = "ok",
    tool_name: str = "my_tool",
    server_name: str = "my_server",
) -> ToolCallResponse:
    return ToolCallResponse(tool_name=tool_name, server_name=server_name, content=content)


def _tool_def(
    name: str = "tool",
    server_name: str = "srv",
    description: str = "Does something useful",
) -> ToolDefinition:
    return ToolDefinition(name=name, server_name=server_name, description=description)


# ---------------------------------------------------------------------------
# _parse_rule (argument_scanner internal helper)
# ---------------------------------------------------------------------------

class TestParseRule:
    def test_non_dict_returns_none(self) -> None:
        assert _parse_rule("not a dict") is None

    def test_missing_tool_pattern_returns_none(self) -> None:
        assert _parse_rule({"param_name": "x"}) is None

    def test_empty_tool_pattern_returns_none(self) -> None:
        assert _parse_rule({"tool_pattern": "", "param_name": "x"}) is None

    def test_missing_param_name_returns_none(self) -> None:
        assert _parse_rule({"tool_pattern": "*:*"}) is None

    def test_unknown_param_type_returns_none(self) -> None:
        assert _parse_rule({
            "tool_pattern": "*:*",
            "param_name": "x",
            "param_type": "unknown_type",
        }) is None

    def test_invalid_numeric_min_val_returns_none(self) -> None:
        assert _parse_rule({
            "tool_pattern": "*:*",
            "param_name": "x",
            "min_val": "not-a-number",
        }) is None

    def test_valid_rule_parsed_correctly(self) -> None:
        rule = _parse_rule({
            "tool_pattern": "srv:tool",
            "param_name": "path",
            "param_type": "str",
            "min_val": None,
            "max_val": None,
            "max_length": 100,
            "required": True,
            "allowed_values": ["a", "b"],
        })
        assert rule is not None
        assert rule.tool_pattern == "srv:tool"
        assert rule.param_name == "path"
        assert rule.max_length == 100
        assert rule.required is True
        assert rule.allowed_values == ["a", "b"]

    def test_null_param_type_is_valid(self) -> None:
        rule = _parse_rule({
            "tool_pattern": "*:*",
            "param_name": "opt",
            "param_type": "null",
        })
        assert rule is not None
        assert rule.param_type == "null"

    def test_non_list_allowed_values_defaults_to_empty(self) -> None:
        rule = _parse_rule({
            "tool_pattern": "*:*",
            "param_name": "x",
            "allowed_values": "not-a-list",
        })
        assert rule is not None
        assert rule.allowed_values == []


# ---------------------------------------------------------------------------
# BasicArgumentScanner
# ---------------------------------------------------------------------------

class TestBasicArgumentScannerNoRules:
    def test_no_rules_always_passes(self) -> None:
        scanner = BasicArgumentScanner()
        result = _run(scanner.scan_request(_request()))
        assert result.action == Action.PASS


class TestBasicArgumentScannerRequiredField:
    def _scanner(self, strict: bool = False) -> BasicArgumentScanner:
        return BasicArgumentScanner({
            "strict_types": strict,
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "path",
                "required": True,
            }],
        })

    def test_required_field_present_passes(self) -> None:
        scanner = self._scanner()
        req = _request(arguments={"path": "/tmp/file"})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.PASS

    def test_required_field_missing_warns_non_strict(self) -> None:
        scanner = self._scanner(strict=False)
        req = _request(arguments={})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.WARN

    def test_required_field_missing_blocks_in_strict_mode(self) -> None:
        scanner = self._scanner(strict=True)
        req = _request(arguments={})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.BLOCK

    def test_no_matching_rule_passes(self) -> None:
        scanner = self._scanner()
        req = _request(tool_name="other_tool", arguments={})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.PASS


class TestBasicArgumentScannerTypeCheck:
    def _scanner(self, param_type: str, strict: bool = False) -> BasicArgumentScanner:
        return BasicArgumentScanner({
            "strict_types": strict,
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "value",
                "param_type": param_type,
            }],
        })

    def test_correct_type_passes(self) -> None:
        scanner = self._scanner("str")
        req = _request(arguments={"value": "hello"})
        assert _run(scanner.scan_request(req)).action == Action.PASS

    def test_wrong_type_warns_non_strict(self) -> None:
        scanner = self._scanner("str")
        req = _request(arguments={"value": 123})
        assert _run(scanner.scan_request(req)).action == Action.WARN

    def test_wrong_type_blocks_strict(self) -> None:
        scanner = self._scanner("str", strict=True)
        req = _request(arguments={"value": 123})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_bool_is_not_treated_as_int(self) -> None:
        scanner = self._scanner("str")
        req = _request(arguments={"value": True})
        # True is bool, not str -> should warn
        assert _run(scanner.scan_request(req)).action == Action.WARN

    def test_bool_is_accepted_for_int_type(self) -> None:
        # bool is a subclass of int — should pass for "int" param_type
        scanner = self._scanner("int")
        req = _request(arguments={"value": True})
        assert _run(scanner.scan_request(req)).action == Action.PASS

    def test_null_type_accepts_none(self) -> None:
        scanner = self._scanner("null")
        req = _request(arguments={"value": None})
        assert _run(scanner.scan_request(req)).action == Action.PASS

    def test_null_type_rejects_non_none(self) -> None:
        scanner = self._scanner("null")
        req = _request(arguments={"value": "not-null"})
        result = _run(scanner.scan_request(req))
        assert result.action in (Action.WARN, Action.BLOCK)


class TestBasicArgumentScannerNumericRange:
    def _scanner(self, min_val: float | None = None, max_val: float | None = None) -> BasicArgumentScanner:
        rule: dict[str, object] = {
            "tool_pattern": "my_server:my_tool",
            "param_name": "count",
        }
        if min_val is not None:
            rule["min_val"] = min_val
        if max_val is not None:
            rule["max_val"] = max_val
        return BasicArgumentScanner({"rules": [rule]})

    def test_value_within_range_passes(self) -> None:
        scanner = self._scanner(min_val=0, max_val=100)
        req = _request(arguments={"count": 50})
        assert _run(scanner.scan_request(req)).action == Action.PASS

    def test_value_below_min_blocks(self) -> None:
        scanner = self._scanner(min_val=10)
        req = _request(arguments={"count": 5})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_value_above_max_blocks(self) -> None:
        scanner = self._scanner(max_val=100)
        req = _request(arguments={"count": 200})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_bool_values_skipped_for_numeric_range(self) -> None:
        scanner = self._scanner(min_val=0, max_val=10)
        req = _request(arguments={"count": True})
        # True is bool, skip numeric check
        assert _run(scanner.scan_request(req)).action == Action.PASS


class TestBasicArgumentScannerLengthAndAllowed:
    def test_string_exceeding_max_length_blocks(self) -> None:
        scanner = BasicArgumentScanner({
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "query",
                "max_length": 5,
            }]
        })
        req = _request(arguments={"query": "too_long_string"})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_list_exceeding_max_length_blocks(self) -> None:
        scanner = BasicArgumentScanner({
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "items",
                "max_length": 2,
            }]
        })
        req = _request(arguments={"items": [1, 2, 3]})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_value_in_allowed_values_passes(self) -> None:
        scanner = BasicArgumentScanner({
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "engine",
                "allowed_values": ["google", "bing"],
            }]
        })
        req = _request(arguments={"engine": "google"})
        assert _run(scanner.scan_request(req)).action == Action.PASS

    def test_value_not_in_allowed_values_blocks(self) -> None:
        scanner = BasicArgumentScanner({
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "engine",
                "allowed_values": ["google", "bing"],
            }]
        })
        req = _request(arguments={"engine": "yahoo"})
        assert _run(scanner.scan_request(req)).action == Action.BLOCK

    def test_param_not_in_arguments_skipped(self) -> None:
        scanner = BasicArgumentScanner({
            "rules": [{
                "tool_pattern": "my_server:my_tool",
                "param_name": "optional_param",
                "max_length": 10,
            }]
        })
        req = _request(arguments={})
        assert _run(scanner.scan_request(req)).action == Action.PASS


# ---------------------------------------------------------------------------
# DescriptionHashScanner
# ---------------------------------------------------------------------------

class TestDescriptionHashScanner:
    def test_scan_request_always_passes(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({"store_path": str(tmp_path / "h.json")})
        result = _run(scanner.scan_request(_request()))
        assert result.action == Action.PASS

    def test_first_encounter_stores_hash_and_passes_auto_approve(
        self, tmp_path: Path
    ) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
            "auto_approve_new": True,
        })
        tool = _tool_def(name="calc", server_name="math")
        result = _run(scanner.scan_tool_description(tool))
        assert result.action == Action.PASS
        assert (tmp_path / "hashes.json").exists()

    def test_first_encounter_warns_when_not_auto_approve(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
            "auto_approve_new": False,
        })
        tool = _tool_def(name="calc", server_name="math")
        result = _run(scanner.scan_tool_description(tool))
        assert result.action == Action.WARN

    def test_same_description_passes_on_second_encounter(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
        })
        tool = _tool_def()
        _run(scanner.scan_tool_description(tool))  # first encounter
        result = _run(scanner.scan_tool_description(tool))  # second encounter
        assert result.action == Action.PASS

    def test_changed_description_blocks(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
        })
        tool_v1 = _tool_def(description="Original description")
        tool_v2 = _tool_def(description="Changed description — rug pull!")
        _run(scanner.scan_tool_description(tool_v1))
        result = _run(scanner.scan_tool_description(tool_v2))
        assert result.action == Action.BLOCK

    def test_reset_hash_allows_reapproval(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
        })
        tool = _tool_def(name="tool", server_name="srv")
        _run(scanner.scan_tool_description(tool))
        removed = scanner.reset_hash("srv", "tool")
        assert removed is True
        # After reset, next call should be treated as first encounter
        result = _run(scanner.scan_tool_description(tool))
        assert result.action == Action.PASS

    def test_reset_hash_returns_false_for_unknown_tool(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
        })
        assert scanner.reset_hash("unknown_srv", "unknown_tool") is False

    def test_list_hashes_returns_copy(self, tmp_path: Path) -> None:
        scanner = DescriptionHashScanner({
            "store_path": str(tmp_path / "hashes.json"),
        })
        tool = _tool_def(name="t", server_name="s")
        _run(scanner.scan_tool_description(tool))
        hashes = scanner.list_hashes()
        assert "s:t" in hashes
        assert isinstance(hashes["s:t"], str)

    def test_loads_existing_hashes_from_disk(self, tmp_path: Path) -> None:
        store_path = tmp_path / "hashes.json"
        existing = {"srv:tool": "abc123"}
        store_path.write_text(json.dumps(existing), encoding="utf-8")
        scanner = DescriptionHashScanner({"store_path": str(store_path)})
        hashes = scanner.list_hashes()
        assert hashes["srv:tool"] == "abc123"

    def test_invalid_store_file_defaults_to_empty(self, tmp_path: Path) -> None:
        store_path = tmp_path / "bad.json"
        store_path.write_text("{bad json", encoding="utf-8")
        scanner = DescriptionHashScanner({"store_path": str(store_path)})
        assert scanner.list_hashes() == {}

    def test_non_dict_store_file_defaults_to_empty(self, tmp_path: Path) -> None:
        store_path = tmp_path / "list.json"
        store_path.write_text("[1, 2, 3]", encoding="utf-8")
        scanner = DescriptionHashScanner({"store_path": str(store_path)})
        assert scanner.list_hashes() == {}


# ---------------------------------------------------------------------------
# BasicPIIScanner
# ---------------------------------------------------------------------------

class TestBasicPIIScannerResponse:
    def _scanner(self, **settings: object) -> BasicPIIScanner:
        return BasicPIIScanner(settings if settings else None)

    def test_clean_response_passes(self) -> None:
        scanner = self._scanner()
        req = _request()
        resp = _response("No PII here, just a normal result.")
        result = _run(scanner.scan_response(req, resp))
        assert result.action == Action.PASS

    def test_ssn_in_response_warns_by_default(self) -> None:
        scanner = self._scanner()
        resp = _response("Your SSN is 123-45-6789.")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN
        assert "ssn" in result.details.get("pii_types", [])

    def test_email_in_response_warns_by_default(self) -> None:
        scanner = self._scanner()
        resp = _response("Contact us at user@example.com for help.")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN

    def test_block_mode_blocks_on_pii(self) -> None:
        scanner = self._scanner(action_on_detect="block")
        resp = _response("user@example.com is the contact.")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.BLOCK

    def test_aws_key_in_response_flagged(self) -> None:
        scanner = self._scanner()
        resp = _response("Key: AKIAIOSFODNN7EXAMPLE here.")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN

    def test_dict_response_content_scanned(self) -> None:
        scanner = self._scanner()
        resp = _response({"result": "user@example.com is the contact"})
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN

    def test_list_response_content_scanned(self) -> None:
        scanner = self._scanner()
        resp = _response(["user@example.com", "other data"])
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN

    def test_limited_pii_types_only_scans_selected(self) -> None:
        scanner = self._scanner(pii_types=["ssn"])
        # Email should NOT be flagged when pii_types is limited to ssn
        resp = _response("contact user@example.com for support")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.PASS

    def test_limited_pii_types_still_catches_selected(self) -> None:
        scanner = self._scanner(pii_types=["ssn"])
        resp = _response("SSN: 123-45-6789")
        result = _run(scanner.scan_response(_request(), resp))
        assert result.action == Action.WARN


class TestBasicPIIScannerRequest:
    def test_request_scan_disabled_by_default(self) -> None:
        scanner = BasicPIIScanner()
        req = _request(arguments={"email": "user@example.com"})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.PASS

    def test_request_scan_enabled_detects_pii(self) -> None:
        scanner = BasicPIIScanner({"scan_requests": True})
        req = _request(arguments={"email": "user@example.com"})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.WARN

    def test_request_scan_clean_arguments_pass(self) -> None:
        scanner = BasicPIIScanner({"scan_requests": True})
        req = _request(arguments={"query": "weather today"})
        result = _run(scanner.scan_request(req))
        assert result.action == Action.PASS


class TestBasicPIIScannerRedact:
    def test_redact_replaces_email(self) -> None:
        scanner = BasicPIIScanner()
        result = scanner.redact("Send to user@example.com please")
        assert "user@example.com" not in result
        assert "[REDACTED" in result

    def test_redact_replaces_ssn(self) -> None:
        scanner = BasicPIIScanner()
        result = scanner.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result

    def test_redact_clean_text_unchanged(self) -> None:
        scanner = BasicPIIScanner()
        text = "No sensitive info here."
        assert scanner.redact(text) == text


# ---------------------------------------------------------------------------
# PluginRegistry (trusted_mcp version)
# ---------------------------------------------------------------------------

class _BaseForTest:
    pass


class TestTrustedMcpPluginRegistry:
    def _make_registry(self) -> PluginRegistry[_BaseForTest]:
        return PluginRegistry(_BaseForTest, "test-reg")

    def test_register_decorator(self) -> None:
        reg = self._make_registry()

        @reg.register("p1")
        class P1(_BaseForTest):
            pass

        assert reg.get("p1") is P1

    def test_register_duplicate_raises(self) -> None:
        reg = self._make_registry()

        @reg.register("dup")
        class Dup(_BaseForTest):
            pass

        with pytest.raises(PluginAlreadyRegisteredError):
            @reg.register("dup")
            class Dup2(_BaseForTest):
                pass

    def test_register_non_subclass_raises_type_error(self) -> None:
        reg = self._make_registry()
        with pytest.raises(TypeError):
            @reg.register("bad")
            class Bad:  # type: ignore[arg-type]
                pass

    def test_register_class_direct(self) -> None:
        reg = self._make_registry()

        class Direct(_BaseForTest):
            pass

        reg.register_class("direct", Direct)
        assert reg.get("direct") is Direct

    def test_register_class_duplicate_raises(self) -> None:
        reg = self._make_registry()

        class D(_BaseForTest):
            pass

        reg.register_class("d", D)
        with pytest.raises(PluginAlreadyRegisteredError):
            reg.register_class("d", D)

    def test_get_unknown_raises_not_found(self) -> None:
        reg = self._make_registry()
        with pytest.raises(PluginNotFoundError):
            reg.get("ghost")

    def test_list_plugins_sorted(self) -> None:
        reg = self._make_registry()

        class Z(_BaseForTest):
            pass

        class A(_BaseForTest):
            pass

        reg.register_class("z", Z)
        reg.register_class("a", A)
        assert reg.list_plugins() == ["a", "z"]

    def test_contains_operator(self) -> None:
        reg = self._make_registry()

        class P(_BaseForTest):
            pass

        reg.register_class("p", P)
        assert "p" in reg
        assert "missing" not in reg

    def test_len_operator(self) -> None:
        reg = self._make_registry()
        assert len(reg) == 0

        class P(_BaseForTest):
            pass

        reg.register_class("p", P)
        assert len(reg) == 1

    def test_deregister_removes_plugin(self) -> None:
        reg = self._make_registry()

        class P(_BaseForTest):
            pass

        reg.register_class("p", P)
        reg.deregister("p")
        assert "p" not in reg

    def test_deregister_unknown_raises_not_found(self) -> None:
        reg = self._make_registry()
        with pytest.raises(PluginNotFoundError):
            reg.deregister("ghost")

    def test_repr_contains_registry_name(self) -> None:
        reg = self._make_registry()
        assert "test-reg" in repr(reg)

    def test_load_entrypoints_no_entries(self) -> None:
        reg = self._make_registry()
        reg.load_entrypoints("fake.group.none")
        assert len(reg) == 0

    def test_load_entrypoints_skips_already_registered(self) -> None:
        reg = self._make_registry()

        class Existing(_BaseForTest):
            pass

        reg.register_class("existing", Existing)

        mock_ep = MagicMock()
        mock_ep.name = "existing"

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            reg.load_entrypoints("some.group")

        assert len(reg) == 1

    def test_load_entrypoints_skips_failed_load(self) -> None:
        reg = self._make_registry()
        mock_ep = MagicMock()
        mock_ep.name = "fail"
        mock_ep.load.side_effect = ImportError("missing")
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            reg.load_entrypoints("some.group")
        assert "fail" not in reg

    def test_load_entrypoints_skips_non_subclass(self) -> None:
        reg = self._make_registry()
        mock_ep = MagicMock()
        mock_ep.name = "bad"

        class NotSubclass:
            pass

        mock_ep.load.return_value = NotSubclass
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            reg.load_entrypoints("some.group")
        assert "bad" not in reg

    def test_plugin_not_found_error_attributes(self) -> None:
        exc = PluginNotFoundError("x", "my-reg")
        assert exc.plugin_name == "x"
        assert exc.registry_name == "my-reg"

    def test_plugin_already_registered_error_attributes(self) -> None:
        exc = PluginAlreadyRegisteredError("y", "my-reg")
        assert exc.plugin_name == "y"
        assert exc.registry_name == "my-reg"
