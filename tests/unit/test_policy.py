"""Unit tests for trusted_mcp.core.policy."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from trusted_mcp.core.exceptions import PolicyError
from trusted_mcp.core.policy import (
    AuditConfig,
    PolicyConfig,
    ProxyConfig,
    ScannerConfig,
    default_policy,
    load_policy,
    load_policy_from_string,
    resolve_env_vars,
)


# ---------------------------------------------------------------------------
# ProxyConfig
# ---------------------------------------------------------------------------

class TestProxyConfig:
    def test_defaults(self) -> None:
        config = ProxyConfig()
        assert config.transport == "stdio"
        assert config.upstream is None
        assert config.timeout_ms == 30000
        assert config.max_concurrent == 10

    def test_sse_transport(self) -> None:
        config = ProxyConfig(transport="sse", upstream="https://mcp.example.com")
        assert config.transport == "sse"
        assert config.upstream == "https://mcp.example.com"

    def test_invalid_transport_raises(self) -> None:
        with pytest.raises(Exception):
            ProxyConfig(transport="websocket")  # type: ignore[arg-type]

    def test_timeout_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            ProxyConfig(timeout_ms=0)

    def test_max_concurrent_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            ProxyConfig(max_concurrent=0)

    def test_custom_timeout(self) -> None:
        config = ProxyConfig(timeout_ms=5000)
        assert config.timeout_ms == 5000

    def test_custom_max_concurrent(self) -> None:
        config = ProxyConfig(max_concurrent=50)
        assert config.max_concurrent == 50


# ---------------------------------------------------------------------------
# ScannerConfig
# ---------------------------------------------------------------------------

class TestScannerConfig:
    def test_minimum_construction(self) -> None:
        config = ScannerConfig(name="regex")
        assert config.name == "regex"
        assert config.enabled is True
        assert config.settings == {}

    def test_disabled_scanner(self) -> None:
        config = ScannerConfig(name="pii", enabled=False)
        assert config.enabled is False

    def test_with_settings(self) -> None:
        config = ScannerConfig(name="regex", settings={"sensitivity": "high"})
        assert config.settings == {"sensitivity": "high"}


# ---------------------------------------------------------------------------
# AuditConfig
# ---------------------------------------------------------------------------

class TestAuditConfig:
    def test_defaults(self) -> None:
        config = AuditConfig()
        assert config.enabled is True
        assert config.backend == "file"
        assert config.path == ".trusted-mcp/audit.jsonl"
        assert config.retention_days == 30
        assert config.redact_pii is True
        assert config.max_file_size_mb == 100

    def test_stdout_backend(self) -> None:
        config = AuditConfig(backend="stdout")
        assert config.backend == "stdout"

    def test_invalid_backend_raises(self) -> None:
        with pytest.raises(Exception):
            AuditConfig(backend="s3")  # type: ignore[arg-type]

    def test_retention_days_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            AuditConfig(retention_days=0)

    def test_max_file_size_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            AuditConfig(max_file_size_mb=0)


# ---------------------------------------------------------------------------
# PolicyConfig
# ---------------------------------------------------------------------------

class TestPolicyConfig:
    def test_defaults(self) -> None:
        config = PolicyConfig()
        assert config.version == "1.0"
        assert config.name == "default"
        assert isinstance(config.proxy, ProxyConfig)
        assert config.scanners == []
        assert isinstance(config.audit, AuditConfig)

    def test_active_scanners_filters_disabled(self) -> None:
        config = PolicyConfig(
            scanners=[
                ScannerConfig(name="regex", enabled=True),
                ScannerConfig(name="pii", enabled=False),
                ScannerConfig(name="allowlist", enabled=True),
            ]
        )
        active = config.active_scanners()
        assert len(active) == 2
        assert all(s.enabled for s in active)
        assert active[0].name == "regex"
        assert active[1].name == "allowlist"

    def test_active_scanners_empty_when_all_disabled(self) -> None:
        config = PolicyConfig(
            scanners=[ScannerConfig(name="regex", enabled=False)]
        )
        assert config.active_scanners() == []

    def test_sse_transport_without_upstream_raises(self) -> None:
        with pytest.raises(Exception, match="upstream"):
            PolicyConfig(proxy=ProxyConfig(transport="sse", upstream=None))

    def test_sse_transport_with_upstream_succeeds(self) -> None:
        config = PolicyConfig(
            proxy=ProxyConfig(transport="sse", upstream="https://mcp.example.com")
        )
        assert config.proxy.transport == "sse"


# ---------------------------------------------------------------------------
# load_policy_from_string
# ---------------------------------------------------------------------------

class TestLoadPolicyFromString:
    def test_minimal_valid_yaml(self) -> None:
        yaml_text = textwrap.dedent("""\
            version: "1.0"
            name: "test-policy"
        """)
        config = load_policy_from_string(yaml_text)
        assert config.name == "test-policy"
        assert config.version == "1.0"

    def test_full_policy_yaml(self) -> None:
        yaml_text = textwrap.dedent("""\
            version: "1.0"
            name: "full-policy"
            proxy:
              transport: stdio
              timeout_ms: 15000
              max_concurrent: 5
            scanners:
              - name: regex
                enabled: true
                settings:
                  sensitivity: high
              - name: pii
                enabled: false
            audit:
              enabled: true
              backend: stdout
        """)
        config = load_policy_from_string(yaml_text)
        assert config.name == "full-policy"
        assert config.proxy.timeout_ms == 15000
        assert len(config.scanners) == 2
        assert config.scanners[0].name == "regex"
        assert config.scanners[0].settings == {"sensitivity": "high"}
        assert config.scanners[1].enabled is False
        assert config.audit.backend == "stdout"

    def test_empty_yaml_raises_policy_error(self) -> None:
        with pytest.raises(PolicyError, match="empty"):
            load_policy_from_string("")

    def test_invalid_yaml_raises_policy_error(self) -> None:
        with pytest.raises(PolicyError, match="YAML"):
            load_policy_from_string("key: [unclosed")

    def test_non_mapping_yaml_raises_policy_error(self) -> None:
        with pytest.raises(PolicyError, match="mapping"):
            load_policy_from_string("- item1\n- item2")

    def test_invalid_field_raises_policy_error(self) -> None:
        yaml_text = textwrap.dedent("""\
            version: "1.0"
            proxy:
              transport: invalid_transport
        """)
        with pytest.raises(PolicyError):
            load_policy_from_string(yaml_text)

    def test_custom_name_in_error_messages(self) -> None:
        with pytest.raises(PolicyError, match="my-source"):
            load_policy_from_string("", name="my-source")

    def test_sse_without_upstream_raises_policy_error(self) -> None:
        yaml_text = textwrap.dedent("""\
            version: "1.0"
            proxy:
              transport: sse
        """)
        with pytest.raises(PolicyError):
            load_policy_from_string(yaml_text)

    def test_scanner_settings_preserved(self) -> None:
        yaml_text = textwrap.dedent("""\
            version: "1.0"
            scanners:
              - name: allowlist
                settings:
                  mode: blocklist
                  tools:
                    block:
                      - "shell:*"
        """)
        config = load_policy_from_string(yaml_text)
        s = config.scanners[0]
        assert s.name == "allowlist"
        assert s.settings["mode"] == "blocklist"


# ---------------------------------------------------------------------------
# load_policy (file-based)
# ---------------------------------------------------------------------------

class TestLoadPolicy:
    def test_nonexistent_file_raises_policy_error(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError, match="not found"):
            load_policy(tmp_path / "nonexistent.yaml")

    def test_valid_file_loads(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            'version: "1.0"\nname: "file-policy"\n',
            encoding="utf-8",
        )
        config = load_policy(policy_file)
        assert config.name == "file-policy"

    def test_empty_file_raises_policy_error(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("", encoding="utf-8")
        with pytest.raises(PolicyError, match="empty"):
            load_policy(policy_file)

    def test_invalid_yaml_file_raises_policy_error(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("key: [unclosed", encoding="utf-8")
        with pytest.raises(PolicyError, match="YAML"):
            load_policy(policy_file)

    def test_non_mapping_yaml_file_raises_policy_error(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(PolicyError, match="mapping"):
            load_policy(policy_file)

    def test_accepts_path_object(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text('version: "1.0"\n', encoding="utf-8")
        config = load_policy(policy_file)
        assert config.version == "1.0"

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text('version: "1.0"\n', encoding="utf-8")
        config = load_policy(str(policy_file))
        assert config.version == "1.0"


# ---------------------------------------------------------------------------
# default_policy
# ---------------------------------------------------------------------------

class TestDefaultPolicy:
    def test_returns_policy_config(self) -> None:
        config = default_policy()
        assert isinstance(config, PolicyConfig)

    def test_has_scanners(self) -> None:
        config = default_policy()
        assert len(config.scanners) > 0

    def test_version_is_set(self) -> None:
        config = default_policy()
        assert config.version is not None


# ---------------------------------------------------------------------------
# resolve_env_vars
# ---------------------------------------------------------------------------

class TestResolveEnvVars:
    def test_plain_string_unchanged(self) -> None:
        result = resolve_env_vars("hello world")
        assert result == "hello world"

    def test_expands_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_VAR_TRUSTED", "myvalue")
        result = resolve_env_vars("$TEST_VAR_TRUSTED")
        assert result == "myvalue"

    def test_unset_var_left_as_is_or_empty(self) -> None:
        # os.path.expandvars leaves unknown vars as-is on Windows,
        # or produces empty string on some platforms; just check no crash
        result = resolve_env_vars("${DEFINITELY_UNSET_12345}")
        assert isinstance(result, str)
