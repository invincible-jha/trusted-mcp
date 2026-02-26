"""Unit tests for trusted_mcp.core.config."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
import yaml

from trusted_mcp.core.config import AppConfig, configure_logging, load_config
from trusted_mcp.core.exceptions import ConfigError


class TestAppConfig:
    def test_defaults(self) -> None:
        config = AppConfig()
        assert config.policy_path is None
        assert config.log_level == "info"
        assert config.data_dir == ".trusted-mcp"
        assert config.transport is None
        assert config.upstream is None
        assert config.audit_path is None
        assert config.audit_backend is None

    def test_log_level_normalised_to_lowercase(self) -> None:
        config = AppConfig(log_level="DEBUG")
        assert config.log_level == "debug"

    def test_log_level_mixed_case_normalised(self) -> None:
        config = AppConfig(log_level="Warning")
        assert config.log_level == "warning"

    @pytest.mark.parametrize("level", ["debug", "info", "warning", "error", "critical"])
    def test_valid_log_levels(self, level: str) -> None:
        config = AppConfig(log_level=level)
        assert config.log_level == level

    def test_invalid_log_level_raises(self) -> None:
        with pytest.raises(Exception):
            AppConfig(log_level="verbose")  # type: ignore[arg-type]

    def test_non_string_log_level_raises(self) -> None:
        with pytest.raises(Exception):
            AppConfig(log_level=42)  # type: ignore[arg-type]

    def test_resolved_data_dir_is_absolute(self) -> None:
        config = AppConfig(data_dir=".trusted-mcp")
        resolved = config.resolved_data_dir()
        assert resolved.is_absolute()

    def test_resolved_data_dir_custom(self, tmp_path: Path) -> None:
        config = AppConfig(data_dir=str(tmp_path / "data"))
        resolved = config.resolved_data_dir()
        assert "data" in str(resolved)

    @pytest.mark.parametrize("level,expected_int", [
        ("debug", logging.DEBUG),
        ("info", logging.INFO),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("critical", logging.CRITICAL),
    ])
    def test_python_log_level_returns_correct_constant(
        self, level: str, expected_int: int
    ) -> None:
        config = AppConfig(log_level=level)
        assert config.python_log_level() == expected_int

    def test_transport_stdio(self) -> None:
        config = AppConfig(transport="stdio")
        assert config.transport == "stdio"

    def test_transport_sse(self) -> None:
        config = AppConfig(transport="sse")
        assert config.transport == "sse"

    def test_invalid_transport_raises(self) -> None:
        with pytest.raises(Exception):
            AppConfig(transport="websocket")  # type: ignore[arg-type]

    def test_audit_backend_file(self) -> None:
        config = AppConfig(audit_backend="file")
        assert config.audit_backend == "file"

    def test_audit_backend_stdout(self) -> None:
        config = AppConfig(audit_backend="stdout")
        assert config.audit_backend == "stdout"

    def test_invalid_audit_backend_raises(self) -> None:
        with pytest.raises(Exception):
            AppConfig(audit_backend="s3")  # type: ignore[arg-type]


class TestLoadConfig:
    def test_defaults_when_no_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Clear all TRUSTED_MCP_* env vars to get pure defaults
        for key in list(__import__("os").environ.keys()):
            if key.startswith("TRUSTED_MCP_"):
                monkeypatch.delenv(key, raising=False)
        config = load_config()
        assert config.log_level == "info"
        assert config.data_dir == ".trusted-mcp"

    def test_explicit_override_wins(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRUSTED_MCP_LOG_LEVEL", raising=False)
        config = load_config(log_level="debug")
        assert config.log_level == "debug"

    def test_env_var_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRUSTED_MCP_LOG_LEVEL", "warning")
        config = load_config()
        assert config.log_level == "warning"

    def test_explicit_override_beats_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRUSTED_MCP_LOG_LEVEL", "error")
        config = load_config(log_level="debug")
        assert config.log_level == "debug"

    def test_json_config_file_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for key in list(__import__("os").environ.keys()):
            if key.startswith("TRUSTED_MCP_"):
                monkeypatch.delenv(key, raising=False)
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"log_level": "warning", "data_dir": "/tmp/data"}),
            encoding="utf-8",
        )
        config = load_config(config_file=config_file)
        assert config.log_level == "warning"

    def test_yaml_config_file_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for key in list(__import__("os").environ.keys()):
            if key.startswith("TRUSTED_MCP_"):
                monkeypatch.delenv(key, raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("log_level: error\n", encoding="utf-8")
        config = load_config(config_file=config_file)
        assert config.log_level == "error"

    def test_nonexistent_config_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_config(config_file=tmp_path / "nonexistent.yaml")

    def test_invalid_json_config_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text("{invalid json}", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(config_file=config_file)

    def test_invalid_yaml_config_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("key: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(config_file=config_file)

    def test_non_mapping_config_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("- item1\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(config_file=config_file)

    def test_env_var_policy_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRUSTED_MCP_POLICY_PATH", "/etc/policy.yaml")
        config = load_config()
        assert config.policy_path == "/etc/policy.yaml"

    def test_env_var_audit_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRUSTED_MCP_AUDIT_BACKEND", "stdout")
        config = load_config()
        assert config.audit_backend == "stdout"


class TestConfigureLogging:
    def test_sets_log_level_on_root_logger(self) -> None:
        config = AppConfig(log_level="debug")
        configure_logging(config)
        root_logger = logging.getLogger()
        assert root_logger.level <= logging.DEBUG
