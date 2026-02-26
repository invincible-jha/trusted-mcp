"""Configuration management for trusted-mcp.

Merges configuration from (in decreasing priority order):
1. Explicit keyword arguments
2. Environment variables (TRUSTED_MCP_* prefix)
3. Config file (JSON or YAML)
4. Built-in defaults

Environment Variables
---------------------
All settings can be overridden with environment variables using the
TRUSTED_MCP_ prefix and uppercase names:

    TRUSTED_MCP_POLICY_PATH=/etc/trusted-mcp/policy.yaml
    TRUSTED_MCP_LOG_LEVEL=debug
    TRUSTED_MCP_TRANSPORT=sse
    TRUSTED_MCP_UPSTREAM=https://mcp.example.com/sse
    TRUSTED_MCP_AUDIT_PATH=/var/log/trusted-mcp/audit.jsonl
    TRUSTED_MCP_AUDIT_BACKEND=stdout

Example
-------
::

    from trusted_mcp.core.config import AppConfig, load_config

    config = load_config()
    print(config.policy_path)   # from env or default
    print(config.log_level)     # "info"
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from trusted_mcp.core.exceptions import ConfigError

logger = logging.getLogger(__name__)

_ENV_PREFIX = "TRUSTED_MCP_"


class AppConfig(BaseModel):
    """Top-level application configuration.

    This is distinct from PolicyConfig — AppConfig controls runtime
    behaviour (log level, policy file path) while PolicyConfig controls
    scanner and proxy settings loaded from the policy YAML.

    Attributes
    ----------
    policy_path:
        Path to the YAML policy file to load. If None, the default
        built-in policy is used.
    log_level:
        Python logging level name. Case-insensitive.
    data_dir:
        Directory for runtime data files (hash stores, audit logs).
        Defaults to .trusted-mcp/ in the current working directory.
    transport:
        Override the policy's transport setting. Useful for CLI flags.
    upstream:
        Override the policy's upstream URL. Useful for CLI flags.
    audit_path:
        Override the policy's audit log path.
    audit_backend:
        Override the policy's audit backend.
    """

    policy_path: str | None = None
    log_level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    data_dir: str = ".trusted-mcp"
    transport: Literal["stdio", "sse"] | None = None
    upstream: str | None = None
    audit_path: str | None = None
    audit_backend: Literal["file", "stdout"] | None = None

    @field_validator("log_level", mode="before")
    @classmethod
    def normalise_log_level(cls, value: object) -> str:
        """Accept any case for log level names."""
        if isinstance(value, str):
            return value.lower()
        raise ValueError(f"log_level must be a string, got {type(value).__name__}")

    def resolved_data_dir(self) -> Path:
        """Return the data directory as a resolved absolute Path.

        Returns
        -------
        Path
            Absolute path to the data directory.
        """
        return Path(self.data_dir).resolve()

    def python_log_level(self) -> int:
        """Convert the log_level string to a Python logging constant.

        Returns
        -------
        int
            e.g. logging.DEBUG, logging.INFO, etc.
        """
        return getattr(logging, self.log_level.upper(), logging.INFO)


def _env_key(field_name: str) -> str:
    """Convert a field name to its environment variable name."""
    return f"{_ENV_PREFIX}{field_name.upper()}"


def _load_env_overrides() -> dict[str, str]:
    """Read all TRUSTED_MCP_* environment variables.

    Returns
    -------
    dict[str, str]
        Mapping of lowercase field names to string values from env.
    """
    overrides: dict[str, str] = {}
    field_names = AppConfig.model_fields.keys()
    for field_name in field_names:
        env_var = _env_key(field_name)
        value = os.environ.get(env_var)
        if value is not None:
            overrides[field_name] = value
    return overrides


def _load_config_file(path: str | Path) -> dict[str, object]:
    """Load a JSON or YAML config file.

    Parameters
    ----------
    path:
        Path to the config file. Extension determines the parser
        (.json uses JSON, all others use YAML).

    Returns
    -------
    dict[str, object]
        Parsed config data.

    Raises
    ------
    ConfigError
        If the file cannot be read or parsed.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {config_path}: {exc}") from exc

    try:
        if config_path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot parse config file {config_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(
            f"Config file {config_path} must contain a mapping at the top level"
        )

    return data  # type: ignore[return-value]


def load_config(
    config_file: str | Path | None = None,
    **overrides: object,
) -> AppConfig:
    """Load and merge application configuration.

    Priority (highest to lowest):
    1. Keyword arguments passed directly to this function.
    2. TRUSTED_MCP_* environment variables.
    3. Config file (if provided).
    4. Built-in defaults.

    Parameters
    ----------
    config_file:
        Optional path to a JSON or YAML config file.
    **overrides:
        Explicit field overrides (highest priority).

    Returns
    -------
    AppConfig
        Merged and validated configuration.

    Raises
    ------
    ConfigError
        If the config file cannot be read or any value fails validation.
    """
    merged: dict[str, object] = {}

    # Layer 3: Config file
    if config_file is not None:
        file_data = _load_config_file(config_file)
        merged.update(file_data)

    # Layer 2: Environment variables
    env_data = _load_env_overrides()
    merged.update(env_data)

    # Layer 1: Explicit overrides
    merged.update({k: v for k, v in overrides.items() if v is not None})

    try:
        return AppConfig.model_validate(merged)
    except Exception as exc:
        raise ConfigError(f"Configuration validation failed: {exc}") from exc


def configure_logging(config: AppConfig) -> None:
    """Apply the log level from AppConfig to the root logger.

    Parameters
    ----------
    config:
        The loaded application configuration.
    """
    level = config.python_log_level()
    # basicConfig is a no-op when the root logger already has handlers
    # (e.g. when running under pytest). Always set the level explicitly so
    # that callers reliably observe the configured level on the root logger.
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logging.getLogger().setLevel(level)
    logger.debug("Logging configured at level %s", config.log_level.upper())
