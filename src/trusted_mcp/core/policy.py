"""Policy configuration loading and validation.

Loads YAML policy files and validates them via Pydantic v2 models.
A policy file controls which scanners are active, how the proxy is
configured, and how audit logging is handled.

YAML Policy Format
------------------
::

    version: "1.0"
    name: "my-policy"

    proxy:
      transport: stdio
      upstream: null
      timeout_ms: 30000
      max_concurrent: 10

    scanners:
      - name: description_hash
        enabled: true
        settings:
          store_path: .trusted-mcp/hashes.json
      - name: regex
        enabled: true
        settings:
          sensitivity: medium

    audit:
      enabled: true
      backend: file
      path: .trusted-mcp/audit.jsonl
      retention_days: 30
      redact_pii: true

Example
-------
::

    from trusted_mcp.core.policy import load_policy

    policy = load_policy("policy.yaml")
    print(policy.name)         # "my-policy"
    print(policy.proxy.transport)  # "stdio"
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from trusted_mcp.core.exceptions import PolicyError


class ProxyConfig(BaseModel):
    """Proxy transport and connection settings.

    Attributes
    ----------
    transport:
        MCP transport type. "stdio" for local subprocess servers,
        "sse" for remote HTTP/SSE servers.
    upstream:
        Upstream MCP server URL (for SSE transport) or None for
        stdio auto-detection.
    timeout_ms:
        Tool call timeout in milliseconds.
    max_concurrent:
        Maximum number of concurrent tool calls.
    """

    transport: Literal["stdio", "sse"] = "stdio"
    upstream: str | None = None
    timeout_ms: int = Field(default=30000, gt=0)
    max_concurrent: int = Field(default=10, gt=0)


class ScannerConfig(BaseModel):
    """Configuration for a single scanner in the chain.

    Attributes
    ----------
    name:
        The registered name of the scanner (must exist in ScannerRegistry).
    enabled:
        Whether this scanner is active. Disabled scanners are not
        instantiated or included in the chain.
    settings:
        Scanner-specific settings passed to the scanner constructor.
    """

    name: str
    enabled: bool = True
    settings: dict[str, object] = Field(default_factory=dict)


class AuditConfig(BaseModel):
    """Audit logging configuration.

    Attributes
    ----------
    enabled:
        Whether audit logging is active.
    backend:
        Storage backend. "file" writes JSON Lines to disk,
        "stdout" prints to stdout.
    path:
        File path for the "file" backend. Ignored for "stdout".
    retention_days:
        Number of days to retain log files before rotation/deletion.
    redact_pii:
        If True, PII detected in audit entries is redacted before writing.
    max_file_size_mb:
        Maximum size of a single log file in megabytes before rotation.
    """

    enabled: bool = True
    backend: Literal["file", "stdout"] = "file"
    path: str = ".trusted-mcp/audit.jsonl"
    retention_days: int = Field(default=30, gt=0)
    redact_pii: bool = True
    max_file_size_mb: int = Field(default=100, gt=0)


class PolicyConfig(BaseModel):
    """Root policy configuration model.

    Attributes
    ----------
    version:
        Policy schema version. Currently "1.0".
    name:
        Human-readable policy name for identification in audit logs.
    proxy:
        Proxy transport and connection settings.
    scanners:
        Ordered list of scanner configurations. Scanners are executed
        in list order; earlier scanners run first.
    audit:
        Audit logging configuration.
    """

    version: str = "1.0"
    name: str = "default"
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    scanners: list[ScannerConfig] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @model_validator(mode="after")
    def check_sse_requires_upstream(self) -> "PolicyConfig":
        """Validate that SSE transport has an upstream URL."""
        if self.proxy.transport == "sse" and not self.proxy.upstream:
            raise ValueError(
                "proxy.upstream must be set when proxy.transport is 'sse'"
            )
        return self

    def active_scanners(self) -> list[ScannerConfig]:
        """Return only the enabled scanner configurations.

        Returns
        -------
        list[ScannerConfig]
            Scanner configs where enabled is True, in original order.
        """
        return [s for s in self.scanners if s.enabled]


def load_policy(path: str | Path) -> PolicyConfig:
    """Load and validate a YAML policy file.

    Reads the YAML file at the given path, parses it, and validates it
    against the PolicyConfig Pydantic model.

    Parameters
    ----------
    path:
        Path to the YAML policy file.

    Returns
    -------
    PolicyConfig
        The validated policy configuration.

    Raises
    ------
    PolicyError
        If the file does not exist, cannot be parsed as YAML, or fails
        Pydantic validation.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {policy_path}")

    try:
        raw_text = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"Cannot read policy file {policy_path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy file {policy_path}: {exc}") from exc

    if data is None:
        raise PolicyError(f"Policy file {policy_path} is empty")

    if not isinstance(data, dict):
        raise PolicyError(
            f"Policy file {policy_path} must be a YAML mapping at the top level"
        )

    try:
        return PolicyConfig.model_validate(data)
    except Exception as exc:
        raise PolicyError(
            f"Policy file {policy_path} failed validation: {exc}"
        ) from exc


def load_policy_from_string(yaml_text: str, name: str = "<string>") -> PolicyConfig:
    """Parse and validate a policy from a YAML string.

    Useful for testing and for generating policies programmatically.

    Parameters
    ----------
    yaml_text:
        YAML-formatted policy content.
    name:
        Descriptive name used in error messages (default "<string>").

    Returns
    -------
    PolicyConfig
        The validated policy configuration.

    Raises
    ------
    PolicyError
        If the text cannot be parsed as YAML or fails validation.
    """
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy {name!r}: {exc}") from exc

    if data is None:
        raise PolicyError(f"Policy {name!r} is empty")

    if not isinstance(data, dict):
        raise PolicyError(f"Policy {name!r} must be a YAML mapping at the top level")

    try:
        return PolicyConfig.model_validate(data)
    except Exception as exc:
        raise PolicyError(f"Policy {name!r} failed validation: {exc}") from exc


def default_policy() -> PolicyConfig:
    """Return a sensible default policy with all built-in scanners enabled.

    Returns
    -------
    PolicyConfig
        Default policy suitable for most use cases.
    """
    _policies_dir = Path(__file__).parents[4] / "policies"
    default_yaml = _policies_dir / "default.yaml"
    if default_yaml.exists():
        return load_policy(default_yaml)

    # Fallback inline default when policies directory is not available
    return PolicyConfig(
        version="1.0",
        name="default",
        proxy=ProxyConfig(),
        scanners=[
            ScannerConfig(name="description_hash", enabled=True),
            ScannerConfig(
                name="allowlist",
                enabled=True,
                settings={"mode": "blocklist", "tools": {"block": []}},
            ),
            ScannerConfig(
                name="regex",
                enabled=True,
                settings={"sensitivity": "medium"},
            ),
            ScannerConfig(
                name="argument",
                enabled=True,
                settings={"strict_types": True},
            ),
            ScannerConfig(
                name="pii",
                enabled=True,
                settings={
                    "action_on_detect": "warn",
                    "patterns": ["ssn", "email", "phone", "credit_card"],
                },
            ),
        ],
        audit=AuditConfig(),
    )


def resolve_env_vars(text: str) -> str:
    """Expand ``${VAR}`` and ``$VAR`` patterns in a string using os.environ.

    Parameters
    ----------
    text:
        The string potentially containing environment variable references.

    Returns
    -------
    str
        The string with environment variables expanded.
    """
    return os.path.expandvars(text)
