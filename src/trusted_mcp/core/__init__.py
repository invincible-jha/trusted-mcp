"""Core domain logic for trusted-mcp.

Exports the stable public interfaces:
- Scanner ABC and data models
- ScanResult, ChainResult, Action
- InterceptorChain
- TrustedMCPProxy
- PolicyConfig and related config models
- Custom exception hierarchy
"""
from __future__ import annotations

from trusted_mcp.core.exceptions import (
    AuditError,
    ConfigError,
    PolicyError,
    ProxyError,
    ScannerError,
    ScannerNotFoundError,
    TrustedMCPError,
)
from trusted_mcp.core.interceptor import InterceptorChain
from trusted_mcp.core.policy import (
    AuditConfig,
    PolicyConfig,
    ProxyConfig,
    ScannerConfig,
    load_policy,
    load_policy_from_string,
)
from trusted_mcp.core.proxy import TrustedMCPProxy, UpstreamConnection, build_proxy_from_configs
from trusted_mcp.core.result import Action, ChainResult, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition

__all__ = [
    # Exceptions
    "TrustedMCPError",
    "ScannerError",
    "PolicyError",
    "ProxyError",
    "ConfigError",
    "ScannerNotFoundError",
    "AuditError",
    # Result types
    "Action",
    "ScanResult",
    "ChainResult",
    # Scanner interface
    "Scanner",
    "ToolCallRequest",
    "ToolCallResponse",
    "ToolDefinition",
    # Pipeline
    "InterceptorChain",
    # Proxy
    "TrustedMCPProxy",
    "UpstreamConnection",
    "build_proxy_from_configs",
    # Policy and config
    "PolicyConfig",
    "ProxyConfig",
    "ScannerConfig",
    "AuditConfig",
    "load_policy",
    "load_policy_from_string",
]
