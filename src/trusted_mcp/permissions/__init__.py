"""Per-tool permission scoping for trusted-mcp.

Provides fine-grained access control for individual MCP tool invocations,
including path-based allow-lists, response size limits, and approval gates.
"""
from __future__ import annotations

from trusted_mcp.permissions.tool_permissions import (
    PermissionViolation,
    ToolPermission,
    ToolPermissionChecker,
    ViolationType,
)
from trusted_mcp.permissions.permission_loader import (
    PermissionLoader,
    load_permissions_from_yaml,
)

__all__ = [
    "ToolPermission",
    "ToolPermissionChecker",
    "PermissionViolation",
    "ViolationType",
    "PermissionLoader",
    "load_permissions_from_yaml",
]
