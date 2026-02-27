"""Per-tool permission dataclasses and checker.

ToolPermission captures the access policy for a single MCP tool.
ToolPermissionChecker validates incoming tool invocations against their
registered permission sets and raises or returns structured violations.

Design
------
- Glob-pattern path matching via fnmatch (stdlib only — no extra deps).
- Max response size enforced at the checker layer, not the proxy layer,
  so scanners remain composable.
- Approval-required tools are flagged via PermissionViolation; the proxy
  layer decides whether to block or queue for human review.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ViolationType(str, Enum):
    """Category of permission violation detected by ToolPermissionChecker."""

    PATH_NOT_ALLOWED = "path_not_allowed"
    RESPONSE_TOO_LARGE = "response_too_large"
    APPROVAL_REQUIRED = "approval_required"
    TOOL_NOT_REGISTERED = "tool_not_registered"
    ARGUMENT_TYPE_INVALID = "argument_type_invalid"


@dataclass(frozen=True)
class PermissionViolation:
    """Structured record of a single permission violation.

    Attributes
    ----------
    tool_name:
        The name of the tool that triggered the violation.
    violation_type:
        The category of violation.
    detail:
        Human-readable explanation of the violation.
    argument_key:
        If the violation relates to a specific argument, its key.
    offending_value:
        The argument value (or response size) that caused the violation.
    """

    tool_name: str
    violation_type: ViolationType
    detail: str
    argument_key: str = ""
    offending_value: str = ""


@dataclass(frozen=True)
class ToolPermission:
    """Access-control policy for a single MCP tool.

    Attributes
    ----------
    tool_name:
        The exact MCP tool name this policy applies to.
    allowed_paths:
        Glob patterns that file-path arguments must match.
        If empty, no path restriction is applied.
    max_response_size:
        Maximum number of bytes allowed in the tool response content.
        Use 0 to disable the limit.
    requires_approval:
        If True, every invocation of this tool requires explicit
        human approval before being forwarded upstream.
    allowed_argument_keys:
        If non-empty, only these argument keys are permitted.
        Any extra keys are flagged as a violation.
    denied_argument_values:
        Mapping of argument key -> set of literal values that are
        explicitly denied (exact match, case-insensitive).
    """

    tool_name: str
    allowed_paths: tuple[str, ...] = field(default_factory=tuple)
    max_response_size: int = 0
    requires_approval: bool = False
    allowed_argument_keys: tuple[str, ...] = field(default_factory=tuple)
    denied_argument_values: dict[str, frozenset[str]] = field(
        default_factory=dict
    )

    # Pydantic-style factory helpers so callers can pass lists
    @classmethod
    def create(
        cls,
        tool_name: str,
        *,
        allowed_paths: list[str] | None = None,
        max_response_size: int = 0,
        requires_approval: bool = False,
        allowed_argument_keys: list[str] | None = None,
        denied_argument_values: dict[str, list[str]] | None = None,
    ) -> "ToolPermission":
        """Convenience constructor accepting mutable collection types.

        Parameters
        ----------
        tool_name:
            The MCP tool name.
        allowed_paths:
            List of glob patterns for allowed file paths.
        max_response_size:
            Maximum response byte count (0 = unlimited).
        requires_approval:
            Whether the tool requires human approval per invocation.
        allowed_argument_keys:
            Allowlist of argument keys. Empty list means all keys allowed.
        denied_argument_values:
            Mapping of argument key -> denied literal values.

        Returns
        -------
        ToolPermission
            Immutable permission record.
        """
        denied: dict[str, frozenset[str]] = {}
        if denied_argument_values:
            for key, values in denied_argument_values.items():
                denied[key] = frozenset(v.lower() for v in values)

        return cls(
            tool_name=tool_name,
            allowed_paths=tuple(allowed_paths or []),
            max_response_size=max_response_size,
            requires_approval=requires_approval,
            allowed_argument_keys=tuple(allowed_argument_keys or []),
            denied_argument_values=denied,
        )

    def path_is_allowed(self, path_value: str) -> bool:
        """Return True if *path_value* matches at least one allowed pattern.

        Parameters
        ----------
        path_value:
            The file path string extracted from a tool argument.

        Returns
        -------
        bool
            True when no patterns are configured (no restriction) or when
            the value matches at least one allowed-paths glob pattern.
        """
        if not self.allowed_paths:
            return True
        normalized = path_value.replace("\\", "/")
        return any(
            fnmatch.fnmatch(normalized, pattern)
            for pattern in self.allowed_paths
        )


class ToolPermissionChecker:
    """Validates tool invocations against registered ToolPermission policies.

    Usage
    -----
    ::

        checker = ToolPermissionChecker()
        checker.register(
            ToolPermission.create(
                "read_file",
                allowed_paths=["/workspace/**"],
                max_response_size=65536,
            )
        )
        violations = checker.check_request("read_file", {"path": "/etc/passwd"})
        # -> [PermissionViolation(tool_name='read_file', type=PATH_NOT_ALLOWED, ...)]

    Design
    ------
    - Unknown tools get a zero-violation pass by default (permissive mode).
    - Set ``strict_mode=True`` to flag unregistered tools as violations.
    """

    _PATH_ARGUMENT_KEYS: frozenset[str] = frozenset(
        {"path", "file_path", "filepath", "filename", "directory", "dir",
         "source", "destination", "target", "output_path", "input_path"}
    )

    def __init__(self, strict_mode: bool = False) -> None:
        """Initialise the checker.

        Parameters
        ----------
        strict_mode:
            When True, tools with no registered permission produce a
            TOOL_NOT_REGISTERED violation instead of passing silently.
        """
        self._permissions: dict[str, ToolPermission] = {}
        self.strict_mode = strict_mode

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, permission: ToolPermission) -> None:
        """Register a ToolPermission policy.

        Replaces any existing policy for the same tool_name.

        Parameters
        ----------
        permission:
            The policy to register.
        """
        self._permissions[permission.tool_name] = permission
        logger.debug("Registered permission policy for tool %r", permission.tool_name)

    def register_many(self, permissions: list[ToolPermission]) -> None:
        """Batch-register multiple policies.

        Parameters
        ----------
        permissions:
            List of permission objects to register.
        """
        for permission in permissions:
            self.register(permission)

    def get(self, tool_name: str) -> ToolPermission | None:
        """Return the registered policy for *tool_name*, or None.

        Parameters
        ----------
        tool_name:
            The MCP tool name to look up.

        Returns
        -------
        ToolPermission | None
        """
        return self._permissions.get(tool_name)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def check_request(
        self,
        tool_name: str,
        arguments: dict[str, object],
    ) -> list[PermissionViolation]:
        """Validate a tool invocation against its registered permission.

        Parameters
        ----------
        tool_name:
            The tool being invoked.
        arguments:
            The key-value arguments passed to the tool.

        Returns
        -------
        list[PermissionViolation]
            Empty when the invocation is fully compliant.
        """
        violations: list[PermissionViolation] = []
        permission = self._permissions.get(tool_name)

        if permission is None:
            if self.strict_mode:
                violations.append(
                    PermissionViolation(
                        tool_name=tool_name,
                        violation_type=ViolationType.TOOL_NOT_REGISTERED,
                        detail=(
                            f"Tool '{tool_name}' has no registered permission policy "
                            "and strict_mode is enabled."
                        ),
                    )
                )
            return violations

        # 1. Approval gate
        if permission.requires_approval:
            violations.append(
                PermissionViolation(
                    tool_name=tool_name,
                    violation_type=ViolationType.APPROVAL_REQUIRED,
                    detail=(
                        f"Tool '{tool_name}' requires explicit human approval "
                        "before invocation."
                    ),
                )
            )

        # 2. Allowed argument keys
        if permission.allowed_argument_keys:
            allowed_set = set(permission.allowed_argument_keys)
            for key in arguments:
                if key not in allowed_set:
                    violations.append(
                        PermissionViolation(
                            tool_name=tool_name,
                            violation_type=ViolationType.ARGUMENT_TYPE_INVALID,
                            detail=(
                                f"Argument key '{key}' is not in the allowed "
                                f"keys for tool '{tool_name}'."
                            ),
                            argument_key=key,
                        )
                    )

        # 3. Path restrictions
        if permission.allowed_paths:
            for key, value in arguments.items():
                if key.lower() in self._PATH_ARGUMENT_KEYS and isinstance(value, str):
                    if not permission.path_is_allowed(value):
                        violations.append(
                            PermissionViolation(
                                tool_name=tool_name,
                                violation_type=ViolationType.PATH_NOT_ALLOWED,
                                detail=(
                                    f"Path '{value}' for argument '{key}' does not "
                                    f"match any allowed pattern for tool '{tool_name}'."
                                ),
                                argument_key=key,
                                offending_value=value,
                            )
                        )

        # 4. Denied argument values
        for key, denied_values in permission.denied_argument_values.items():
            raw_value = arguments.get(key)
            if raw_value is not None and isinstance(raw_value, str):
                if raw_value.lower() in denied_values:
                    violations.append(
                        PermissionViolation(
                            tool_name=tool_name,
                            violation_type=ViolationType.ARGUMENT_TYPE_INVALID,
                            detail=(
                                f"Argument '{key}' has a denied value '{raw_value}' "
                                f"for tool '{tool_name}'."
                            ),
                            argument_key=key,
                            offending_value=raw_value,
                        )
                    )

        return violations

    def check_response_size(
        self,
        tool_name: str,
        response_content: str | bytes,
    ) -> list[PermissionViolation]:
        """Validate that a tool response does not exceed the configured size limit.

        Parameters
        ----------
        tool_name:
            The tool that produced the response.
        response_content:
            The raw response content to measure.

        Returns
        -------
        list[PermissionViolation]
            Empty when within the limit or no limit is configured.
        """
        violations: list[PermissionViolation] = []
        permission = self._permissions.get(tool_name)

        if permission is None or permission.max_response_size <= 0:
            return violations

        if isinstance(response_content, str):
            size = len(response_content.encode("utf-8"))
        else:
            size = len(response_content)

        if size > permission.max_response_size:
            violations.append(
                PermissionViolation(
                    tool_name=tool_name,
                    violation_type=ViolationType.RESPONSE_TOO_LARGE,
                    detail=(
                        f"Response size {size} bytes exceeds the configured limit of "
                        f"{permission.max_response_size} bytes for tool '{tool_name}'."
                    ),
                    offending_value=str(size),
                )
            )

        return violations

    def is_compliant(
        self,
        tool_name: str,
        arguments: dict[str, object],
    ) -> bool:
        """Return True when the invocation has no violations.

        Convenience wrapper around :meth:`check_request` that ignores
        APPROVAL_REQUIRED violations (since those are not hard blocks).

        Parameters
        ----------
        tool_name:
            The tool being invoked.
        arguments:
            The key-value arguments passed to the tool.

        Returns
        -------
        bool
        """
        violations = self.check_request(tool_name, arguments)
        blocking = [
            v for v in violations
            if v.violation_type != ViolationType.APPROVAL_REQUIRED
        ]
        return len(blocking) == 0
