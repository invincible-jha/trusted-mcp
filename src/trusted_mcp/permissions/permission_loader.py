"""Load per-tool permissions from a YAML configuration file.

YAML schema
-----------
::

    permissions:
      - tool_name: read_file
        allowed_paths:
          - "/workspace/**"
          - "/tmp/*.txt"
        max_response_size: 65536
        requires_approval: false
        allowed_argument_keys: ["path", "encoding"]
        denied_argument_values:
          path:
            - "/etc/passwd"
            - "/etc/shadow"

      - tool_name: execute_command
        requires_approval: true
        max_response_size: 1048576
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from trusted_mcp.permissions.tool_permissions import ToolPermission, ToolPermissionChecker

logger = logging.getLogger(__name__)


def _parse_permission_entry(entry: dict[str, object]) -> ToolPermission:
    """Parse a single YAML permission entry into a ToolPermission.

    Parameters
    ----------
    entry:
        Dictionary loaded from YAML representing one tool's permission block.

    Returns
    -------
    ToolPermission
        Validated, immutable permission record.

    Raises
    ------
    ValueError
        If the entry is missing required fields or has an invalid type.
    """
    tool_name = entry.get("tool_name")
    if not tool_name or not isinstance(tool_name, str):
        raise ValueError(
            f"Each permission entry must have a non-empty 'tool_name' string. "
            f"Got: {entry!r}"
        )

    allowed_paths_raw = entry.get("allowed_paths", [])
    if not isinstance(allowed_paths_raw, list):
        raise ValueError(
            f"'allowed_paths' for tool '{tool_name}' must be a list, "
            f"got {type(allowed_paths_raw).__name__}."
        )
    allowed_paths: list[str] = [str(p) for p in allowed_paths_raw]

    max_response_size_raw = entry.get("max_response_size", 0)
    if not isinstance(max_response_size_raw, int) or max_response_size_raw < 0:
        raise ValueError(
            f"'max_response_size' for tool '{tool_name}' must be a non-negative int, "
            f"got {max_response_size_raw!r}."
        )

    requires_approval = bool(entry.get("requires_approval", False))

    allowed_keys_raw = entry.get("allowed_argument_keys", [])
    if not isinstance(allowed_keys_raw, list):
        raise ValueError(
            f"'allowed_argument_keys' for tool '{tool_name}' must be a list."
        )
    allowed_argument_keys: list[str] = [str(k) for k in allowed_keys_raw]

    denied_raw = entry.get("denied_argument_values", {})
    if not isinstance(denied_raw, dict):
        raise ValueError(
            f"'denied_argument_values' for tool '{tool_name}' must be a mapping."
        )
    denied_argument_values: dict[str, list[str]] = {
        str(k): [str(v) for v in values]
        for k, values in denied_raw.items()
        if isinstance(values, list)
    }

    return ToolPermission.create(
        tool_name=tool_name,
        allowed_paths=allowed_paths,
        max_response_size=max_response_size_raw,
        requires_approval=requires_approval,
        allowed_argument_keys=allowed_argument_keys,
        denied_argument_values=denied_argument_values,
    )


def load_permissions_from_yaml(yaml_content: str) -> list[ToolPermission]:
    """Parse YAML text and return a list of ToolPermission objects.

    Parameters
    ----------
    yaml_content:
        Raw YAML string following the schema described in this module's
        docstring.

    Returns
    -------
    list[ToolPermission]
        Parsed permission objects, in document order.

    Raises
    ------
    ValueError
        If the YAML is structurally invalid.
    yaml.YAMLError
        If the YAML cannot be parsed.
    """
    data = yaml.safe_load(yaml_content)
    if data is None:
        return []

    if not isinstance(data, dict):
        raise ValueError(
            f"Top-level YAML must be a mapping with a 'permissions' key, "
            f"got {type(data).__name__}."
        )

    entries = data.get("permissions", [])
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError(
            f"'permissions' key must be a list, got {type(entries).__name__}."
        )

    permissions: list[ToolPermission] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Entry at index {index} in 'permissions' must be a mapping, "
                f"got {type(entry).__name__}."
            )
        try:
            perm = _parse_permission_entry(entry)
        except ValueError as exc:
            raise ValueError(
                f"Invalid permission entry at index {index}: {exc}"
            ) from exc
        permissions.append(perm)
        logger.debug("Loaded permission for tool %r", perm.tool_name)

    return permissions


class PermissionLoader:
    """High-level loader that reads YAML files and populates a ToolPermissionChecker.

    Usage
    -----
    ::

        loader = PermissionLoader()
        checker = loader.load_file(Path("permissions.yaml"))
        violations = checker.check_request("read_file", {"path": "/etc/passwd"})
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """Initialise the loader.

        Parameters
        ----------
        strict_mode:
            Passed through to the created ToolPermissionChecker.
        """
        self.strict_mode = strict_mode

    def load_file(self, path: Path) -> ToolPermissionChecker:
        """Load permissions from a YAML file and return a configured checker.

        Parameters
        ----------
        path:
            Filesystem path to the YAML permission configuration file.

        Returns
        -------
        ToolPermissionChecker
            Checker pre-populated with all permissions from the file.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        ValueError
            If the file content is structurally invalid.
        yaml.YAMLError
            If the YAML cannot be parsed.
        """
        if not path.exists():
            raise FileNotFoundError(
                f"Permission configuration file not found: {path}"
            )

        yaml_content = path.read_text(encoding="utf-8")
        return self.load_string(yaml_content)

    def load_string(self, yaml_content: str) -> ToolPermissionChecker:
        """Load permissions from a YAML string and return a configured checker.

        Parameters
        ----------
        yaml_content:
            Raw YAML content following the permission schema.

        Returns
        -------
        ToolPermissionChecker
            Checker pre-populated with all permissions from the YAML.
        """
        permissions = load_permissions_from_yaml(yaml_content)
        checker = ToolPermissionChecker(strict_mode=self.strict_mode)
        checker.register_many(permissions)
        logger.info(
            "Loaded %d permission policies from YAML", len(permissions)
        )
        return checker
