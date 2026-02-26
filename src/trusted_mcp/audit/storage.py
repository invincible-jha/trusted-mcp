"""Audit log storage backends.

Provides pluggable storage for audit entries: file-based (with rotation),
stdout (for containerized deployments), and null (for testing).
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trusted_mcp.audit.logger import AuditEntry

from trusted_mcp.audit.formatter import AuditFormatter


class AuditStorage(ABC):
    """Abstract base class for audit log storage backends."""

    @abstractmethod
    async def write(self, entry: AuditEntry) -> None:
        """Persist a single audit entry."""

    async def close(self) -> None:
        """Clean up resources. Default is no-op."""


class FileStorage(AuditStorage):
    """Append-only file storage in JSON Lines format.

    Parameters
    ----------
    path:
        Path to the audit log file.
    max_size_mb:
        Maximum file size in megabytes before rotation. Set to 0
        to disable rotation. Defaults to 100 MB.
    """

    def __init__(self, path: str | Path, max_size_mb: float = 100.0) -> None:
        self._path = Path(path)
        self._max_size_bytes = int(max_size_mb * 1024 * 1024)
        self._formatter = AuditFormatter()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        if self._max_size_bytes <= 0:
            return
        if not self._path.exists():
            return
        if self._path.stat().st_size < self._max_size_bytes:
            return

        # Simple rotation: rename current to .1, .1 to .2, etc.
        for i in range(9, 0, -1):
            old_path = self._path.with_suffix(f".{i}")
            new_path = self._path.with_suffix(f".{i + 1}")
            if old_path.exists():
                old_path.rename(new_path)

        self._path.rename(self._path.with_suffix(".1"))

    async def write(self, entry: AuditEntry) -> None:
        """Append entry as JSONL to the log file."""
        self._rotate_if_needed()
        line = self._formatter.format_json(entry)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class StdoutStorage(AuditStorage):
    """Writes audit entries to stdout in JSON Lines format.

    Suitable for Docker/Kubernetes deployments where logs are
    collected from stdout by the container runtime.
    """

    def __init__(self) -> None:
        self._formatter = AuditFormatter()

    async def write(self, entry: AuditEntry) -> None:
        """Write entry as JSONL to stdout."""
        line = self._formatter.format_json(entry)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


class NullStorage(AuditStorage):
    """Discards all audit entries. For testing and benchmarks."""

    async def write(self, entry: AuditEntry) -> None:
        """No-op."""
