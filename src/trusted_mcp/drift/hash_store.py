"""Approved tool description hash persistence for drift detection.

Provides thread-safe storage and retrieval of SHA-256 hashes for
approved tool descriptions. The default backend is a JSON file at
``~/.trusted-mcp/approved_hashes.json``.

What This Is NOT
----------------
This is a simple local file store. It is NOT:
- A distributed hash store for multi-node deployments
- A signed attestation registry (available via plugins)
- A tamper-evident append-only log (available via plugins)
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_STORE_PATH = Path.home() / ".trusted-mcp" / "approved_hashes.json"


class HashStore:
    """Thread-safe JSON file store for approved tool description hashes.

    Parameters
    ----------
    store_path:
        Path to the JSON file for hash persistence.
        Defaults to ``~/.trusted-mcp/approved_hashes.json``.

    Example
    -------
    ::

        store = HashStore()
        store.save("my_server:my_tool", "abc123...")
        loaded = store.load("my_server:my_tool")  # "abc123..."
        all_tools = store.list_approved()          # ["my_server:my_tool"]
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path: Path = store_path if store_path is not None else _DEFAULT_STORE_PATH
        self._lock = threading.Lock()
        self._data: dict[str, str] = self._load_from_disk()

    def _load_from_disk(self) -> dict[str, str]:
        """Load hash data from the JSON file.

        Returns an empty dict if the file does not exist or is malformed.

        Returns
        -------
        dict[str, str]
            Mapping of tool key to SHA-256 hash string.
        """
        if not self._store_path.exists():
            return {}
        try:
            raw = self._store_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                logger.warning(
                    "Hash store at %s is malformed (not a JSON object); resetting.",
                    self._store_path,
                )
                return {}
            return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load hash store from %s: %s", self._store_path, exc)
            return {}

    def _persist(self) -> None:
        """Write current data to disk. Caller must hold self._lock."""
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            self._store_path.write_text(
                json.dumps(self._data, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Failed to persist hash store to %s: %s", self._store_path, exc)

    def save(self, tool_key: str, hash_value: str) -> None:
        """Store an approved hash for a tool.

        Parameters
        ----------
        tool_key:
            Unique key for the tool, typically ``"server_name:tool_name"``.
        hash_value:
            SHA-256 hex digest of the approved tool description.
        """
        with self._lock:
            self._data[tool_key] = hash_value
            self._persist()
            logger.debug("Stored approved hash for %r", tool_key)

    def load(self, tool_key: str) -> str | None:
        """Retrieve the approved hash for a tool.

        Parameters
        ----------
        tool_key:
            The tool key used when calling ``save``.

        Returns
        -------
        str | None
            The stored SHA-256 hash, or None if the tool has no approved hash.
        """
        with self._lock:
            return self._data.get(tool_key)

    def delete(self, tool_key: str) -> bool:
        """Remove the approved hash for a tool.

        Parameters
        ----------
        tool_key:
            The tool key to remove.

        Returns
        -------
        bool
            True if the key existed and was removed, False otherwise.
        """
        with self._lock:
            if tool_key not in self._data:
                return False
            del self._data[tool_key]
            self._persist()
            logger.debug("Removed approved hash for %r", tool_key)
            return True

    def list_approved(self) -> list[str]:
        """Return all tool keys that have an approved hash.

        Returns
        -------
        list[str]
            Sorted list of tool keys.
        """
        with self._lock:
            return sorted(self._data.keys())

    def clear(self) -> None:
        """Remove all approved hashes from the store and persist the empty state."""
        with self._lock:
            self._data.clear()
            self._persist()
            logger.debug("Cleared all approved hashes from store")
