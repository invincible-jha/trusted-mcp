"""Tool description hash scanner for rug-pull attack detection.

Stores SHA-256 hashes of tool descriptions on first encounter and
blocks tool calls when descriptions change — a simple but effective
defense against rug-pull attacks where a tool's behavior is altered
after initial approval.

What This Is NOT
----------------
This is basic hash comparison, NOT:
- Behavioral drift detection (available via plugins)
- Semantic similarity analysis (available via plugins)
- Tool Trust Decay algorithm (available via plugins)
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolDefinition


class DescriptionHashScanner(Scanner):
    """Detects tool description changes via SHA-256 hash comparison.

    On first encounter with a tool, stores the hash of its description.
    On subsequent encounters, compares against the stored baseline. A
    mismatch indicates the description was changed after approval —
    a potential rug-pull attack.

    Parameters
    ----------
    settings:
        Optional configuration dict. Supported keys:

        - ``store_path`` (str): Path to the hash store JSON file.
          Defaults to ``.trusted-mcp/hashes.json``.
        - ``auto_approve_new`` (bool): If True, silently store hashes
          for newly seen tools. If False, emit a WARN for new tools.
          Defaults to True.
    """

    name: str = "description_hash"

    def __init__(self, settings: dict[str, object] | None = None) -> None:
        settings = settings or {}
        store_path = settings.get("store_path", ".trusted-mcp/hashes.json")
        if not isinstance(store_path, str):
            store_path = ".trusted-mcp/hashes.json"
        self.store_path = Path(store_path)
        self.auto_approve_new: bool = bool(settings.get("auto_approve_new", True))
        self._lock = threading.Lock()
        self._hashes: dict[str, str] = self._load_hashes()

    def _load_hashes(self) -> dict[str, str]:
        """Load stored hashes from disk."""
        if not self.store_path.exists():
            return {}
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save_hashes(self) -> None:
        """Persist hashes to disk."""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(
            json.dumps(self._hashes, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    @staticmethod
    def _hash_description(description: str) -> str:
        """Compute SHA-256 hash of a tool description."""
        return hashlib.sha256(description.encode("utf-8")).hexdigest()

    async def scan_request(self, request: object) -> ScanResult:
        """No-op for requests — description scanning happens on tool listing."""
        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Compare tool description hash against stored baseline."""
        current_hash = self._hash_description(tool.description)
        tool_key = f"{tool.server_name}:{tool.name}"

        with self._lock:
            stored_hash = self._hashes.get(tool_key)

            if stored_hash is None:
                # First encounter — store hash
                self._hashes[tool_key] = current_hash
                self._save_hashes()

                if self.auto_approve_new:
                    return ScanResult(
                        action=Action.PASS,
                        scanner_name=self.name,
                        details={"status": "new_tool_registered", "tool": tool_key},
                    )
                return ScanResult(
                    action=Action.WARN,
                    reason=f"New tool '{tool_key}' registered. Hash stored for future verification.",
                    scanner_name=self.name,
                    details={"status": "new_tool_warn", "tool": tool_key},
                )

            if stored_hash != current_hash:
                return ScanResult(
                    action=Action.BLOCK,
                    reason=(
                        f"Tool description changed for '{tool.name}' on server "
                        f"'{tool.server_name}'. Possible rug-pull attack. "
                        f"Review the new description before allowing."
                    ),
                    scanner_name=self.name,
                    details={
                        "tool": tool.name,
                        "server": tool.server_name,
                        "previous_hash": stored_hash[:16] + "...",
                        "current_hash": current_hash[:16] + "...",
                    },
                )

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    def reset_hash(self, server_name: str, tool_name: str) -> bool:
        """Reset the stored hash for a tool, allowing re-approval.

        Returns True if the hash existed and was removed.
        """
        tool_key = f"{server_name}:{tool_name}"
        with self._lock:
            if tool_key in self._hashes:
                del self._hashes[tool_key]
                self._save_hashes()
                return True
        return False

    def list_hashes(self) -> dict[str, str]:
        """Return a copy of all stored tool hashes."""
        with self._lock:
            return dict(self._hashes)
