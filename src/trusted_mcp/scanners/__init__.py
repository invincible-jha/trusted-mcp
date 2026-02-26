# Copyright 2024 AumOS Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Commodity security scanners for trusted-mcp.

All scanners in this package implement the Scanner ABC defined in
``trusted_mcp.core.scanner`` and are automatically registered with
the global ``scanner_registry`` when this package is imported.

Available Scanners
------------------
BasicRegexScanner (name="regex")
    Commodity regex-based scanner using patterns from OWASP and public
    security literature. Detects prompt injection, shell injection,
    SQL injection, path traversal, and obfuscation attempts.

BasicAllowlistScanner (name="allowlist")
    Static tool allowlist and blocklist enforcement. Supports wildcard
    glob patterns (``server:*``, ``github:create_*``).

BasicArgumentScanner (name="argument")
    Validates tool call arguments against configured rules: type checks,
    length limits, numeric ranges, required fields, allowed values.

DescriptionHashScanner (name="description_hash")
    SHA-256 hash comparison to detect tool description rug-pull attacks.
    Stores baseline hashes on first encounter and blocks mismatches.

BasicPIIScanner (name="pii")
    Scans tool responses for common PII patterns (SSN, email, phone,
    credit card, AWS keys, etc.) before they reach the LLM context.

What These Scanners Are NOT
---------------------------
These are commodity implementations only. They do NOT include:
- ML-based classification (available via plugins)
- Reasoning-layer invariant analysis (available via plugins)
- Session correlation engine (available via plugins)
- Behavioral drift detection (available via plugins)
"""
from __future__ import annotations

from trusted_mcp.scanners.allowlist_scanner import BasicAllowlistScanner
from trusted_mcp.scanners.argument_scanner import BasicArgumentScanner
from trusted_mcp.scanners.description_hash import DescriptionHashScanner
from trusted_mcp.scanners.pii_scanner import BasicPIIScanner
from trusted_mcp.scanners.regex_scanner import BasicRegexScanner

# Register all built-in scanners with the global plugin registry so that
# policy YAML files can reference them by name.
from trusted_mcp.plugins.registry import PluginRegistry
from trusted_mcp.core.scanner import Scanner

# Lazy import to avoid circular dependency — the registry import triggers
# trusted_mcp.core which is fine, but we want scanners importable standalone.
def _register_builtin_scanners() -> None:
    """Register all built-in scanners with the global scanner registry."""
    from trusted_mcp.plugins import scanner_registry  # type: ignore[attr-defined]

    _builtins: list[tuple[str, type[Scanner]]] = [
        ("regex", BasicRegexScanner),
        ("allowlist", BasicAllowlistScanner),
        ("argument", BasicArgumentScanner),
        ("description_hash", DescriptionHashScanner),
        ("pii", BasicPIIScanner),
    ]
    for scanner_name, scanner_class in _builtins:
        if scanner_name not in scanner_registry:
            scanner_registry.register_class(scanner_name, scanner_class)


try:
    _register_builtin_scanners()
except Exception:
    # If the registry is not yet initialised (e.g., during package bootstrap)
    # this is a no-op — callers must ensure scanners are imported before use.
    pass

__all__ = [
    "BasicRegexScanner",
    "BasicAllowlistScanner",
    "BasicArgumentScanner",
    "DescriptionHashScanner",
    "BasicPIIScanner",
]
