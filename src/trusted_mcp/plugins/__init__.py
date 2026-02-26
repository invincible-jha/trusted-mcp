"""Plugin subsystem for trusted-mcp.

The registry module provides the decorator-based registration surface.
Third-party implementations register via this system using
``importlib.metadata`` entry-points under the "trusted_mcp.plugins"
group.

Example
-------
Declare a plugin in pyproject.toml:

.. code-block:: toml

    [trusted_mcp.plugins]
    my_plugin = "my_package.plugins.my_plugin:MyPlugin"
"""
from __future__ import annotations

from trusted_mcp.plugins.registry import PluginRegistry
from trusted_mcp.core.scanner import Scanner

# Global scanner registry — all built-in and registered scanner classes are
# registered here so that policy YAML files can reference them by name.
scanner_registry: PluginRegistry[Scanner] = PluginRegistry(Scanner, "scanners")

__all__ = ["PluginRegistry", "scanner_registry"]
