"""RuleFileScanner — Scanner that loads YAML rules from trusted-mcp-rules.

Bridges the community rule repository with the trusted-mcp scanner chain.
Rules are loaded from YAML files on disk and compiled into regex patterns
that are evaluated during scan_request() and scan_tool_description().

Example
-------
::

    from trusted_mcp.scanners.rule_file_scanner import RuleFileScanner

    scanner = RuleFileScanner(config={"rules_dir": "/path/to/rules"})
    result = await scanner.scan_request(request)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from trusted_mcp.core.result import Action, ScanResult
from trusted_mcp.core.scanner import Scanner, ToolCallRequest, ToolCallResponse, ToolDefinition

logger = logging.getLogger(__name__)


@dataclass
class RulePattern:
    """A compiled regex pattern from a YAML rule file."""

    regex: re.Pattern[str]
    description: str


@dataclass
class LoadedRule:
    """A fully loaded rule with compiled patterns."""

    id: str
    name: str
    category: str
    severity: str
    description: str
    patterns: list[RulePattern] = field(default_factory=list)


# Map rule severity strings to scan result actions
_SEVERITY_TO_ACTION: dict[str, Action] = {
    "critical": Action.BLOCK,
    "high": Action.BLOCK,
    "medium": Action.WARN,
    "low": Action.WARN,
    "info": Action.PASS,
}


class RuleFileScanner(Scanner):
    """Scanner that loads and applies community YAML rules.

    Parameters
    ----------
    config:
        Configuration dict. Supported keys:

        - ``rules_dir`` (str): Path to the directory of YAML rule files.
          Defaults to looking for a ``rules/`` directory next to the package.
        - ``categories`` (list[str] | None): Only load rules from these categories.
          Pass ``None`` to load all.
        - ``severity_threshold`` (str): Minimum severity that produces a WARN/BLOCK
          action. Rules below this severity are treated as PASS. Default: "low".

    """

    name: str = "rule_file"

    def __init__(self, config: dict[str, object] | None = None) -> None:
        cfg = config or {}
        rules_dir_raw = cfg.get("rules_dir", "")
        self._rules_dir = Path(str(rules_dir_raw)) if rules_dir_raw else None
        categories_raw = cfg.get("categories")
        self._categories: list[str] | None = (
            list(categories_raw) if isinstance(categories_raw, list) else None  # type: ignore[arg-type]
        )
        self._severity_threshold = str(cfg.get("severity_threshold", "low"))
        self._rules: list[LoadedRule] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Lazy-load rules from disk on first use."""
        if self._loaded:
            return
        self._loaded = True

        if self._rules_dir is None or not self._rules_dir.exists():
            logger.info(
                "RuleFileScanner: no rules directory configured or found — scanning disabled"
            )
            return

        try:
            import yaml
        except ImportError:
            logger.warning("RuleFileScanner: pyyaml not installed — scanning disabled")
            return

        for yaml_path in sorted(self._rules_dir.rglob("*.yaml")):
            try:
                with open(yaml_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                category = data.get("category", "")
                if self._categories is not None and category not in self._categories:
                    continue

                patterns: list[RulePattern] = []
                for pat in data.get("patterns", []):
                    regex_str = pat.get("regex", "")
                    if regex_str:
                        patterns.append(
                            RulePattern(
                                regex=re.compile(regex_str, re.IGNORECASE),
                                description=pat.get("description", ""),
                            )
                        )

                if patterns:
                    self._rules.append(
                        LoadedRule(
                            id=data.get("id", yaml_path.stem),
                            name=data.get("name", ""),
                            category=category,
                            severity=data.get("severity", "medium"),
                            description=data.get("description", ""),
                            patterns=patterns,
                        )
                    )
                    logger.debug("Loaded rule %s: %s", data.get("id"), data.get("name"))
            except Exception as exc:
                logger.warning("Failed to load rule from %s: %s", yaml_path, exc)

        logger.info(
            "RuleFileScanner: loaded %d rules from %s", len(self._rules), self._rules_dir
        )

    def _match_text(self, text: str) -> ScanResult:
        """Match text against all loaded rules and return the first hit."""
        self._ensure_loaded()

        for rule in self._rules:
            for pattern in rule.patterns:
                if pattern.regex.search(text):
                    action = _SEVERITY_TO_ACTION.get(rule.severity, Action.WARN)
                    return ScanResult(
                        action=action,
                        reason=f"Rule {rule.id} ({rule.name}): {pattern.description}",
                        scanner_name=self.name,
                        details={
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "category": rule.category,
                            "severity": rule.severity,
                            "pattern": pattern.description,
                        },
                    )

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_request(self, request: ToolCallRequest) -> ScanResult:
        """Scan a tool call request against community rules.

        Checks the tool name and all string values in the arguments dict.
        """
        self._ensure_loaded()

        # Check tool name
        result = self._match_text(request.tool_name)
        if result.action != Action.PASS:
            return result

        # Check argument values
        for _key, value in request.arguments.items():
            if isinstance(value, str):
                result = self._match_text(value)
                if result.action != Action.PASS:
                    return result

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_response(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> ScanResult:
        """Scan a tool response against community rules."""
        self._ensure_loaded()

        content = response.content
        if isinstance(content, str):
            return self._match_text(content)

        return ScanResult(action=Action.PASS, scanner_name=self.name)

    async def scan_tool_description(self, tool: ToolDefinition) -> ScanResult:
        """Scan a tool description against community rules."""
        self._ensure_loaded()
        return self._match_text(tool.description)
