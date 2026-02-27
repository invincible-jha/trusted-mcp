"""MCP Security Certification levels mapped to OASIS MCP taxonomy.

Defines a 3-tier certification hierarchy (Bronze / Silver / Gold) where
each higher tier is a strict superset of all lower-tier requirements.
The requirements map to the OASIS MCP security taxonomy categories:
injection, authentication, authorization, audit, session, integrity,
data_protection, and supply_chain.

Example
-------
::

    from trusted_mcp.certification.levels import (
        determine_certification_level,
        get_requirements_for_level,
        CertificationLevel,
    )

    passed = {"Prompt Injection Resistance", "Input Validation Completeness",
              "Tool Description Integrity", "PII Handling"}
    level = determine_certification_level(passed)
    print(level)  # CertificationLevel.BRONZE
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CertificationLevel(str, Enum):
    """MCP security certification tiers.

    Values are lowercase strings for natural JSON / YAML serialisation.
    Tier ordering (lowest to highest): NONE < BRONZE < SILVER < GOLD.
    """

    NONE = "none"
    """No certification — at least one Bronze requirement failed."""

    BRONZE = "bronze"
    """Basic injection and integrity controls present."""

    SILVER = "silver"
    """Bronze plus authentication, authorization, and audit controls."""

    GOLD = "gold"
    """Silver plus session security and supply-chain verification."""


@dataclass(frozen=True)
class CertificationRequirement:
    """A single, auditable certification requirement.

    Attributes
    ----------
    category:
        OASIS MCP taxonomy category (e.g. "injection", "audit").
    name:
        Unique human-readable name for this requirement.
        Used as the key in ``passed_requirements`` sets.
    description:
        Full description of what must be true for this requirement
        to pass.
    bronze_required:
        True if Bronze certification requires this check to pass.
    silver_required:
        True if Silver certification requires this check to pass.
        Silver requirements are always a superset of Bronze.
    gold_required:
        True if Gold certification requires this check to pass.
        Gold requirements are always a superset of Silver.
    """

    category: str
    name: str
    description: str
    bronze_required: bool
    silver_required: bool
    gold_required: bool


CERTIFICATION_REQUIREMENTS: list[CertificationRequirement] = [
    # ------------------------------------------------------------------ #
    # Injection (OWASP LLM01 / OASIS MCP §4.1)                           #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="injection",
        name="Prompt Injection Resistance",
        description="No known prompt injection patterns in tool descriptions or outputs",
        bronze_required=True,
        silver_required=True,
        gold_required=True,
    ),
    CertificationRequirement(
        category="injection",
        name="Input Validation Completeness",
        description="All tool inputs validated against declared schemas",
        bronze_required=True,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Authentication (OASIS MCP §4.2)                                     #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="authentication",
        name="Authentication Implemented",
        description="Server requires authentication for tool access",
        bronze_required=False,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Authorization (OASIS MCP §4.3)                                      #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="authorization",
        name="Permission Boundaries Enforced",
        description="Tool-level authorization prevents unauthorized operations",
        bronze_required=False,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Audit (NIST SP 800-53 AU)                                           #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="audit",
        name="Audit Logging",
        description="All tool invocations are logged with timestamps and caller identity",
        bronze_required=False,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Session Security (OWASP ASVS §3)                                   #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="session",
        name="Session Security",
        description="Session tokens are cryptographically secure, expire appropriately",
        bronze_required=False,
        silver_required=False,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Integrity (OASIS MCP §4.4)                                          #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="integrity",
        name="Tool Description Integrity",
        description="Tool descriptions have cryptographic hashes to detect tampering",
        bronze_required=True,
        silver_required=True,
        gold_required=True,
    ),
    CertificationRequirement(
        category="integrity",
        name="Schema Stability Verification",
        description="Tool schemas are version-pinned and changes are detectable",
        bronze_required=False,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Data Protection (GDPR / NIST PF)                                   #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="data_protection",
        name="PII Handling",
        description="No PII leaks in tool responses or error messages",
        bronze_required=True,
        silver_required=True,
        gold_required=True,
    ),
    # ------------------------------------------------------------------ #
    # Supply Chain (SLSA / NIST SP 800-218)                              #
    # ------------------------------------------------------------------ #
    CertificationRequirement(
        category="supply_chain",
        name="Dependency Verification",
        description="All server dependencies are pinned and audited for vulnerabilities",
        bronze_required=False,
        silver_required=False,
        gold_required=True,
    ),
]


def get_requirements_for_level(
    level: CertificationLevel,
) -> list[CertificationRequirement]:
    """Return the subset of requirements that apply to *level*.

    Parameters
    ----------
    level:
        The certification tier to query.

    Returns
    -------
    list[CertificationRequirement]
        Requirements that must pass for the specified level.
        Returns an empty list for ``CertificationLevel.NONE``.
    """
    if level == CertificationLevel.BRONZE:
        return [r for r in CERTIFICATION_REQUIREMENTS if r.bronze_required]
    if level == CertificationLevel.SILVER:
        return [r for r in CERTIFICATION_REQUIREMENTS if r.silver_required]
    if level == CertificationLevel.GOLD:
        return [r for r in CERTIFICATION_REQUIREMENTS if r.gold_required]
    return []


def determine_certification_level(
    passed_requirements: set[str],
) -> CertificationLevel:
    """Determine the highest certification level achieved.

    Evaluates tiers from highest to lowest. The first tier whose
    requirements are all present in *passed_requirements* is returned.

    Parameters
    ----------
    passed_requirements:
        Set of requirement *names* (``CertificationRequirement.name``)
        that the scanner found to be passing.

    Returns
    -------
    CertificationLevel
        Highest level fully satisfied, or ``CertificationLevel.NONE`` if
        Bronze requirements are not all satisfied.

    Example
    -------
    ::

        passed = {"Prompt Injection Resistance", "Input Validation Completeness",
                  "Tool Description Integrity", "PII Handling"}
        level = determine_certification_level(passed)
        # CertificationLevel.BRONZE
    """
    for level in (CertificationLevel.GOLD, CertificationLevel.SILVER, CertificationLevel.BRONZE):
        required = get_requirements_for_level(level)
        if all(req.name in passed_requirements for req in required):
            return level
    return CertificationLevel.NONE
