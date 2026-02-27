"""MCP Security Certification — 3-tier certification for MCP servers.

Provides a Bronze / Silver / Gold certification framework that evaluates
:class:`~trusted_mcp.core.scanner.ToolDefinition` objects for compliance
with the OASIS MCP security taxonomy.

Quick start
-----------
::

    from trusted_mcp.certification import CertificationScanner, generate_attestation
    from trusted_mcp.core.scanner import ToolDefinition

    tools = [
        ToolDefinition(
            name="search",
            server_name="my-server",
            description="Search the web for information.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
    ]
    scanner = CertificationScanner()
    result = scanner.evaluate(tools)
    attestation = generate_attestation("my-server", result)
    print(result.level)            # e.g. CertificationLevel.BRONZE
    print(attestation.sha256_hash) # 64-char hex digest
"""
from trusted_mcp.certification.attestation import CertificationAttestation, generate_attestation, verify_attestation
from trusted_mcp.certification.badge import generate_certification_badge
from trusted_mcp.certification.levels import (
    CERTIFICATION_REQUIREMENTS,
    CertificationLevel,
    CertificationRequirement,
    determine_certification_level,
    get_requirements_for_level,
)
from trusted_mcp.certification.scanner import CertificationResult, CertificationScanner

__all__ = [
    "CertificationLevel",
    "CertificationRequirement",
    "CERTIFICATION_REQUIREMENTS",
    "get_requirements_for_level",
    "determine_certification_level",
    "CertificationScanner",
    "CertificationResult",
    "generate_certification_badge",
    "CertificationAttestation",
    "generate_attestation",
    "verify_attestation",
]
