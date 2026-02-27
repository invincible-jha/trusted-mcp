"""trusted-mcp — Security proxy for MCP (Model Context Protocol) connections.

Public API
----------
The stable public surface is everything exported from this module.
Anything inside submodules not re-exported here is considered private
and may change without notice.

Example
-------
>>> import trusted_mcp
>>> trusted_mcp.__version__
'0.1.0'
"""
from __future__ import annotations

__version__: str = "0.1.0"

from trusted_mcp.convenience import TrustedProxy

# Audit logging (Phase 5)
from trusted_mcp.audit import (
    AuditEntry,
    AuditFormatter,
    AuditLogger,
    AuditStorage,
    FileStorage,
    NullStorage,
    StdoutStorage,
)

# MCP security certification (Phase 5)
from trusted_mcp.certification import (
    CERTIFICATION_REQUIREMENTS,
    CertificationAttestation,
    CertificationLevel,
    CertificationRequirement,
    CertificationResult,
    CertificationScanner,
    determine_certification_level,
    generate_attestation,
    generate_certification_badge,
    get_requirements_for_level,
    verify_attestation,
)

# Tool description drift detection (Phase 6)
from trusted_mcp.drift import (
    DiffEngine,
    DiffResult,
    DriftDetector,
    DriftResult,
    HashStore,
)

# Server reputation registry (Phase 6)
from trusted_mcp.reputation import (
    ReportType,
    ReputationRegistry,
    ReputationReport,
    ServerReputation,
    TrustScorer,
    TrustScorerConfig,
    compute_trust_score,
)

__all__ = [
    "__version__",
    "TrustedProxy",
    # Audit logging
    "AuditEntry",
    "AuditFormatter",
    "AuditLogger",
    "AuditStorage",
    "FileStorage",
    "NullStorage",
    "StdoutStorage",
    # Certification
    "CERTIFICATION_REQUIREMENTS",
    "CertificationAttestation",
    "CertificationLevel",
    "CertificationRequirement",
    "CertificationResult",
    "CertificationScanner",
    "determine_certification_level",
    "generate_attestation",
    "generate_certification_badge",
    "get_requirements_for_level",
    "verify_attestation",
    # Drift detection
    "DiffEngine",
    "DiffResult",
    "DriftDetector",
    "DriftResult",
    "HashStore",
    # Reputation
    "ReportType",
    "ReputationRegistry",
    "ReputationReport",
    "ServerReputation",
    "TrustScorer",
    "TrustScorerConfig",
    "compute_trust_score",
]
