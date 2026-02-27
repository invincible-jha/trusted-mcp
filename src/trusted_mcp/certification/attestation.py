"""Signed attestation for MCP Security Certification results.

An attestation is a tamper-evident record that binds a server name to its
certification level at a specific point in time. The integrity of the
attestation is protected by a SHA-256 hash of the canonical JSON representation
of all fields except the hash itself.

Example
-------
::

    from trusted_mcp.certification.attestation import generate_attestation, verify_attestation
    from trusted_mcp.certification.scanner import CertificationScanner
    from trusted_mcp.core.scanner import ToolDefinition

    tools = [ToolDefinition(name="search", server_name="my-server",
                            description="Search the web.",
                            input_schema={"type": "object",
                                          "properties": {"query": {"type": "string"}}})]
    result = CertificationScanner().evaluate(tools)
    attestation = generate_attestation("my-server", result)
    assert verify_attestation(attestation)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from trusted_mcp.certification.levels import CertificationLevel
from trusted_mcp.certification.scanner import CertificationResult

#: Attestation schema version — bump when the format changes incompatibly.
ATTESTATION_VERSION = "1.0"


@dataclass
class CertificationAttestation:
    """A tamper-evident record of an MCP server's certification state.

    Attributes
    ----------
    server_name:
        Name of the MCP server that was evaluated.
    level:
        The certification level achieved (``CertificationLevel`` value string).
    timestamp:
        ISO 8601 UTC timestamp of when the attestation was generated.
    requirements_checked:
        Total number of requirements evaluated.
    requirements_passed:
        Number of requirements that passed.
    requirements_failed:
        Number of requirements that failed.
    sha256_hash:
        SHA-256 hex digest of the canonical JSON of all other fields.
        Set to an empty string before the hash is computed.
    version:
        Attestation schema version string.
    """

    server_name: str
    level: str               # CertificationLevel.value (str enum)
    timestamp: str           # ISO 8601 UTC
    requirements_checked: int
    requirements_passed: int
    requirements_failed: int
    sha256_hash: str
    version: str = ATTESTATION_VERSION

    def to_dict(self) -> dict[str, object]:
        """Return a plain dict representation suitable for JSON serialisation."""
        return asdict(self)

    def to_json(self, indent: int | None = 2) -> str:
        """Serialise the attestation to a JSON string.

        Parameters
        ----------
        indent:
            Indentation level passed to :func:`json.dumps`.

        Returns
        -------
        str
            JSON representation of the attestation.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def _canonical_json(
    server_name: str,
    level: str,
    timestamp: str,
    requirements_checked: int,
    requirements_passed: int,
    requirements_failed: int,
    version: str,
) -> str:
    """Return the canonical JSON string used as input to the SHA-256 hash.

    The hash covers all attestation fields *except* ``sha256_hash`` itself.
    Fields are sorted by key to ensure determinism across platforms.

    Parameters
    ----------
    server_name, level, timestamp, requirements_checked, requirements_passed,
    requirements_failed, version:
        Attestation field values.

    Returns
    -------
    str
        Compact, key-sorted JSON string.
    """
    payload: dict[str, object] = {
        "level": level,
        "requirements_checked": requirements_checked,
        "requirements_failed": requirements_failed,
        "requirements_passed": requirements_passed,
        "server_name": server_name,
        "timestamp": timestamp,
        "version": version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _compute_hash(
    server_name: str,
    level: str,
    timestamp: str,
    requirements_checked: int,
    requirements_passed: int,
    requirements_failed: int,
    version: str,
) -> str:
    """Compute the SHA-256 hash over the canonical attestation payload."""
    canonical = _canonical_json(
        server_name=server_name,
        level=level,
        timestamp=timestamp,
        requirements_checked=requirements_checked,
        requirements_passed=requirements_passed,
        requirements_failed=requirements_failed,
        version=version,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_attestation(
    server_name: str,
    result: CertificationResult,
) -> CertificationAttestation:
    """Create a signed :class:`CertificationAttestation` from a scan result.

    Parameters
    ----------
    server_name:
        Name of the MCP server that was evaluated.
    result:
        The :class:`~trusted_mcp.certification.scanner.CertificationResult`
        returned by :meth:`~trusted_mcp.certification.scanner.CertificationScanner.evaluate`.

    Returns
    -------
    CertificationAttestation
        Attestation with a valid ``sha256_hash``.

    Example
    -------
    ::

        attestation = generate_attestation("my-server", result)
        print(attestation.sha256_hash)  # 64-char hex string
    """
    timestamp = datetime.now(tz=timezone.utc).isoformat()
    level_str = result.level.value  # e.g. "gold"
    requirements_checked = len(result.passed_requirements) + len(result.failed_requirements)
    requirements_passed = len(result.passed_requirements)
    requirements_failed = len(result.failed_requirements)

    sha256_hash = _compute_hash(
        server_name=server_name,
        level=level_str,
        timestamp=timestamp,
        requirements_checked=requirements_checked,
        requirements_passed=requirements_passed,
        requirements_failed=requirements_failed,
        version=ATTESTATION_VERSION,
    )

    return CertificationAttestation(
        server_name=server_name,
        level=level_str,
        timestamp=timestamp,
        requirements_checked=requirements_checked,
        requirements_passed=requirements_passed,
        requirements_failed=requirements_failed,
        sha256_hash=sha256_hash,
        version=ATTESTATION_VERSION,
    )


def verify_attestation(attestation: CertificationAttestation) -> bool:
    """Verify the integrity of an attestation by recomputing its hash.

    Recomputes the SHA-256 hash from the attestation's fields (excluding
    ``sha256_hash``) and compares it to the stored ``sha256_hash``.

    Parameters
    ----------
    attestation:
        The attestation to verify.

    Returns
    -------
    bool
        True if the attestation is intact; False if any field has been
        tampered with.

    Example
    -------
    ::

        attestation = generate_attestation("my-server", result)
        assert verify_attestation(attestation)

        # Simulate tampering:
        attestation.level = "gold"
        assert not verify_attestation(attestation)
    """
    expected = _compute_hash(
        server_name=attestation.server_name,
        level=attestation.level,
        timestamp=attestation.timestamp,
        requirements_checked=attestation.requirements_checked,
        requirements_passed=attestation.requirements_passed,
        requirements_failed=attestation.requirements_failed,
        version=attestation.version,
    )
    return expected == attestation.sha256_hash
