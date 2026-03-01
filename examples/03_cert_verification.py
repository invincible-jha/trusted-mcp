#!/usr/bin/env python3
"""Example: Certificate Verification

Demonstrates MCP server certification scanning and attestation
generation using the trusted-mcp certification subsystem.

Usage:
    python examples/03_cert_verification.py

Requirements:
    pip install trusted-mcp
"""
from __future__ import annotations

import trusted_mcp
from trusted_mcp import (
    CertificationLevel,
    CertificationScanner,
    generate_certification_badge,
    get_requirements_for_level,
)


def build_server_config(with_auth: bool = True) -> dict[str, object]:
    """Build a sample MCP server configuration for scanning."""
    return {
        "server_id": "analytics-mcp-v1",
        "name": "Analytics MCP Server",
        "version": "1.2.0",
        "transport": "https",
        "authentication": "bearer_token" if with_auth else None,
        "tls_enabled": True,
        "rate_limiting": True,
        "audit_logging": True,
        "tool_schema_validation": True,
    }


def main() -> None:
    print(f"trusted-mcp version: {trusted_mcp.__version__}")

    # Step 1: Show certification requirements for each level
    print("\nCertification level requirements:")
    for level in [CertificationLevel.BASIC, CertificationLevel.STANDARD, CertificationLevel.ADVANCED]:
        requirements = get_requirements_for_level(level)
        print(f"  {level.name}: {len(requirements)} requirement(s)")

    # Step 2: Scan a well-configured server
    scanner = CertificationScanner()
    config = build_server_config(with_auth=True)
    print(f"\nScanning server: {config['server_id']}")

    try:
        result = scanner.scan(config)
        print(f"  Certification level: {result.level.name}")
        print(f"  Passed checks: {result.passed_count}")
        print(f"  Failed checks: {result.failed_count}")

        # Step 3: Generate a badge
        badge = generate_certification_badge(result)
        print(f"\nCertification badge:\n{badge}")
    except Exception as error:
        print(f"Scan error: {error}")

    # Step 4: Scan a minimal (less-secure) server
    minimal_config = build_server_config(with_auth=False)
    minimal_config["tls_enabled"] = False
    print(f"\nScanning minimal server:")
    try:
        minimal_result = scanner.scan(minimal_config)
        print(f"  Certification level: {minimal_result.level.name}")
        print(f"  Passed: {minimal_result.passed_count}  Failed: {minimal_result.failed_count}")
    except Exception as error:
        print(f"Scan error: {error}")


if __name__ == "__main__":
    main()
