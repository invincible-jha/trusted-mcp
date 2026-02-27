"""Tests for trusted_mcp.certification.attestation module."""
from __future__ import annotations

import json

import pytest

from trusted_mcp.certification.attestation import (
    ATTESTATION_VERSION,
    CertificationAttestation,
    _canonical_json,
    generate_attestation,
    verify_attestation,
)
from trusted_mcp.certification.scanner import CertificationResult, CertificationScanner
from trusted_mcp.core.scanner import ToolDefinition


# ---------------------------------------------------------------------------
# Helper: build a CertificationResult at a given level
# ---------------------------------------------------------------------------


def _make_result(level: str = "bronze") -> CertificationResult:
    tools = [
        ToolDefinition(
            name="search",
            server_name="test-server",
            description="Search the web for information.",
            input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        )
    ]
    config: dict[str, object] = {}
    if level in ("silver", "gold"):
        config.update(
            require_authentication=True,
            require_authorization=True,
            require_audit_logging=True,
            require_schema_stability=True,
        )
    if level == "gold":
        config.update(
            require_session_security=True,
            require_dependency_verification=True,
        )
    scanner = CertificationScanner(config=config)
    return scanner.evaluate(tools)


# ---------------------------------------------------------------------------
# TestGenerateAttestation
# ---------------------------------------------------------------------------


class TestGenerateAttestation:
    def test_returns_certification_attestation(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert isinstance(attestation, CertificationAttestation)

    def test_server_name_set_correctly(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("my-mcp-server", result)
        assert attestation.server_name == "my-mcp-server"

    def test_level_matches_result(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert attestation.level == result.level.value

    def test_gold_level_attestation(self) -> None:
        result = _make_result("gold")
        attestation = generate_attestation("gold-server", result)
        assert attestation.level == "gold"

    def test_timestamp_is_iso_format(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        # ISO 8601 timestamps contain 'T' separating date and time.
        assert "T" in attestation.timestamp

    def test_sha256_hash_is_64_hex_chars(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert len(attestation.sha256_hash) == 64
        assert all(c in "0123456789abcdef" for c in attestation.sha256_hash)

    def test_requirements_checked_is_correct(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        expected = len(result.passed_requirements) + len(result.failed_requirements)
        assert attestation.requirements_checked == expected

    def test_requirements_passed_matches_result(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert attestation.requirements_passed == len(result.passed_requirements)

    def test_requirements_failed_matches_result(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert attestation.requirements_failed == len(result.failed_requirements)

    def test_version_matches_attestation_version(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert attestation.version == ATTESTATION_VERSION


# ---------------------------------------------------------------------------
# TestVerifyAttestation
# ---------------------------------------------------------------------------


class TestVerifyAttestation:
    def test_valid_attestation_verifies_true(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        assert verify_attestation(attestation) is True

    def test_tampered_level_verifies_false(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        # Mutate the level to simulate tampering.
        attestation.level = "gold"
        assert verify_attestation(attestation) is False

    def test_tampered_server_name_verifies_false(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("legitimate-server", result)
        attestation.server_name = "attacker-server"
        assert verify_attestation(attestation) is False

    def test_tampered_timestamp_verifies_false(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        attestation.timestamp = "1970-01-01T00:00:00+00:00"
        assert verify_attestation(attestation) is False

    def test_tampered_hash_itself_verifies_false(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        attestation.sha256_hash = "a" * 64
        assert verify_attestation(attestation) is False

    def test_gold_attestation_verifies(self) -> None:
        result = _make_result("gold")
        attestation = generate_attestation("gold-server", result)
        assert verify_attestation(attestation) is True


# ---------------------------------------------------------------------------
# TestAttestationSerialization
# ---------------------------------------------------------------------------


class TestAttestationSerialization:
    def test_to_dict_returns_dict(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        data = attestation.to_dict()
        assert isinstance(data, dict)

    def test_to_dict_contains_all_fields(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        data = attestation.to_dict()
        expected_keys = {
            "server_name",
            "level",
            "timestamp",
            "requirements_checked",
            "requirements_passed",
            "requirements_failed",
            "sha256_hash",
            "version",
        }
        assert expected_keys.issubset(data.keys())

    def test_to_json_is_valid_json(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        json_str = attestation.to_json()
        assert isinstance(json_str, str)
        # Must parse without error.
        parsed = json.loads(json_str)
        assert parsed["server_name"] == "test-server"

    def test_to_json_contains_sha256_hash(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("test-server", result)
        json_str = attestation.to_json()
        parsed = json.loads(json_str)
        assert "sha256_hash" in parsed
        assert len(parsed["sha256_hash"]) == 64

    def test_to_dict_server_name_matches(self) -> None:
        result = _make_result("bronze")
        attestation = generate_attestation("serialization-server", result)
        data = attestation.to_dict()
        assert data["server_name"] == "serialization-server"


# ---------------------------------------------------------------------------
# TestCanonicalJson
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    def test_produces_deterministic_output(self) -> None:
        kwargs = {
            "server_name": "my-server",
            "level": "bronze",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "requirements_checked": 10,
            "requirements_passed": 4,
            "requirements_failed": 6,
            "version": ATTESTATION_VERSION,
        }
        result_a = _canonical_json(**kwargs)
        result_b = _canonical_json(**kwargs)
        assert result_a == result_b

    def test_output_is_valid_json(self) -> None:
        canonical = _canonical_json(
            server_name="test",
            level="gold",
            timestamp="2026-01-01T00:00:00+00:00",
            requirements_checked=10,
            requirements_passed=10,
            requirements_failed=0,
            version=ATTESTATION_VERSION,
        )
        parsed = json.loads(canonical)
        assert parsed["server_name"] == "test"
        assert parsed["level"] == "gold"

    def test_different_inputs_produce_different_output(self) -> None:
        base_kwargs = {
            "server_name": "server-a",
            "level": "bronze",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "requirements_checked": 10,
            "requirements_passed": 4,
            "requirements_failed": 6,
            "version": ATTESTATION_VERSION,
        }
        alt_kwargs = {**base_kwargs, "server_name": "server-b"}
        assert _canonical_json(**base_kwargs) != _canonical_json(**alt_kwargs)

    def test_keys_are_sorted(self) -> None:
        canonical = _canonical_json(
            server_name="s",
            level="none",
            timestamp="2026-01-01T00:00:00+00:00",
            requirements_checked=10,
            requirements_passed=0,
            requirements_failed=10,
            version=ATTESTATION_VERSION,
        )
        parsed = json.loads(canonical)
        keys = list(parsed.keys())
        assert keys == sorted(keys)
