"""Tests for trusted_mcp.certification.levels module."""
from __future__ import annotations

import pytest

from trusted_mcp.certification.levels import (
    CERTIFICATION_REQUIREMENTS,
    CertificationLevel,
    CertificationRequirement,
    determine_certification_level,
    get_requirements_for_level,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BRONZE_REQUIRED_NAMES = {
    "Prompt Injection Resistance",
    "Input Validation Completeness",
    "Tool Description Integrity",
    "PII Handling",
}

_SILVER_EXTRA_NAMES = {
    "Authentication Implemented",
    "Permission Boundaries Enforced",
    "Audit Logging",
    "Schema Stability Verification",
}

_GOLD_EXTRA_NAMES = {
    "Session Security",
    "Dependency Verification",
}

_ALL_REQUIREMENT_NAMES = _BRONZE_REQUIRED_NAMES | _SILVER_EXTRA_NAMES | _GOLD_EXTRA_NAMES


# ---------------------------------------------------------------------------
# TestCertificationLevel
# ---------------------------------------------------------------------------


class TestCertificationLevel:
    def test_none_value(self) -> None:
        assert CertificationLevel.NONE == "none"

    def test_bronze_value(self) -> None:
        assert CertificationLevel.BRONZE == "bronze"

    def test_silver_value(self) -> None:
        assert CertificationLevel.SILVER == "silver"

    def test_gold_value(self) -> None:
        assert CertificationLevel.GOLD == "gold"

    def test_is_str_mixin(self) -> None:
        # CertificationLevel is a str enum — instances are plain strings too.
        assert isinstance(CertificationLevel.GOLD, str)

    def test_all_four_members_present(self) -> None:
        members = {m.name for m in CertificationLevel}
        assert members == {"NONE", "BRONZE", "SILVER", "GOLD"}

    def test_can_be_compared_to_string(self) -> None:
        assert CertificationLevel.BRONZE == "bronze"
        assert CertificationLevel.SILVER != "gold"

    def test_value_attribute(self) -> None:
        assert CertificationLevel.GOLD.value == "gold"


# ---------------------------------------------------------------------------
# TestCertificationRequirement
# ---------------------------------------------------------------------------


class TestCertificationRequirement:
    def test_is_frozen_dataclass(self) -> None:
        req = CertificationRequirement(
            category="injection",
            name="Test Requirement",
            description="Desc",
            bronze_required=True,
            silver_required=True,
            gold_required=True,
        )
        with pytest.raises((AttributeError, TypeError)):
            req.name = "Changed"  # type: ignore[misc]

    def test_all_fields_set(self) -> None:
        req = CertificationRequirement(
            category="audit",
            name="Audit Logging",
            description="All invocations are logged.",
            bronze_required=False,
            silver_required=True,
            gold_required=True,
        )
        assert req.category == "audit"
        assert req.name == "Audit Logging"
        assert req.description == "All invocations are logged."
        assert req.bronze_required is False
        assert req.silver_required is True
        assert req.gold_required is True

    def test_bronze_only_requirement(self) -> None:
        # Hypothetical: something only needed at bronze but not higher doesn't
        # exist in the actual data, but the dataclass must support the pattern.
        req = CertificationRequirement(
            category="injection",
            name="X",
            description="x",
            bronze_required=True,
            silver_required=False,
            gold_required=False,
        )
        assert req.bronze_required is True
        assert req.silver_required is False
        assert req.gold_required is False

    def test_gold_only_requirement(self) -> None:
        req = CertificationRequirement(
            category="supply_chain",
            name="Dependency Verification",
            description="All dependencies are pinned.",
            bronze_required=False,
            silver_required=False,
            gold_required=True,
        )
        assert req.bronze_required is False
        assert req.silver_required is False
        assert req.gold_required is True


# ---------------------------------------------------------------------------
# TestCertificationRequirements (the module-level list)
# ---------------------------------------------------------------------------


class TestCertificationRequirements:
    def test_exactly_ten_items(self) -> None:
        assert len(CERTIFICATION_REQUIREMENTS) == 10

    def test_four_bronze_required(self) -> None:
        bronze_reqs = [r for r in CERTIFICATION_REQUIREMENTS if r.bronze_required]
        assert len(bronze_reqs) == 4

    def test_bronze_requirement_names(self) -> None:
        bronze_names = {r.name for r in CERTIFICATION_REQUIREMENTS if r.bronze_required}
        assert bronze_names == _BRONZE_REQUIRED_NAMES

    def test_eight_silver_required(self) -> None:
        silver_reqs = [r for r in CERTIFICATION_REQUIREMENTS if r.silver_required]
        assert len(silver_reqs) == 8

    def test_silver_includes_all_bronze(self) -> None:
        bronze_names = {r.name for r in CERTIFICATION_REQUIREMENTS if r.bronze_required}
        silver_names = {r.name for r in CERTIFICATION_REQUIREMENTS if r.silver_required}
        assert bronze_names.issubset(silver_names)

    def test_ten_gold_required(self) -> None:
        gold_reqs = [r for r in CERTIFICATION_REQUIREMENTS if r.gold_required]
        assert len(gold_reqs) == 10

    def test_gold_includes_all_silver(self) -> None:
        silver_names = {r.name for r in CERTIFICATION_REQUIREMENTS if r.silver_required}
        gold_names = {r.name for r in CERTIFICATION_REQUIREMENTS if r.gold_required}
        assert silver_names.issubset(gold_names)

    def test_categories_cover_all_taxonomy(self) -> None:
        expected_categories = {
            "injection",
            "authentication",
            "authorization",
            "audit",
            "session",
            "integrity",
            "data_protection",
            "supply_chain",
        }
        actual_categories = {r.category for r in CERTIFICATION_REQUIREMENTS}
        assert actual_categories == expected_categories

    def test_all_names_are_unique(self) -> None:
        names = [r.name for r in CERTIFICATION_REQUIREMENTS]
        assert len(names) == len(set(names))

    def test_all_have_non_empty_description(self) -> None:
        for req in CERTIFICATION_REQUIREMENTS:
            assert req.description.strip(), f"{req.name} has an empty description"


# ---------------------------------------------------------------------------
# TestGetRequirementsForLevel
# ---------------------------------------------------------------------------


class TestGetRequirementsForLevel:
    def test_bronze_returns_four(self) -> None:
        reqs = get_requirements_for_level(CertificationLevel.BRONZE)
        assert len(reqs) == 4

    def test_silver_returns_eight(self) -> None:
        reqs = get_requirements_for_level(CertificationLevel.SILVER)
        assert len(reqs) == 8

    def test_gold_returns_ten(self) -> None:
        reqs = get_requirements_for_level(CertificationLevel.GOLD)
        assert len(reqs) == 10

    def test_none_returns_empty(self) -> None:
        reqs = get_requirements_for_level(CertificationLevel.NONE)
        assert reqs == []

    def test_silver_is_superset_of_bronze(self) -> None:
        bronze_names = {r.name for r in get_requirements_for_level(CertificationLevel.BRONZE)}
        silver_names = {r.name for r in get_requirements_for_level(CertificationLevel.SILVER)}
        assert bronze_names.issubset(silver_names)

    def test_gold_is_superset_of_silver(self) -> None:
        silver_names = {r.name for r in get_requirements_for_level(CertificationLevel.SILVER)}
        gold_names = {r.name for r in get_requirements_for_level(CertificationLevel.GOLD)}
        assert silver_names.issubset(gold_names)

    def test_bronze_names_match_expected(self) -> None:
        names = {r.name for r in get_requirements_for_level(CertificationLevel.BRONZE)}
        assert names == _BRONZE_REQUIRED_NAMES

    def test_returns_list_of_certification_requirement_objects(self) -> None:
        reqs = get_requirements_for_level(CertificationLevel.GOLD)
        for req in reqs:
            assert isinstance(req, CertificationRequirement)


# ---------------------------------------------------------------------------
# TestDetermineCertificationLevel
# ---------------------------------------------------------------------------


class TestDetermineCertificationLevel:
    def test_empty_set_returns_none(self) -> None:
        assert determine_certification_level(set()) == CertificationLevel.NONE

    def test_only_bronze_requirements_returns_bronze(self) -> None:
        passed = _BRONZE_REQUIRED_NAMES.copy()
        assert determine_certification_level(passed) == CertificationLevel.BRONZE

    def test_bronze_and_silver_requirements_returns_silver(self) -> None:
        passed = _BRONZE_REQUIRED_NAMES | _SILVER_EXTRA_NAMES
        assert determine_certification_level(passed) == CertificationLevel.SILVER

    def test_all_requirements_returns_gold(self) -> None:
        passed = _ALL_REQUIREMENT_NAMES.copy()
        assert determine_certification_level(passed) == CertificationLevel.GOLD

    def test_missing_one_bronze_requirement_returns_none(self) -> None:
        # Remove one bronze requirement — should drop to NONE.
        passed = _BRONZE_REQUIRED_NAMES - {"Prompt Injection Resistance"}
        assert determine_certification_level(passed) == CertificationLevel.NONE

    def test_extra_unknown_requirements_are_ignored(self) -> None:
        # Extra names that don't appear in the registry shouldn't affect result.
        passed = _BRONZE_REQUIRED_NAMES | {"Some Future Requirement"}
        assert determine_certification_level(passed) == CertificationLevel.BRONZE

    def test_silver_requirements_without_bronze_returns_none(self) -> None:
        # Silver requirements alone (missing bronze ones) should yield NONE.
        passed = _SILVER_EXTRA_NAMES.copy()
        assert determine_certification_level(passed) == CertificationLevel.NONE

    def test_gold_requirements_without_silver_returns_bronze_at_most(self) -> None:
        # All bronze + gold extras but missing some silver extras.
        passed = _BRONZE_REQUIRED_NAMES | _GOLD_EXTRA_NAMES
        # Silver is NOT achieved (missing silver-only extras), so result is BRONZE.
        assert determine_certification_level(passed) == CertificationLevel.BRONZE
