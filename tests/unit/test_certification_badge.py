"""Tests for trusted_mcp.certification.badge module."""
from __future__ import annotations

import pytest

from trusted_mcp.certification.badge import (
    _LEVEL_COLORS,
    _LEVEL_LABELS,
    generate_certification_badge,
)
from trusted_mcp.certification.levels import CertificationLevel


# ---------------------------------------------------------------------------
# TestLevelColors
# ---------------------------------------------------------------------------


class TestLevelColors:
    def test_all_four_levels_have_colors(self) -> None:
        for level in CertificationLevel:
            assert level in _LEVEL_COLORS, f"Missing color for {level}"

    def test_none_color_is_red(self) -> None:
        # NONE should be a red-ish color indicating failure.
        assert _LEVEL_COLORS[CertificationLevel.NONE] == "#e05d44"

    def test_bronze_color_defined(self) -> None:
        color = _LEVEL_COLORS[CertificationLevel.BRONZE]
        assert color.startswith("#")
        assert len(color) == 7  # 6-digit hex

    def test_silver_color_defined(self) -> None:
        color = _LEVEL_COLORS[CertificationLevel.SILVER]
        assert color.startswith("#")

    def test_gold_color_defined(self) -> None:
        color = _LEVEL_COLORS[CertificationLevel.GOLD]
        assert color.startswith("#")

    def test_colors_are_unique(self) -> None:
        # Each tier should have a visually distinct color.
        colors = list(_LEVEL_COLORS.values())
        assert len(colors) == len(set(colors))


# ---------------------------------------------------------------------------
# TestLevelLabels
# ---------------------------------------------------------------------------


class TestLevelLabels:
    def test_all_four_levels_have_labels(self) -> None:
        for level in CertificationLevel:
            assert level in _LEVEL_LABELS, f"Missing label for {level}"

    def test_none_label(self) -> None:
        assert _LEVEL_LABELS[CertificationLevel.NONE] == "none"

    def test_bronze_label(self) -> None:
        assert _LEVEL_LABELS[CertificationLevel.BRONZE] == "bronze"

    def test_silver_label(self) -> None:
        assert _LEVEL_LABELS[CertificationLevel.SILVER] == "silver"

    def test_gold_label(self) -> None:
        assert _LEVEL_LABELS[CertificationLevel.GOLD] == "gold"


# ---------------------------------------------------------------------------
# TestGenerateCertificationBadge
# ---------------------------------------------------------------------------


class TestGenerateCertificationBadge:
    def test_returns_string(self) -> None:
        result = generate_certification_badge(CertificationLevel.BRONZE)
        assert isinstance(result, str)

    def test_contains_mcp_security_text(self) -> None:
        result = generate_certification_badge(CertificationLevel.GOLD)
        assert "MCP Security" in result

    def test_none_level_contains_label(self) -> None:
        result = generate_certification_badge(CertificationLevel.NONE)
        assert "none" in result

    def test_bronze_level_contains_label(self) -> None:
        result = generate_certification_badge(CertificationLevel.BRONZE)
        assert "bronze" in result

    def test_silver_level_contains_label(self) -> None:
        result = generate_certification_badge(CertificationLevel.SILVER)
        assert "silver" in result

    def test_gold_level_contains_label(self) -> None:
        result = generate_certification_badge(CertificationLevel.GOLD)
        assert "gold" in result

    def test_correct_color_for_none(self) -> None:
        result = generate_certification_badge(CertificationLevel.NONE)
        assert _LEVEL_COLORS[CertificationLevel.NONE] in result

    def test_correct_color_for_bronze(self) -> None:
        result = generate_certification_badge(CertificationLevel.BRONZE)
        assert _LEVEL_COLORS[CertificationLevel.BRONZE] in result

    def test_correct_color_for_silver(self) -> None:
        result = generate_certification_badge(CertificationLevel.SILVER)
        assert _LEVEL_COLORS[CertificationLevel.SILVER] in result

    def test_correct_color_for_gold(self) -> None:
        result = generate_certification_badge(CertificationLevel.GOLD)
        assert _LEVEL_COLORS[CertificationLevel.GOLD] in result

    def test_valid_svg_structure_starts_with_svg_tag(self) -> None:
        result = generate_certification_badge(CertificationLevel.BRONZE)
        stripped = result.strip()
        assert stripped.startswith("<svg")

    def test_svg_has_closing_tag(self) -> None:
        result = generate_certification_badge(CertificationLevel.GOLD)
        assert "</svg>" in result

    def test_contains_shield_icon_path(self) -> None:
        result = generate_certification_badge(CertificationLevel.BRONZE)
        # The SVG template includes a shield <path> element.
        assert "<path" in result

    def test_each_level_produces_distinct_output(self) -> None:
        badges = {level: generate_certification_badge(level) for level in CertificationLevel}
        # All four badges should differ from each other.
        unique_badges = set(badges.values())
        assert len(unique_badges) == 4

    @pytest.mark.parametrize("level", list(CertificationLevel))
    def test_all_levels_produce_non_empty_output(self, level: CertificationLevel) -> None:
        result = generate_certification_badge(level)
        assert len(result) > 0
