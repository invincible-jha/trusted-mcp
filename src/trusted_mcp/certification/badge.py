"""SVG badge generator for MCP Security Certification levels.

Produces a shield-shaped SVG badge that communicates the certification tier
(None / Bronze / Silver / Gold) at a glance. The badge follows the Shields.io
visual convention: a left panel with the label and a right panel with the
tier name rendered in the tier colour.

Example
-------
::

    from trusted_mcp.certification.badge import generate_certification_badge
    from trusted_mcp.certification.levels import CertificationLevel

    svg = generate_certification_badge(CertificationLevel.GOLD)
    with open("badge.svg", "w") as fh:
        fh.write(svg)
"""
from __future__ import annotations

from trusted_mcp.certification.levels import CertificationLevel

# Colour scheme per tier
_LEVEL_COLORS: dict[CertificationLevel, str] = {
    CertificationLevel.NONE: "#e05d44",     # red — uncertified
    CertificationLevel.BRONZE: "#cd7f32",   # bronze / copper
    CertificationLevel.SILVER: "#aaaaaa",   # silver / gray
    CertificationLevel.GOLD: "#dfb317",     # gold / amber
}

_LEVEL_LABELS: dict[CertificationLevel, str] = {
    CertificationLevel.NONE: "none",
    CertificationLevel.BRONZE: "bronze",
    CertificationLevel.SILVER: "silver",
    CertificationLevel.GOLD: "gold",
}

# SVG template — two-panel badge with a shield icon on the left side.
# Dimensions:  total width=180, height=36, left-panel width=100, right-panel width=80.
_SVG_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="180" height="36" role="img" aria-label="MCP Security: {level_label}">
  <title>MCP Security: {level_label}</title>
  <defs>
    <linearGradient id="grad" x2="0" y2="100%">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="clip">
      <rect width="180" height="36" rx="4" fill="#fff"/>
    </clipPath>
  </defs>
  <g clip-path="url(#clip)">
    <!-- Left panel: dark background with label -->
    <rect width="100" height="36" fill="#555"/>
    <!-- Right panel: tier colour -->
    <rect x="100" width="80" height="36" fill="{color}"/>
    <!-- Gradient overlay for depth -->
    <rect width="180" height="36" fill="url(#grad)"/>
  </g>
  <!-- Shield icon (left panel) -->
  <g fill="#fff" opacity="0.9" transform="translate(8,6)">
    <path d="M12 2L4 5v6c0 5.25 3.5 10.15 8 11.35C17.5 21.15 21 16.25 21 11V5l-9-3z
             M12 4.15l7 2.33V11c0 4.3-2.8 8.35-7 9.6C7.8 19.35 5 15.3 5 11V6.48l7-2.33z"/>
  </g>
  <!-- Left label text -->
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif"
     font-size="11">
    <text x="58" y="23" fill="#010101" fill-opacity=".3">MCP Security</text>
    <text x="58" y="22">MCP Security</text>
  </g>
  <!-- Right tier text -->
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif"
     font-size="11" font-weight="bold">
    <text x="140" y="23" fill="#010101" fill-opacity=".3">{level_label}</text>
    <text x="140" y="22">{level_label}</text>
  </g>
</svg>"""


def generate_certification_badge(level: CertificationLevel) -> str:
    """Generate an SVG badge string for the given certification level.

    Parameters
    ----------
    level:
        The certification tier to render.

    Returns
    -------
    str
        A well-formed SVG document as a string.  The caller is responsible
        for writing this to a ``.svg`` file or embedding it in HTML.

    Example
    -------
    ::

        svg = generate_certification_badge(CertificationLevel.GOLD)
        Path("badge.svg").write_text(svg, encoding="utf-8")
    """
    color = _LEVEL_COLORS[level]
    label = _LEVEL_LABELS[level]
    return _SVG_TEMPLATE.format(color=color, level_label=label)
