"""Unit tests for the severity colour/symbol helpers in ``core.logger``."""

from __future__ import annotations

import pytest

from core.logger import _SEVERITY_STYLE, severity_badge, severity_marker


@pytest.mark.parametrize("sev", list(_SEVERITY_STYLE))
def test_badge_and_marker_carry_label_and_glyph(sev):
    badge = severity_badge(sev)
    marker = severity_marker(sev)
    glyph = _SEVERITY_STYLE[sev][2]
    assert sev.upper() in badge and sev.upper() in marker
    assert glyph in badge and glyph in marker
    # The badge is a coloured background; the inline marker is foreground-only.
    assert " on " in badge
    assert " on " not in marker


def test_unknown_severity_falls_back_to_info_style():
    # Unknown severity uses the info style/glyph but keeps its own label.
    info_glyph = _SEVERITY_STYLE["info"][2]
    badge = severity_badge("nope")
    marker = severity_marker("nope")
    assert info_glyph in badge and info_glyph in marker
    assert "grey42" in badge       # info badge background
    assert "grey62" in marker      # info marker foreground
    assert "NOPE" in badge         # original label preserved


def test_marker_keeps_a_severity_colour_for_critical():
    # Regression: the marker must not collapse to plain white (no colour).
    assert "red" in severity_marker("critical")


def test_each_severity_has_a_distinct_glyph():
    glyphs = [v[2] for v in _SEVERITY_STYLE.values()]
    assert len(glyphs) == len(set(glyphs))
