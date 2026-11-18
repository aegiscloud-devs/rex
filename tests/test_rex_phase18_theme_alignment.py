"""UIX upgrade (post-PLAN.md) — dark desktop theme with aegisone's design
accents. Desktop audit tools need dark backgrounds for readability and
contrast; this pass keeps that while incorporating aegisone's accent color
system (purple as the second accent) for design alignment.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase18_theme_alignment.py -v
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod


def test_bg_stays_dark_for_desktop():
    assert rexmod.COLORS["bg"] == "#070708"


def test_bg2_and_bg3_dark_contrast_scale():
    assert rexmod.COLORS["bg2"] == "#0d0d10"
    assert rexmod.COLORS["bg3"] == "#131317"
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg"]
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg3"]


def test_border_colors_dark_theme_rgba():
    assert rexmod.COLORS["border"] == "rgba(255,255,255,0.1)"
    assert rexmod.COLORS["border2"] == "rgba(255,255,255,0.1)"


def test_text_colors_light_on_dark():
    assert rexmod.COLORS["text"] == "#d4d4d8"
    assert rexmod.COLORS["text2"] == "#9d9d9d"
    assert rexmod.COLORS["text3"] == "#6e6e6e"


def test_accent_includes_aegisone_purple():
    # Bright cyan for dark backgrounds (interactive accents, buttons).
    assert rexmod.COLORS["cyan"] == "#00e5c0"
    # Purple added as aegisone's --accent for future design elements.
    assert rexmod.COLORS["purple"] == "#534AB7"
    # cyan_dim is a darkened hover shade of cyan.
    assert rexmod.COLORS["cyan_dim"] != rexmod.COLORS["cyan"]


def test_severity_triad_legible_on_dark_bg():
    green, orange, red = (
        rexmod.COLORS["green"], rexmod.COLORS["orange"], rexmod.COLORS["red"],
    )
    assert len({green, orange, red}) == 3
    # None of them may collide with the bright cyan interactive accent.
    assert green != rexmod.COLORS["cyan"]
    assert orange != rexmod.COLORS["cyan"]
    assert red != rexmod.COLORS["cyan"]


def test_display_font_stack_leads_with_aegisone_mono():
    original_has_qt = rexmod.HAS_QT
    try:
        rexmod.HAS_QT = False
        assert rexmod._display_font_stack() == (
            "'DM Mono', 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace"
        )
    finally:
        rexmod.HAS_QT = original_has_qt
