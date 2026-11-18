"""Phase 18 (PLAN.md) — UI chrome palette/typography alignment pass.

Asserts the COLORS values this phase changed, and that the brand accent
colors (cyan/green/red) were deliberately left alone rather than
re-derived from the realigned palette.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase18_theme_alignment.py -v
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


def test_bg_realigned_to_plugin_root():
    assert rexmod.COLORS["bg"] == "#070708"


def test_bg2_and_bg3_sit_in_the_plugin_surface2_range():
    assert rexmod.COLORS["bg3"] == "#131317"
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg"]
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg3"]


def test_border_and_border2_use_the_plugin_rgba_idiom():
    assert rexmod.COLORS["border"] == "rgba(255,255,255,0.1)"
    assert rexmod.COLORS["border2"] == "rgba(255,255,255,0.1)"


def test_text_colors_realigned():
    assert rexmod.COLORS["text"] == "#d4d4d8"
    assert rexmod.COLORS["text2"] == "#9d9d9d"
    assert rexmod.COLORS["text3"] == "#6e6e6e"


def test_brand_accent_colors_left_unchanged():
    # Regression: these were already an exact match to the plugin and must
    # never be "helpfully" re-derived from the realigned bg/border/text scale.
    assert rexmod.COLORS["cyan"] == "#00e5c0"
    assert rexmod.COLORS["green"] == "#00ff88"
    assert rexmod.COLORS["red"] == "#ff1744"


def test_display_font_stack_falls_back_when_syne_unavailable():
    original_has_qt = rexmod.HAS_QT
    try:
        rexmod.HAS_QT = False
        assert rexmod._display_font_stack() == (
            "'JetBrains Mono', 'Fira Mono', 'Courier New', monospace"
        )
    finally:
        rexmod.HAS_QT = original_has_qt
