"""UIX upgrade (post-PLAN.md) — re-anchor the chrome palette a second time,
this pass onto aegisone's actual web palette (aegis1/templates/aegis-one.html
:root) instead of aegiscode-plugin's dark chrome.

Supersedes the Phase 18 (PLAN.md) pass this file used to document — that
pass's own regression guard ("cyan/green/red deliberately left alone") no
longer holds, because this time the brand accent itself (cyan) is one of
the colors being re-pointed at aegisone's --accent2. The severity triad
(green/warn-orange/red) is NOT borrowed from aegisone, which has no
warn/critical concept of its own — those three are asserted merely as
mutually distinct, not pinned to a specific source.

Run with:  .venv/bin/python -m pytest tests/test_rex_phase18_theme_alignment.py -v
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rex as rexmod  # noqa: E402


def test_bg_realigned_to_aegisone_root():
    assert rexmod.COLORS["bg"] == "#ffffff"


def test_bg2_and_bg3_match_aegisone_surface_scale():
    assert rexmod.COLORS["bg2"] == "#f8f8f6"
    assert rexmod.COLORS["bg3"] == "#f2f2ef"
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg"]
    assert rexmod.COLORS["bg2"] != rexmod.COLORS["bg3"]


def test_border_colors_match_aegisone_flat_hex():
    # aegisone uses flat hex here, not an rgba idiom — no reason to keep
    # the old dark-theme rgba(255,255,255,...) shape once bg is light.
    assert rexmod.COLORS["border"] == "#e8e8e4"
    assert rexmod.COLORS["border2"] == "#d8d8d4"


def test_text_colors_match_aegisone_muted_scale():
    assert rexmod.COLORS["text"] == "#111110"
    assert rexmod.COLORS["text2"] == "#6b6b68"
    assert rexmod.COLORS["text3"] == "#9b9b98"


def test_accent_colors_match_aegisone_two_accent_system():
    # cyan == aegisone's --accent2 (its own primary CTA color); purple ==
    # aegisone's --accent. Both now point at aegisone's real values rather
    # than an unrelated legacy blue/teal.
    assert rexmod.COLORS["cyan"] == "#0F6E56"
    assert rexmod.COLORS["purple"] == "#534AB7"
    # cyan_dim is a darkened hover shade of cyan, not an independent value.
    assert rexmod.COLORS["cyan_dim"] != rexmod.COLORS["cyan"]


def test_severity_triad_stays_mutually_distinct_on_light_bg():
    green, orange, red = (
        rexmod.COLORS["green"], rexmod.COLORS["orange"], rexmod.COLORS["red"],
    )
    assert len({green, orange, red}) == 3
    # None of them may collide with the brand accent either — pass/warn/
    # critical must read differently from "this is just the interactive
    # accent color".
    assert green != rexmod.COLORS["cyan"]
    assert orange != rexmod.COLORS["cyan"]
    assert red != rexmod.COLORS["cyan"]


def test_display_font_stack_leads_with_aegisone_mono_and_falls_back():
    original_has_qt = rexmod.HAS_QT
    try:
        rexmod.HAS_QT = False
        assert rexmod._display_font_stack() == (
            "'DM Mono', 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace"
        )
    finally:
        rexmod.HAS_QT = original_has_qt
