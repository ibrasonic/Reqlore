"""WCAG 2.1 AAA contrast validation for every theme token combination."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from reqlore.a11y import (
    contrast_ratio,
    hex_to_rgb,
    wcag_aaa_pass,
    wcag_pass,
    wcag_ui_component_pass,
)

CSS = Path(__file__).resolve().parents[2] / "web" / "static" / "reqlore.css"


def _parse_themes() -> dict[str, dict[str, str]]:
    """Extract each theme block's --var: #hex assignments from reqlore.css.

    A "theme" is a CSS selector that defines core color tokens. We pull
    :root (light), [data-theme="dark"], and [data-theme="high-contrast"].
    """
    text = CSS.read_text(encoding="utf-8")
    # Walk by selector. Use a non-greedy block match.
    selectors = {
        "light": r":root",
        "dark": r'html\[data-theme="dark"\]',
        "high-contrast": r'html\[data-theme="high-contrast"\]',
    }
    out: dict[str, dict[str, str]] = {}
    for name, sel in selectors.items():
        m = re.search(sel + r"\s*\{([^}]*)\}", text)
        assert m, f"theme block {name} not found in {CSS}"
        body = m.group(1)
        vars_ = dict(re.findall(r"--([a-z0-9\-]+)\s*:\s*(#[0-9a-fA-F]{3,8})", body))
        out[name] = vars_
    return out


THEMES = _parse_themes()

# Pairs that render text on a background — must hit AAA 7:1.
TEXT_PAIRS = [
    ("fg", "bg"),
    ("muted", "bg"),
    ("accent", "bg"),
    ("accent-fg", "accent"),
    ("warn-fg", "warn-bg"),
    ("err-fg", "err-bg"),
    ("ok-fg", "ok-bg"),
]

# Pairs that render non-text UI components — must hit SC 1.4.11's 3:1.
UI_PAIRS = [
    ("focus", "bg"),
    ("border", "bg"),
    ("accent", "bg"),
]


# ---------- helpers ----------

def test_wcag_aaa_pass_thresholds():
    # Black on white: 21:1, well above AAA.
    ok, ratio = wcag_aaa_pass("#000000", "#ffffff")
    assert ok and ratio > 20

    # A grey at ~5.7:1 PASSES AA but FAILS AAA at normal size.
    ok, _ = wcag_aaa_pass("#717171", "#ffffff")
    assert ok is False

    # The same grey PASSES AAA when treated as large text (>=4.5).
    ok, _ = wcag_aaa_pass("#717171", "#ffffff", large_text=True)
    assert ok is True


def test_wcag_ui_component_pass_threshold():
    ok, ratio = wcag_ui_component_pass("#80868f", "#ffffff")
    assert ok and ratio >= 3.0
    # Old border color failed.
    ok, _ = wcag_ui_component_pass("#b6bcc7", "#ffffff")
    assert ok is False


# ---------- theme validation ----------

@pytest.mark.parametrize("theme", list(THEMES.keys()))
@pytest.mark.parametrize("fg,bg", TEXT_PAIRS)
def test_theme_text_pairs_meet_aaa(theme: str, fg: str, bg: str):
    vars_ = THEMES[theme]
    if fg not in vars_ or bg not in vars_:
        pytest.skip(f"{theme} does not define both --{fg} and --{bg}")
    ok, ratio = wcag_aaa_pass(vars_[fg], vars_[bg])
    assert ok, (
        f"{theme}: --{fg} ({vars_[fg]}) on --{bg} ({vars_[bg]}) "
        f"= {ratio:.2f}:1, need >= 7.0:1 for WCAG AAA"
    )


@pytest.mark.parametrize("theme", list(THEMES.keys()))
@pytest.mark.parametrize("fg,bg", UI_PAIRS)
def test_theme_ui_pairs_meet_non_text_contrast(theme: str, fg: str, bg: str):
    vars_ = THEMES[theme]
    if fg not in vars_ or bg not in vars_:
        pytest.skip(f"{theme} does not define both --{fg} and --{bg}")
    ok, ratio = wcag_ui_component_pass(vars_[fg], vars_[bg])
    assert ok, (
        f"{theme}: --{fg} ({vars_[fg]}) on --{bg} ({vars_[bg]}) "
        f"= {ratio:.2f}:1, need >= 3.0:1 for WCAG 1.4.11"
    )


def test_text_pairs_also_meet_aa():
    """Sanity: every AAA-pass pair trivially clears AA too."""
    for theme, vars_ in THEMES.items():
        for fg, bg in TEXT_PAIRS:
            if fg in vars_ and bg in vars_:
                assert wcag_pass(vars_[fg], vars_[bg])[0], f"{theme} {fg}/{bg}"


def test_high_contrast_theme_is_extreme():
    """High-contrast theme should crush past AAA on every text pair."""
    vars_ = THEMES["high-contrast"]
    for fg, bg in TEXT_PAIRS:
        if fg in vars_ and bg in vars_:
            ratio = contrast_ratio(hex_to_rgb(vars_[fg]), hex_to_rgb(vars_[bg]))
            assert ratio >= 7.0, f"high-contrast {fg}/{bg} only {ratio:.2f}:1"
