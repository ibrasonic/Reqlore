"""Phase 9 — scan-preset tests.

Pure-Python; no network, no web client. Covers:

- preset table integrity (every preset references valid ActiveOptions
  fields; canonical preset names; ``custom`` is a passthrough);
- ``apply_preset`` deltas + base-override semantics;
- ``preset_summary`` / ``all_summaries`` JSON-friendliness;
- wall-clock deadline enforcement in ``ActiveScanner.run_on_project``.
"""
from __future__ import annotations

import time
from dataclasses import fields

import pytest

from reqlore.scanner import (
    DEFAULT_PRESET,
    PRESET_DESCRIPTIONS,
    PRESET_NAMES,
    SCAN_PRESETS,
    ActiveOptions,
    ActiveScanner,
    ActiveScanResult,
    all_summaries,
    apply_preset,
    preset_summary,
)

# ---------------------------------------------------------------------------
# Table integrity.
# ---------------------------------------------------------------------------

def test_preset_names_canonical_order():
    """Match Burp's UI labels + the trailing 'custom' sentinel."""
    assert PRESET_NAMES == (
        "lightweight", "fast", "balanced", "deep", "custom",
    )


def test_default_preset_is_balanced():
    assert DEFAULT_PRESET == "balanced"


def test_preset_table_keys_match_named_presets():
    """``SCAN_PRESETS`` carries data for every non-custom preset."""
    data_keys = set(SCAN_PRESETS.keys())
    assert data_keys == set(PRESET_NAMES) - {"custom"}


def test_preset_descriptions_cover_every_name():
    for n in PRESET_NAMES:
        assert n in PRESET_DESCRIPTIONS
        assert PRESET_DESCRIPTIONS[n].strip(), f"empty desc for {n!r}"


def test_preset_fields_are_real_ActiveOptions_fields():
    valid = {f.name for f in fields(ActiveOptions)}
    for name, table in SCAN_PRESETS.items():
        unknown = set(table) - valid
        assert not unknown, (
            f"SCAN_PRESETS[{name!r}] references non-ActiveOptions "
            f"field(s): {sorted(unknown)!r}"
        )


def test_intensity_levels_are_frozenset_in_table():
    """Mutable sets would let a caller poison the global table."""
    for name, table in SCAN_PRESETS.items():
        assert isinstance(table["intensity_levels"], frozenset), name


# ---------------------------------------------------------------------------
# apply_preset.
# ---------------------------------------------------------------------------

def test_apply_preset_lightweight_only_light_tier():
    opts = apply_preset("lightweight")
    assert opts.intensity_levels == frozenset({"light"})
    assert opts.max_probes_per_check == 10
    assert opts.follow_redirects is False
    assert opts.wall_clock_seconds == 15 * 60
    assert opts.allow_dom_xss_probes is False


def test_apply_preset_fast_light_and_medium():
    opts = apply_preset("fast")
    assert opts.intensity_levels == frozenset({"light", "medium"})
    assert opts.max_probes_per_check == 25
    assert opts.rate_delay_ms == 0
    assert opts.wall_clock_seconds == 25 * 60


def test_apply_preset_balanced_is_the_default():
    opts = apply_preset("balanced")
    assert opts.intensity_levels == frozenset({"light", "medium"})
    assert opts.max_probes_per_check == 50
    assert opts.follow_redirects is True
    assert opts.rate_delay_ms == 50
    assert opts.wall_clock_seconds == 60 * 60


def test_apply_preset_deep_unlocks_intrusive_and_no_cap():
    opts = apply_preset("deep")
    assert opts.intensity_levels == frozenset(
        {"light", "medium", "intrusive"}
    )
    assert opts.max_probes_per_check == 200
    assert opts.wall_clock_seconds is None
    assert opts.allow_smuggling_probes is True
    assert opts.allow_dom_xss_probes is True
    # Account-locking / state-mutating probes stay opt-in even at deep.
    assert opts.allow_credential_probes is False
    assert opts.allow_race_probes is False


def test_apply_preset_is_case_insensitive_and_strips_whitespace():
    assert apply_preset("  BALANCED  ").max_probes_per_check == 50
    assert apply_preset("Deep").wall_clock_seconds is None


def test_apply_preset_custom_returns_base_unchanged():
    base = ActiveOptions(max_probes_per_check=7, follow_redirects=True)
    out = apply_preset("custom", base=base)
    assert out is base


def test_apply_preset_custom_with_no_base_returns_defaults():
    out = apply_preset("custom")
    defaults = ActiveOptions()
    assert out.max_probes_per_check == defaults.max_probes_per_check
    assert out.intensity_levels == defaults.intensity_levels


def test_apply_preset_unknown_raises_with_helpful_message():
    with pytest.raises(ValueError) as exc:
        apply_preset("aggressive")
    assert "aggressive" in str(exc.value)
    assert "lightweight" in str(exc.value) or "PRESET" in str(exc.value).upper()


def test_apply_preset_preserves_unrelated_base_fields():
    """Fields the preset table doesn't touch survive a preset apply."""
    base = ActiveOptions(
        enabled_checks=["xss-reflected"],
        replay_every_n_probes=5,
        timeout_s=42.0,
    )
    out = apply_preset("fast", base=base)
    assert out.enabled_checks == ["xss-reflected"]
    assert out.replay_every_n_probes == 5
    assert out.timeout_s == 42.0
    # And the fast deltas did apply.
    assert out.max_probes_per_check == 25
    assert out.intensity_levels == frozenset({"light", "medium"})


def test_apply_preset_default_does_not_mutate_passed_base():
    base = ActiveOptions(rate_delay_ms=999)
    apply_preset("lightweight", base=base)
    assert base.rate_delay_ms == 999  # untouched


# ---------------------------------------------------------------------------
# Summaries (UI surface).
# ---------------------------------------------------------------------------

def test_preset_summary_collapses_frozenset_to_sorted_list():
    s = preset_summary("balanced")
    assert s["name"] == "balanced"
    assert s["fields"]["intensity_levels"] == ["light", "medium"]


def test_preset_summary_includes_description():
    s = preset_summary("lightweight")
    assert s["description"]


def test_preset_summary_custom_has_no_fields():
    s = preset_summary("custom")
    assert s["name"] == "custom"
    assert s["fields"] == {}


def test_preset_summary_unknown_raises():
    with pytest.raises(ValueError):
        preset_summary("nuclear")


def test_all_summaries_returns_every_preset_in_canonical_order():
    out = all_summaries()
    assert [s["name"] for s in out] == list(PRESET_NAMES)


# ---------------------------------------------------------------------------
# Wall-clock enforcement in run_on_project.
# ---------------------------------------------------------------------------

class _FakeRow:
    """Bare-minimum history row shape ``run_on_project`` consumes."""

    def __init__(self, host: str = "x.test"):
        self.id = 1
        self.host = host
        self.url = f"https://{host}/p"
        self.method = "GET"
        self.status = 200
        self.req_blob = (
            b"GET /p HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        )
        self.resp_blob = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )


class _FakeProject:
    """Just enough Project surface for ActiveScanner.run_on_project."""

    def __init__(self, n_rows: int):
        self._rows = [_FakeRow(host=f"row-{i}.test") for i in range(n_rows)]

    def list_history(self, *, limit, host=None):
        del limit, host
        return list(self._rows)

    def list_scope(self):
        return []  # empty rules → host_in_scope returns True

    def record_rule_run(self, **_kw):  # noqa: D401
        pass


class _SlowCheck:
    """One-shot check that just burns wall-clock time per row."""

    from reqlore.scanner.rules import RuleMeta as _RM

    meta = _RM(
        id="active:slow",
        intensity="light",
        title="slow",
        default_severity="info",
    )
    name = "slow"
    description = "Sleep, do nothing"

    def __init__(self, sleep_per_row: float = 0.05):
        self.sleep_per_row = sleep_per_row
        self.calls = 0

    def run(self, ctx, send, opts=None):                    # noqa: ARG002
        time.sleep(self.sleep_per_row)
        self.calls += 1
        return iter([])


def test_wall_clock_seconds_none_means_no_cap():
    proj = _FakeProject(3)
    check = _SlowCheck(sleep_per_row=0.0)
    scanner = ActiveScanner(checks=[check], sender=lambda r: None)
    opts = ActiveOptions(wall_clock_seconds=None,
                         enabled_checks=["slow"])
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.aborted_due_to_deadline is False
    assert result.rows_skipped_deadline == 0
    assert result.rows_scanned == 3


def test_wall_clock_seconds_zero_means_no_cap():
    """0 (and any non-positive) treated as 'unset' to avoid an
    accidental 'never scan a row' configuration."""
    proj = _FakeProject(2)
    check = _SlowCheck(sleep_per_row=0.0)
    scanner = ActiveScanner(checks=[check], sender=lambda r: None)
    opts = ActiveOptions(wall_clock_seconds=0,
                         enabled_checks=["slow"])
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.aborted_due_to_deadline is False
    assert result.rows_scanned == 2


def test_wall_clock_seconds_enforced_between_rows():
    """A small cap aborts the run after the first slow row."""
    proj = _FakeProject(6)
    check = _SlowCheck(sleep_per_row=0.12)
    scanner = ActiveScanner(checks=[check], sender=lambda r: None)
    # 50 ms cap; first row takes 120 ms, so we abort before row 2.
    opts = ActiveOptions(wall_clock_seconds=0.05,
                         enabled_checks=["slow"])
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.aborted_due_to_deadline is True
    assert result.deadline_seconds == 0.05
    # First row completes (we check the deadline between rows, not
    # mid-row, by design), subsequent rows are skipped.
    assert result.rows_scanned == 1
    assert result.rows_skipped_deadline == 5


def test_wall_clock_cap_finishes_cleanly_when_under_budget():
    """A generous cap doesn't trip even with multiple rows."""
    proj = _FakeProject(2)
    check = _SlowCheck(sleep_per_row=0.0)
    scanner = ActiveScanner(checks=[check], sender=lambda r: None)
    opts = ActiveOptions(wall_clock_seconds=60.0,
                         enabled_checks=["slow"])
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.aborted_due_to_deadline is False
    assert result.deadline_seconds == 60.0
    assert result.rows_skipped_deadline == 0


def test_preset_deep_gives_unbounded_run():
    """Smoke: applying 'deep' really yields a no-cap result."""
    proj = _FakeProject(2)
    check = _SlowCheck(sleep_per_row=0.0)
    scanner = ActiveScanner(checks=[check], sender=lambda r: None)
    opts = apply_preset("deep")
    # Override enabled_checks so we exercise our single fake.
    opts = ActiveOptions(
        wall_clock_seconds=opts.wall_clock_seconds,
        enabled_checks=["slow"],
    )
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.aborted_due_to_deadline is False


def test_ActiveScanResult_default_deadline_fields_are_inert():
    """A scan that doesn't set wall_clock leaves the new fields off."""
    r = ActiveScanResult()
    assert r.aborted_due_to_deadline is False
    assert r.deadline_seconds is None
    assert r.rows_skipped_deadline == 0
