"""Phase 4 — restructured /scanner panel.

Covers:

- ``Project.list_findings`` ``confidence`` + ``waf_tagged`` keyword filters.
- ``Project.rule_last_fire_map`` / ``rule_last_fire_map_by_host``.
- ``LiveScanWorker.throughput_sparkline`` + snapshot key.
- ``/scanner/`` index: confidence dropdown + WAF checkbox + active-filter
  chips + inline occurrence preview when a finding has consolidated rows.
- ``/scanner/live``: sparkline bars + last-5 findings table.
- ``/scanner/run``: dry-run estimate text.
- ``/scanner/coverage``: ``Last fire`` column.

The Phase 3 baseline keeps the ``rule_run_summary`` / ``rule_run_summary_by_host``
shape unchanged — these tests assert the new fields surface via a sidecar
map rather than mutating the existing dicts (otherwise the 1792-test suite
regresses).
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.scanner.live import LiveScanWorker
from reqlore.web import create_app


# --------------------------- storage-level filters ---------------------------


@pytest.fixture
def project(tmp_path: Path):
    from reqlore.storage import Project
    proj = Project(tmp_path / "p4.rlr")
    yield proj
    proj.close()


def test_list_findings_filters_by_confidence(project):
    project.add_finding(
        severity="high", title="t-tentative",
        rule_id="active:r1", host="h",
        url="https://h/a", evidence="e1", confidence="tentative",
    )
    project.add_finding(
        severity="high", title="t-firm",
        rule_id="active:r1", host="h",
        url="https://h/b", evidence="e2", confidence="firm",
    )
    project.add_finding(
        severity="high", title="t-certain",
        rule_id="active:r1", host="h",
        url="https://h/c", evidence="e3", confidence="certain",
    )

    rows_tent = project.list_findings(confidence="tentative")
    rows_firm = project.list_findings(confidence="firm")
    rows_cert = project.list_findings(confidence="certain")
    rows_all = project.list_findings()

    assert [r["title"] for r in rows_tent] == ["t-tentative"]
    assert [r["title"] for r in rows_firm] == ["t-firm"]
    assert [r["title"] for r in rows_cert] == ["t-certain"]
    assert len(rows_all) == 3


def test_list_findings_filters_by_waf_tagged(project):
    project.add_finding(
        severity="high", title="behind-waf",
        rule_id="active:r1", host="h",
        url="https://h/a", evidence="e1",
        fingerprint_tags="behind_waf:cloudflare",
    )
    project.add_finding(
        severity="high", title="plain",
        rule_id="active:r1", host="h",
        url="https://h/b", evidence="e2",
    )

    waf_rows = project.list_findings(waf_tagged=True)
    plain_rows = project.list_findings()

    assert [r["title"] for r in waf_rows] == ["behind-waf"]
    assert {r["title"] for r in plain_rows} == {"behind-waf", "plain"}


def test_rule_last_fire_map_aggregates_by_rule(project):
    t0 = int(time.time())
    project.record_rule_run(
        rule_id="passive:hsts", host="a.test", url="", fired=True,
    )
    project.record_rule_run(
        rule_id="passive:hsts", host="b.test", url="", fired=False,
    )
    project.record_rule_run(
        rule_id="passive:csp", host="a.test", url="", fired=True,
    )

    m = project.rule_last_fire_map()
    assert set(m) == {"passive:hsts", "passive:csp"}
    assert m["passive:hsts"] >= t0
    assert m["passive:csp"] >= t0


def test_rule_last_fire_map_by_host_keyed_by_pair(project):
    project.record_rule_run(
        rule_id="passive:hsts", host="a.test", url="", fired=True,
    )
    project.record_rule_run(
        rule_id="passive:hsts", host="b.test", url="", fired=False,
    )

    by_host = project.rule_last_fire_map_by_host()
    # Only the host where it actually fired shows up.
    assert ("passive:hsts", "a.test") in by_host
    assert ("passive:hsts", "b.test") not in by_host


def test_rule_run_summary_shape_unchanged_phase4(project):
    """Phase 4 must NOT add fields to the legacy summary dict — many
    tests assert dict-equality against it. New fields live on the
    sidecar maps."""
    project.record_rule_run(
        rule_id="passive:hsts", host="h", url="", fired=True,
    )
    row = project.rule_run_summary()[0]
    assert set(row.keys()) == {"rule_id", "fired", "evaluated"}
    row_h = project.rule_run_summary_by_host()[0]
    assert set(row_h.keys()) == {"rule_id", "host", "fired", "evaluated"}


# --------------------------- live worker sparkline ---------------------------


class _FakeClock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:  # mimic time.time()
        return self.t


def _make_worker(clock: _FakeClock) -> LiveScanWorker:
    # We never start the worker thread — only feed _completions and
    # query the helper / snapshot. The constructor accepts no clock
    # override, so monkey-patch the bound clock after construction.
    w = LiveScanWorker.__new__(LiveScanWorker)
    w._clock = clock
    w._completions = []
    w.last_error = ""
    w._last_error_ts = 0
    return w


def test_throughput_sparkline_buckets_old_to_new():
    clock = _FakeClock()
    w = _make_worker(clock)
    # 60s window split into 6 buckets of 10s each.
    # Bucket index 5 = newest (age 0-10s), 0 = oldest (50-60s).
    w._completions = [
        clock.t - 55,  # bucket 0
        clock.t - 55,  # bucket 0
        clock.t - 25,  # bucket 3
        clock.t - 5,   # bucket 5
    ]
    out = w.throughput_sparkline()
    assert out == [2, 0, 0, 1, 0, 1]


def test_throughput_sparkline_drops_samples_outside_window():
    clock = _FakeClock()
    w = _make_worker(clock)
    w._completions = [clock.t - 120, clock.t - 5]  # 120s old → dropped
    out = w.throughput_sparkline()
    assert out == [0, 0, 0, 0, 0, 1]


def test_throughput_sparkline_empty_returns_zeros():
    w = _make_worker(_FakeClock())
    assert w.throughput_sparkline() == [0, 0, 0, 0, 0, 0]


# --------------------------- web routes / templates --------------------------


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(
        plugins_mod, "default_plugin_dirs", lambda: [tmp_path / "plugins"]
    )
    reset_registry()
    return create_app(tmp_path / "p4.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _proj(app):
    return app.extensions["reqlore_project"]


def test_index_renders_confidence_filter_and_waf_checkbox(client, app):
    resp = client.get("/scanner/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Confidence dropdown options
    assert 'name="confidence"' in body
    for opt in ("tentative", "firm", "certain"):
        assert f'value="{opt}"' in body
    # WAF checkbox
    assert 'name="waf_tagged"' in body


def test_index_confidence_filter_narrows_results(client, app):
    proj = _proj(app)
    proj.add_finding(
        severity="high", title="P4-tentative",
        rule_id="active:rX", host="h",
        url="https://h/a", evidence="e1", confidence="tentative",
    )
    proj.add_finding(
        severity="high", title="P4-firm",
        rule_id="active:rX", host="h",
        url="https://h/b", evidence="e2", confidence="firm",
    )
    resp = client.get("/scanner/?confidence=tentative")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "P4-tentative" in body
    assert "P4-firm" not in body


def test_index_renders_filter_chip_with_clear_link(client, app):
    proj = _proj(app)
    proj.add_finding(
        severity="high", title="P4-firm-only",
        rule_id="active:rX", host="h",
        url="https://h/a", evidence="e", confidence="firm",
    )
    resp = client.get("/scanner/?confidence=firm")
    body = resp.get_data(as_text=True)
    # Chip with the filter name visible + clear link
    assert "filter-chip" in body
    assert "Clear all" in body or "clear" in body.lower()


def test_index_renders_inline_occurrence_preview(client, app):
    """When a finding has consolidated rows (occurrence_count > 1),
    the row should expose a collapsible preview of the first few
    occurrence URLs."""
    proj = _proj(app)
    # Two adds with the same dedupe_key (same title + host + evidence
    # + url-template) will bump occurrence_count.
    for n in range(3):
        proj.add_finding(
            severity="high", title="P4-consolidated",
            rule_id="active:rX", host="h",
            url=f"https://h/users/{n}/profile", evidence="e",
        )
    resp = client.get("/scanner/")
    body = resp.get_data(as_text=True)
    assert "occ-preview" in body
    # The first 3 occurrences should be linkable.
    assert "/users/0/profile" in body or "/users/1/profile" in body


def test_live_page_renders_sparkline_and_recent_findings(client, app):
    proj = _proj(app)
    proj.add_finding(
        severity="medium", title="P4-live-recent",
        rule_id="active:rX", host="h",
        url="https://h/r", evidence="e",
    )
    resp = client.get("/scanner/live")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "sparkline" in body
    # Last-5 findings table renders the most recent title.
    assert "P4-live-recent" in body


def test_run_page_includes_dry_run_estimate(client):
    resp = client.get("/scanner/run")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Dry-run estimate" in body
    # Both passive and active sections carry an estimate.
    assert body.count("Dry-run estimate") >= 2


def test_coverage_page_renders_last_fire_column(client, app):
    proj = _proj(app)
    proj.record_rule_run(
        rule_id="passive:hsts", host="h", url="", fired=True,
    )
    resp = client.get("/scanner/coverage")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Last fire" in body
    # The "never" placeholder also exists for non-fired rules.
    proj.record_rule_run(
        rule_id="passive:csp", host="h", url="", fired=False,
    )
    resp2 = client.get("/scanner/coverage")
    body2 = resp2.get_data(as_text=True)
    assert "never" in body2
