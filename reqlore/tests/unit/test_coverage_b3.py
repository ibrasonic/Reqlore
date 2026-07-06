"""B.3 coverage report tests: per-host rule_run summary, reporter rendering,
and the /scanner/coverage UI."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.reporter._common import coverage_rows_by_host
from reqlore.reporter.html import render_html
from reqlore.reporter.json_export import build_export, render_json
from reqlore.reporter.markdown import render_markdown
from reqlore.scanner import Scanner
from reqlore.storage import Project
from reqlore.web import create_app

# --------------------------- coverage_rows_by_host ---------------------------


def test_coverage_rows_by_host_normalises_and_filters_empty_rule_ids():
    rows = coverage_rows_by_host([
        {"rule_id": "passive:hsts-missing", "host": "a.test", "fired": 3, "evaluated": 10},
        {"rule_id": "", "host": "skip.test", "fired": 1, "evaluated": 1},
        {"rule_id": "passive:csp-missing", "host": "", "fired": 0, "evaluated": 4},
    ])
    assert rows == [
        {"rule_id": "passive:hsts-missing", "host": "a.test", "fired": 3, "evaluated": 10},
        {"rule_id": "passive:csp-missing", "host": "(unknown)", "fired": 0, "evaluated": 4},
    ]


def test_coverage_rows_by_host_empty_input_returns_empty():
    assert coverage_rows_by_host(None) == []
    assert coverage_rows_by_host([]) == []


# --------------------------- storage layer -----------------------------------


@pytest.fixture
def project(tmp_path: Path):
    proj = Project(tmp_path / "cov.rlr")
    yield proj
    proj.close()


def test_rule_run_summary_by_host_groups_per_host(project):
    project.record_rule_run(rule_id="passive:hsts-missing", host="a.test",
                              url="https://a.test/", fired=True)
    project.record_rule_run(rule_id="passive:hsts-missing", host="a.test",
                              url="https://a.test/x", fired=False, reason="no_match")
    project.record_rule_run(rule_id="passive:hsts-missing", host="b.test",
                              url="https://b.test/", fired=True)
    project.record_rule_run(rule_id="passive:csp-missing", host="a.test",
                              url="https://a.test/", fired=False, reason="no_match")

    by_host = project.rule_run_summary_by_host()
    # Sorted by (rule_id, host)
    assert by_host == [
        {"rule_id": "passive:csp-missing", "host": "a.test", "fired": 0, "evaluated": 1},
        {"rule_id": "passive:hsts-missing", "host": "a.test", "fired": 1, "evaluated": 2},
        {"rule_id": "passive:hsts-missing", "host": "b.test", "fired": 1, "evaluated": 1},
    ]


def test_rule_run_summary_global_still_aggregates_across_hosts(project):
    """Sanity check: the original rule_run_summary still works."""
    project.record_rule_run(rule_id="passive:hsts-missing", host="a.test",
                              url="", fired=True)
    project.record_rule_run(rule_id="passive:hsts-missing", host="b.test",
                              url="", fired=False)
    summary = {r["rule_id"]: r for r in project.rule_run_summary()}
    assert summary["passive:hsts-missing"]["fired"] == 1
    assert summary["passive:hsts-missing"]["evaluated"] == 2


def test_rule_run_summary_by_host_collapses_empty_host_to_blank(project):
    project.record_rule_run(rule_id="passive:hsts-missing", host="",
                              url="", fired=False, reason="no_match")
    by_host = project.rule_run_summary_by_host()
    assert by_host == [
        {"rule_id": "passive:hsts-missing", "host": "", "fired": 0, "evaluated": 1},
    ]


# --------------------------- reporter rendering ------------------------------


_FIXTURE_BY_HOST = [
    {"rule_id": "passive:hsts-missing", "host": "a.test", "fired": 3, "evaluated": 10},
    {"rule_id": "passive:hsts-missing", "host": "b.test", "fired": 0, "evaluated": 4},
]


def test_markdown_reporter_renders_coverage_by_host_section():
    out = render_markdown(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=_FIXTURE_BY_HOST,
    )
    assert "## Coverage" in out
    assert "### Coverage by host" in out
    assert "| Rule | Host | Fired | Evaluated |" in out
    assert "`passive:hsts-missing` | `a.test` | 3 | 10" in out
    assert "`passive:hsts-missing` | `b.test` | 0 | 4" in out


def test_markdown_reporter_omits_per_host_when_empty():
    out = render_markdown(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=None,
    )
    assert "## Coverage" in out
    assert "### Coverage by host" not in out


def test_html_reporter_renders_coverage_by_host_table():
    out = render_html(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=_FIXTURE_BY_HOST,
    )
    assert 'id="coverage"' in out
    assert "Coverage by host" in out
    assert "a.test" in out and "b.test" in out
    # Numeric cells are present
    assert ">10<" in out and ">4<" in out


def test_json_reporter_adds_coverage_by_host_key():
    payload = build_export(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=_FIXTURE_BY_HOST,
    )
    assert "coverage_by_host" in payload
    assert payload["coverage_by_host"][0]["host"] == "a.test"


def test_json_reporter_omits_coverage_by_host_when_empty():
    payload = build_export(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=None,
    )
    assert "coverage_by_host" not in payload


def test_render_json_string_includes_coverage_by_host():
    s = render_json(
        {"name": "p"}, [],
        include_coverage=True,
        coverage=[{"rule_id": "passive:hsts-missing", "fired": 3, "evaluated": 14}],
        coverage_by_host=_FIXTURE_BY_HOST,
    )
    payload = json.loads(s)
    assert payload["coverage_by_host"][1]["fired"] == 0


# --------------------------- /scanner/coverage UI ----------------------------


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(plugins_mod, "default_plugin_dirs",
                         lambda: [tmp_path / "plugins"])
    reset_registry()
    return create_app(tmp_path / "cov.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_missing_csp_row(proj) -> int:
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    return proj.add_history(
        host="cov.test", method="GET", url="https://cov.test/",
        status=200, duration_ms=5, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\n\r\n", raw_resp=head,
    )


def test_coverage_route_empty_state_renders_no_runs_message(client):
    r = client.get("/scanner/coverage")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Scanner coverage" in body
    assert "No rule runs recorded" in body


def test_coverage_route_lists_rule_totals_after_scan(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    r = client.get("/scanner/coverage")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Rule totals" in body
    assert "Coverage by host" in body
    assert "cov.test" in body
    # At least one rule (CSP / HSTS / etc.) should appear as a row.
    assert "passive:" in body


def test_coverage_route_rule_filter_narrows_results(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    # All matches first.
    r_all = client.get("/scanner/coverage")
    body_all = r_all.get_data(as_text=True)
    # Now restrict to a string that should match at least one rule.
    r_csp = client.get("/scanner/coverage?rule_id=passive:csp")
    body_csp = r_csp.get_data(as_text=True)
    assert "Scanner coverage" in body_csp
    # Filtering by "csp" should drop unrelated rules.
    if "passive:csp" in body_all:
        assert "passive:csp" in body_csp


def test_coverage_route_host_filter_narrows_per_host_table(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    r = client.get("/scanner/coverage?host=cov.test")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "cov.test" in body
    r2 = client.get("/scanner/coverage?host=does-not-exist.invalid")
    body2 = r2.get_data(as_text=True)
    assert "No per-host runs match" in body2


def test_scanner_index_links_to_coverage_page(client):
    r = client.get("/scanner/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # After the redesign the Coverage link lives in the section nav.
    assert "/scanner/coverage" in body
    assert ">Coverage<" in body


# ---------------- item #22: "explain why I'm safe" reasons -------------------


def test_rule_run_reasons_groups_by_rule_host_and_reason(project):
    project.record_rule_run(rule_id="passive:csp-missing", host="a.test",
                              url="https://a.test/", fired=False,
                              reason="no_match")
    project.record_rule_run(rule_id="passive:csp-missing", host="a.test",
                              url="https://a.test/x", fired=False,
                              reason="no_match")
    project.record_rule_run(rule_id="passive:csp-missing", host="a.test",
                              url="https://a.test/y", fired=False,
                              reason="suppressed")
    project.record_rule_run(rule_id="passive:csp-missing", host="b.test",
                              url="https://b.test/", fired=True)  # fired, ignored
    rows = project.rule_run_reasons()
    # Should contain the no_match (x2) entry first because of the COUNT
    # DESC tiebreak, plus the suppressed (x1) entry, but NOT the fired
    # row from b.test.
    bucket = {(r["host"], r["reason"]): r["count"] for r in rows}
    assert bucket[("a.test", "no_match")] == 2
    assert bucket[("a.test", "suppressed")] == 1
    assert ("b.test", "no_match") not in bucket


def test_rule_run_reasons_honours_rule_and_host_filters(project):
    project.record_rule_run(rule_id="active:forced-browsing", host="a.test",
                              url="", fired=False, reason="no_match")
    project.record_rule_run(rule_id="active:forced-browsing", host="b.test",
                              url="", fired=False, reason="no_match")
    project.record_rule_run(rule_id="passive:hsts-missing", host="a.test",
                              url="", fired=False, reason="suppressed")
    only_rule = project.rule_run_reasons(rule_id="active:forced-browsing")
    assert {r["host"] for r in only_rule} == {"a.test", "b.test"}
    only_host = project.rule_run_reasons(host="a.test")
    assert {r["rule_id"] for r in only_host} == {
        "active:forced-browsing", "passive:hsts-missing",
    }


def test_coverage_route_shows_reason_breakdown(client, app):
    """The /scanner/coverage page should surface the `reason` column from
    rule_runs so the operator can see WHY a rule didn't fire on a host."""
    proj = app.extensions["reqlore_project"]
    proj.record_rule_run(rule_id="active:forced-browsing", host="reasons.test",
                          url="https://reasons.test/p", fired=False,
                          reason="no_match")
    proj.record_rule_run(rule_id="active:forced-browsing", host="reasons.test",
                          url="https://reasons.test/q", fired=False,
                          reason="no_match")
    proj.record_rule_run(rule_id="active:forced-browsing", host="reasons.test",
                          url="https://reasons.test/r", fired=False,
                          reason="suppressed")
    r = client.get("/scanner/coverage?host=reasons.test")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Why not fired" in body
    assert "no_match" in body
    assert "suppressed" in body
    # The reason column groups by count, so each reason should appear
    # exactly once in the breakdown.
    assert body.count("<code>no_match</code>") == 1
    assert body.count("<code>suppressed</code>") == 1
