"""A.5 triage memory: marking a finding 'false_positive' creates a suppression
that survives re-scans; the suppressions UI lists and deletes them.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.scanner import Scanner
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(plugins_mod, "default_plugin_dirs",
                         lambda: [tmp_path / "plugins"])
    reset_registry()
    return create_app(tmp_path / "triage.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _seed_missing_csp_row(proj) -> int:
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    return proj.add_history(
        host="vt.test", method="GET", url="https://vt.test/",
        status=200, duration_ms=5, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\n\r\n", raw_resp=head,
    )


# ---------- triage creates suppression ----------


def test_marking_false_positive_creates_suppression(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    findings = proj.list_findings()
    assert findings, "scanner should have produced at least one finding"
    fid = findings[0]["id"]
    rule_id = findings[0]["rule_id"]
    assert rule_id, "Phase A.2 should have stamped a rule_id"

    token = _csrf(client)
    r = client.post(f"/scanner/{fid}/status",
                     data={"_csrf": token, "status": "false_positive"})
    assert r.status_code == 302

    sups = proj.list_finding_suppressions()
    assert any(s["rule_id"] == rule_id and s["host"] == "vt.test"
                for s in sups), sups
    # Finding row itself was also updated.
    assert proj.get_finding(fid)["status"] == "false_positive"


def test_marking_non_fp_status_does_not_suppress(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    fid = proj.list_findings()[0]["id"]

    token = _csrf(client)
    client.post(f"/scanner/{fid}/status",
                 data={"_csrf": token, "status": "triaged"})
    assert proj.list_finding_suppressions() == []
    assert proj.get_finding(fid)["status"] == "triaged"


def test_marking_fp_without_rule_id_flashes_warn(client, app):
    proj = app.extensions["reqlore_project"]
    # Bypass the bus / scanner so rule_id is empty.
    fid = proj.add_finding(severity="low", title="manual-no-rule",
                            host="vt.test", url="https://vt.test/x",
                            evidence="ev", source="manual", rule_id="")

    token = _csrf(client)
    r = client.post(f"/scanner/{fid}/status",
                     data={"_csrf": token, "status": "false_positive"},
                     follow_redirects=True)
    assert r.status_code == 200
    assert proj.list_finding_suppressions() == []
    assert b"No rule_id" in r.data


def test_rescan_after_fp_does_not_add_new_finding(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    fid = proj.list_findings()[0]["id"]
    rule_id = proj.get_finding(fid)["rule_id"]

    token = _csrf(client)
    client.post(f"/scanner/{fid}/status",
                 data={"_csrf": token, "status": "false_positive"})
    # Clear every finding so dedupe is no longer the reason a re-scan produces
    # zero rows for the suppressed rule — only the suppression should be doing that.
    for f in proj.list_findings(limit=10_000):
        proj.delete_finding(f["id"])
    assert proj.findings_count() == 0

    before = {r["rule_id"]: r for r in proj.rule_run_summary()}
    # B.5 resume marker would otherwise short-circuit this re-scan; opt out
    # because the test intent is to re-evaluate the same row.
    Scanner().scan_project(proj, resume=False)
    after = {r["rule_id"]: r for r in proj.rule_run_summary()}

    # The targeted rule must NOT have re-emitted.
    rows_for_rule = proj.list_findings(rule_id=rule_id)
    assert rows_for_rule == [], rows_for_rule

    # And the suppressed run delta must be entirely non-fired.
    b = before.get(rule_id, {"fired": 0, "evaluated": 0})
    a = after[rule_id]
    assert a["evaluated"] > b["evaluated"], (b, a)
    assert a["fired"] == b["fired"], (b, a)


def test_deleting_suppression_re_enables_detection(client, app):
    proj = app.extensions["reqlore_project"]
    _seed_missing_csp_row(proj)
    Scanner().scan_project(proj)
    fid = proj.list_findings()[0]["id"]
    rule_id = proj.get_finding(fid)["rule_id"]
    host = proj.get_finding(fid)["host"]
    url = proj.get_finding(fid)["url"]

    token = _csrf(client)
    client.post(f"/scanner/{fid}/status",
                 data={"_csrf": token, "status": "false_positive"})
    for f in proj.list_findings(limit=10_000):
        proj.delete_finding(f["id"])
    # B.5 — opt out of the resume marker so we actually re-scan the same row.
    Scanner().scan_project(proj, resume=False)
    assert proj.list_findings(rule_id=rule_id) == []

    # Delete the suppression via the route, then re-scan.
    r = client.post("/scanner/suppressions/delete", data={
        "_csrf": token,
        "rule_id": rule_id,
        "host": host,
        "url_pattern": url,
    })
    assert r.status_code == 302
    assert proj.list_finding_suppressions() == []

    for f in proj.list_findings(limit=10_000):
        proj.delete_finding(f["id"])
    Scanner().scan_project(proj, resume=False)
    assert proj.list_findings(rule_id=rule_id), "rule should have re-fired"


# ---------- suppressions UI ----------


def test_suppressions_page_renders_empty(client):
    r = client.get("/scanner/suppressions")
    assert r.status_code == 200
    assert b"Finding suppressions" in r.data
    assert b"No suppressions configured" in r.data


def test_suppressions_page_lists_existing_rules(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding_suppression(rule_id="passive:hsts-missing",
                                   host="vt.test", url_pattern="",
                                   reason="known noise")
    r = client.get("/scanner/suppressions")
    assert r.status_code == 200
    assert b"passive:hsts-missing" in r.data
    assert b"known noise" in r.data
    assert b"vt.test" in r.data


def test_suppressions_delete_requires_rule_id(client):
    token = _csrf(client)
    r = client.post("/scanner/suppressions/delete",
                     data={"_csrf": token},
                     follow_redirects=True)
    assert r.status_code == 200
    assert b"rule_id is required" in r.data


def test_scanner_index_links_to_suppressions(client):
    r = client.get("/scanner/")
    assert r.status_code == 200
    # After the redesign the Suppressions link lives in the section nav.
    assert b"/scanner/suppressions" in r.data
    assert b">Suppressions<" in r.data
