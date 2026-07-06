"""A.1 — record_finding write-bus."""
from __future__ import annotations

import pytest

from reqlore.findings_bus import record_finding, record_no_finding
from reqlore.storage import Project


@pytest.fixture
def project(tmp_path):
    p = Project(tmp_path / "t.rlr")
    yield p
    p.close()


def test_record_finding_returns_id_on_first_call(project):
    fid = record_finding(
        project, source="manual", rule_id="manual:user", severity="high",
        title="Test", host="h", url="https://h/x", evidence="EV",
    )
    assert isinstance(fid, int) and fid > 0


def test_record_finding_is_idempotent(project):
    kwargs = {"source": "scanner", "rule_id": "passive:csp", "severity": "medium",
                  "title": "Missing CSP", "host": "h", "url": "https://h/x",
                  "evidence": "response without CSP header"}
    a = record_finding(project, **kwargs)
    b = record_finding(project, **kwargs)
    assert a == b
    assert project.findings_count() == 1


def test_record_finding_writes_rule_run_on_fire(project):
    record_finding(project, source="scanner", rule_id="passive:hsts",
                    severity="low", title="t", host="h", url="https://h/x",
                    evidence="EV")
    summary = {r["rule_id"]: r for r in project.rule_run_summary()}
    assert summary["passive:hsts"]["fired"] == 1
    assert summary["passive:hsts"]["evaluated"] == 1


def test_record_finding_suppressed_returns_none(project):
    project.add_finding_suppression(rule_id="passive:hsts", host="h",
                                      reason="reviewed")
    fid = record_finding(project, source="scanner", rule_id="passive:hsts",
                          severity="low", title="t", host="h",
                          url="https://h/x", evidence="EV")
    assert fid is None
    assert project.findings_count() == 0
    summary = {r["rule_id"]: r for r in project.rule_run_summary()}
    assert summary["passive:hsts"]["fired"] == 0
    assert summary["passive:hsts"]["evaluated"] == 1


def test_record_finding_with_reproduction_stores_token(project):
    req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\n\r\n"
    fid = record_finding(
        project, source="scanner", rule_id="active:xss-reflected",
        severity="high", title="X", host="h", url="https://h/x",
        evidence="EV",
        reproduction=(req, resp, "GET", "https://h/x", 200, 12),
    )
    f = project.get_finding(fid)
    assert f is not None
    assert f["reproduction_token"]
    repro = project.get_reproduction(f["reproduction_token"])
    assert repro["request_blob"] == req
    assert repro["response_blob"] == resp
    assert repro["status"] == 200
    assert repro["elapsed_ms"] == 12


def test_record_finding_extra_targets_recorded(project):
    fid = record_finding(
        project, source="scanner", rule_id="passive:csp", severity="medium",
        title="X", host="a.example", url="https://a/x", evidence="EV",
        extra_targets=[("b.example", "https://b/x")],
    )
    assert ("b.example", "https://b/x") in project.list_finding_targets(fid)


def test_record_finding_without_rule_id_still_writes(project):
    # Producers without a stable rule id (e.g. legacy) must still work.
    fid = record_finding(project, source="manual", severity="low",
                          title="ad hoc", evidence="ev")
    assert fid is not None
    # No rule_id => no rule_run row.
    assert project.rule_run_summary() == []


def test_record_no_finding_writes_skip_row(project):
    record_no_finding(project, rule_id="passive:csp", host="h",
                       url="https://h/x", reason="not html")
    summary = project.rule_run_summary()
    assert summary == [
        {"rule_id": "passive:csp", "fired": 0, "evaluated": 1},
    ]
