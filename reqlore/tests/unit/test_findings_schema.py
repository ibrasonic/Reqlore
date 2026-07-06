"""Phase A.0 — issues-table schema upgrade and new finding helper tables."""
from __future__ import annotations

import sqlite3

import pytest

from reqlore.storage import SCHEMA_VERSION, Project


@pytest.fixture
def project(tmp_path):
    p = Project(tmp_path / "t.rlr")
    yield p
    p.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_schema_version_is_four():
    assert SCHEMA_VERSION >= 4


def test_issues_table_has_new_columns(project):
    cols = _columns(project._conn, "issues")
    expected = {
        "uuid", "source", "rule_id", "rule_version", "description",
        "remediation", "references_json", "cvss_vector", "cvss_score",
        "reproduction_token", "updated_at", "dedupe_key",
    }
    assert expected.issubset(cols)


def test_helper_tables_exist(project):
    names = {
        r[0] for r in project._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"finding_targets", "finding_suppressions",
            "finding_reproductions", "rule_runs"}.issubset(names)


def test_migration_is_idempotent(project):
    # Running the schema script + _migrate again must not raise.
    from reqlore.storage import _SCHEMA  # type: ignore[attr-defined]
    project._conn.executescript(_SCHEMA)
    project._migrate()
    project._migrate()


def test_add_finding_stores_all_new_fields(project):
    fid = project.add_finding(
        severity="high", title="t",
        description="long desc", remediation="fix it",
        cwe="CWE-79", owasp="A03:2021-Injection",
        host="h", url="https://h/x", evidence="EV", payload="PL",
        source="manual", rule_id="manual:user", rule_version=1,
        references=["https://cwe.mitre.org/data/definitions/79.html"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        cvss_score=5.4,
    )
    f = project.get_finding(fid)
    assert f is not None
    assert f["source"] == "manual"
    assert f["rule_id"] == "manual:user"
    assert f["rule_version"] == 1
    assert f["description"] == "long desc"
    assert f["remediation"] == "fix it"
    assert f["references"] == [
        "https://cwe.mitre.org/data/definitions/79.html"
    ]
    assert f["cvss_score"] == pytest.approx(5.4)
    assert f["cvss_vector"].startswith("CVSS:3.1/")
    assert len(f["uuid"]) == 32
    assert f["updated_at"] is not None
    assert f["dedupe_key"]


def test_add_finding_deduplicates_by_key(project):
    a = project.add_finding(
        severity="low", title="t", host="h", url="https://h/x",
        evidence="EV", rule_id="passive:x",
    )
    b = project.add_finding(
        severity="low", title="t", host="h", url="https://h/x",
        evidence="EV", rule_id="passive:x",
    )
    assert a == b
    assert project.findings_count() == 1


def test_add_finding_different_evidence_creates_new_row(project):
    project.add_finding(severity="low", title="t", host="h",
                        url="https://h/x", evidence="EV1",
                        rule_id="passive:x")
    project.add_finding(severity="low", title="t", host="h",
                        url="https://h/x", evidence="EV2",
                        rule_id="passive:x")
    assert project.findings_count() == 2


def test_list_findings_filters_by_source_and_rule_id(project):
    project.add_finding(severity="low", title="A", source="scanner",
                        rule_id="passive:hsts")
    project.add_finding(severity="low", title="B", source="intruder",
                        rule_id="intruder:grep")
    project.add_finding(severity="low", title="C", source="manual",
                        rule_id="manual:user")
    by_src = project.list_findings(source="intruder")
    assert [f["title"] for f in by_src] == ["B"]
    by_rule = project.list_findings(rule_id="manual:user")
    assert [f["title"] for f in by_rule] == ["C"]


def test_set_finding_status_updates_updated_at(project):
    fid = project.add_finding(severity="low", title="t", rule_id="r:1")
    before = project.get_finding(fid)["updated_at"]
    project.set_finding_status(fid, "triaged")
    after = project.get_finding(fid)["updated_at"]
    assert after >= before
    assert project.get_finding(fid)["status"] == "triaged"


def test_extra_targets_recorded(project):
    fid = project.add_finding(
        severity="medium", title="t", host="a.example", url="https://a/x",
        rule_id="r:1",
        extra_targets=[("b.example", "https://b/x"),
                       ("c.example", "https://c/x")],
    )
    targets = project.list_finding_targets(fid)
    assert ("b.example", "https://b/x") in targets
    assert ("c.example", "https://c/x") in targets


# ---- suppressions ----

def test_add_and_list_suppressions(project):
    project.add_finding_suppression(rule_id="passive:hsts-missing",
                                      host="example.com",
                                      reason="known false positive")
    sups = project.list_finding_suppressions()
    assert len(sups) == 1
    assert sups[0]["rule_id"] == "passive:hsts-missing"
    assert sups[0]["host"] == "example.com"
    assert sups[0]["reason"] == "known false positive"


def test_is_suppressed_matches_exact_host(project):
    project.add_finding_suppression(rule_id="r:1", host="api.example.com")
    assert project.is_suppressed(rule_id="r:1", host="api.example.com")
    assert not project.is_suppressed(rule_id="r:1", host="www.example.com")


def test_is_suppressed_matches_wildcard_subdomain(project):
    project.add_finding_suppression(rule_id="r:1", host="*.example.com")
    assert project.is_suppressed(rule_id="r:1", host="api.example.com")
    assert project.is_suppressed(rule_id="r:1", host="example.com")
    assert not project.is_suppressed(rule_id="r:1", host="example.org")


def test_is_suppressed_empty_host_matches_any(project):
    project.add_finding_suppression(rule_id="r:1")
    assert project.is_suppressed(rule_id="r:1", host="anything.tld")


def test_is_suppressed_requires_rule_id(project):
    project.add_finding_suppression(rule_id="r:1")
    assert not project.is_suppressed(rule_id="")


def test_is_suppressed_with_url_pattern(project):
    project.add_finding_suppression(rule_id="r:1", url_pattern="/admin")
    assert project.is_suppressed(rule_id="r:1", url="https://h/admin/x")
    assert not project.is_suppressed(rule_id="r:1", url="https://h/public")


def test_delete_suppression(project):
    project.add_finding_suppression(rule_id="r:1", host="h")
    project.delete_finding_suppression(rule_id="r:1", host="h")
    assert project.list_finding_suppressions() == []


# ---- reproductions ----

def test_add_and_get_reproduction_roundtrip(project):
    req = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    token = project.add_reproduction(
        request_blob=req, response_blob=resp,
        method="GET", url="https://h/x", status=200, elapsed_ms=42,
    )
    assert isinstance(token, str) and len(token) == 32
    repro = project.get_reproduction(token)
    assert repro is not None
    assert repro["request_blob"] == req
    assert repro["response_blob"] == resp
    assert repro["method"] == "GET"
    assert repro["url"] == "https://h/x"
    assert repro["status"] == 200
    assert repro["elapsed_ms"] == 42


def test_get_reproduction_missing_returns_none(project):
    assert project.get_reproduction("nope") is None


# ---- rule_runs ----

def test_record_rule_run_and_summary(project):
    project.record_rule_run(rule_id="passive:hsts", host="a", url="u1",
                              fired=True)
    project.record_rule_run(rule_id="passive:hsts", host="b", url="u2",
                              fired=False, reason="header present")
    project.record_rule_run(rule_id="passive:csp", host="a", url="u1",
                              fired=False, reason="not html")
    summary = project.rule_run_summary()
    by_rule = {s["rule_id"]: s for s in summary}
    assert by_rule["passive:hsts"]["fired"] == 1
    assert by_rule["passive:hsts"]["evaluated"] == 2
    assert by_rule["passive:csp"]["fired"] == 0
    assert by_rule["passive:csp"]["evaluated"] == 1


def test_record_rule_run_ignores_empty_rule_id(project):
    project.record_rule_run(rule_id="", host="h", url="u", fired=True)
    assert project.rule_run_summary() == []
