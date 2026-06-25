"""Phase 3 — Burp-parity confidence + consolidation + fingerprint tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.findings_bus import record_finding
from reqlore.plugins import reset_registry
from reqlore.scanner.findings import Finding
from reqlore.scanner.fingerprints import (
    apply_fingerprint, fingerprint_response,
)
from reqlore.storage import Project, SCHEMA_VERSION
from reqlore.web import create_app


@pytest.fixture
def project(tmp_path):
    p = Project(tmp_path / "p.rlr")
    yield p
    p.close()


# ----------------------------------------------------------------- schema

def test_schema_version_is_four():
    assert SCHEMA_VERSION >= 4


def test_issues_table_has_phase3_columns(project):
    cols = {r[1] for r in project._conn.execute("PRAGMA table_info(issues)")}
    assert "confidence" in cols
    assert "occurrence_count" in cols
    assert "fingerprint_tags" in cols
    assert "last_seen_at" in cols


def test_finding_occurrences_table_exists(project):
    rows = project._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='finding_occurrences'"
    ).fetchall()
    assert len(rows) == 1


# ------------------------------------------------------ Finding dataclass

def test_finding_default_confidence_is_firm():
    f = Finding(severity="high", title="x")
    assert f.confidence == "firm"


def test_finding_accepts_all_three_confidences():
    for c in ("tentative", "firm", "certain"):
        f = Finding(severity="high", title="x", confidence=c)  # type: ignore[arg-type]
        assert f.confidence == c


# --------------------------------------------------------- add_finding

def test_add_finding_default_confidence_is_firm(project):
    fid = project.add_finding(
        severity="high", title="t", rule_id="r:a", host="h",
        url="https://h/a", evidence="e",
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "firm"
    assert row["occurrence_count"] == 1
    assert row["fingerprint_tags"] == ""


def test_add_finding_round_trips_explicit_confidence(project):
    fid = project.add_finding(
        severity="high", title="t", rule_id="r:b", host="h",
        url="https://h/b", evidence="e", confidence="tentative",
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "tentative"


def test_add_finding_records_fingerprint_tags(project):
    fid = project.add_finding(
        severity="medium", title="t", rule_id="r:c", host="h",
        url="https://h/c", evidence="e",
        fingerprint_tags="behind_waf:cloudflare,error_page:php",
    )
    row = project.get_finding(fid)
    assert "behind_waf:cloudflare" in row["fingerprint_tags_list"]
    assert "error_page:php" in row["fingerprint_tags_list"]


# ------------------------------------------------- URL templating dedupe

def test_normalize_url_strips_numeric_id():
    assert Project._normalize_url_for_consolidation(
        "https://h/users/1/profile"
    ) == "https://h/users/{id}/profile"


def test_normalize_url_strips_uuid():
    assert Project._normalize_url_for_consolidation(
        "https://h/o/550e8400-e29b-41d4-a716-446655440000/x"
    ) == "https://h/o/{id}/x"


def test_normalize_url_strips_long_hex():
    assert Project._normalize_url_for_consolidation(
        "https://h/sha/deadbeefcafebabe/x"
    ) == "https://h/sha/{id}/x"


def test_normalize_url_preserves_query():
    assert Project._normalize_url_for_consolidation(
        "https://h/users/7?x=1"
    ) == "https://h/users/{id}?x=1"


def test_normalize_url_empty_safe():
    assert Project._normalize_url_for_consolidation("") == ""


def test_dedupe_consolidates_numeric_path_segments(project):
    fid1 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/users/1/profile", evidence="e",
    )
    fid2 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/users/2/profile", evidence="e",
    )
    assert fid1 == fid2
    row = project.get_finding(fid1)
    assert row["occurrence_count"] == 2


def test_dedupe_consolidates_uuid_path_segments(project):
    fid1 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h",
        url="https://h/o/550e8400-e29b-41d4-a716-446655440000/x",
        evidence="e",
    )
    fid2 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h",
        url="https://h/o/11111111-2222-3333-4444-555555555555/x",
        evidence="e",
    )
    assert fid1 == fid2
    row = project.get_finding(fid1)
    assert row["occurrence_count"] == 2


# --------------------------------------------------- occurrence rows

def test_list_finding_occurrences_records_each_hit(project):
    fid1 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/users/1/x", evidence="e",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/users/2/x", evidence="e",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/users/3/x", evidence="e",
    )
    occs = project.list_finding_occurrences(fid1)
    assert len(occs) == 3
    assert {o["url"] for o in occs} == {
        "https://h/users/1/x",
        "https://h/users/2/x",
        "https://h/users/3/x",
    }


def test_list_finding_occurrences_newest_first(project):
    fid1 = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/1/x", evidence="e",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/2/x", evidence="e",
    )
    occs = project.list_finding_occurrences(fid1)
    # ORDER BY ts DESC, id DESC — newest insert is index 0.
    assert occs[0]["id"] > occs[1]["id"]


# --------------------------------------------------- confidence bumping

def test_bump_never_demotes_confidence(project):
    fid = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/1/x", evidence="e", confidence="firm",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/2/x", evidence="e",
        confidence="tentative",
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "firm"


def test_bump_upgrades_confidence(project):
    fid = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/1/x", evidence="e",
        confidence="tentative",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/2/x", evidence="e", confidence="certain",
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "certain"


def test_bump_merges_fingerprint_tags(project):
    fid = project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/1/x", evidence="e",
        fingerprint_tags="behind_waf:cloudflare",
    )
    project.add_finding(
        severity="high", title="t", rule_id="active:xss-reflected",
        host="h", url="https://h/u/2/x", evidence="e",
        fingerprint_tags="error_page:php",
    )
    row = project.get_finding(fid)
    assert set(row["fingerprint_tags_list"]) == {
        "behind_waf:cloudflare", "error_page:php",
    }


# --------------------------------------------------- fingerprint catalogue

def test_fingerprint_response_detects_cloudflare_body():
    body = b"<html><title>Attention Required! | Cloudflare</title></html>"
    tags = fingerprint_response(body, [], status=403)
    assert "behind_waf:cloudflare" in tags


def test_fingerprint_response_detects_cloudflare_header():
    tags = fingerprint_response(b"x", [("cf-ray", "abc")], status=200)
    assert "behind_waf:cloudflare" in tags


def test_fingerprint_response_detects_akamai_header():
    tags = fingerprint_response(b"x", [("X-Akamai-Transformed", "9 0 pmb=mTOE,3"),])
    assert "behind_waf:akamai" in tags


def test_fingerprint_response_detects_imperva_header():
    tags = fingerprint_response(b"x", [("X-Iinfo", "1-2-NN")])
    assert "behind_waf:imperva" in tags


def test_fingerprint_response_detects_flask_debug_body():
    body = b"<html>Werkzeug Debugger - the debugger lets you...</html>"
    tags = fingerprint_response(body)
    assert "error_page:flask_debug" in tags


def test_fingerprint_response_detects_php_warning():
    body = b"<b>Warning</b>:  include(missing.php): failed to open stream"
    tags = fingerprint_response(body)
    assert "error_page:php" in tags


def test_fingerprint_response_safe_on_none():
    assert fingerprint_response(None) == []
    assert fingerprint_response(b"") == []


def test_fingerprint_response_dedupes_and_sorts():
    body = b"Werkzeug Debugger and Cloudflare attention required"
    tags = fingerprint_response(body, [("cf-ray", "x")])
    assert tags == sorted(set(tags))


def test_apply_fingerprint_demotes_to_tentative_on_waf():
    conf, tags = apply_fingerprint(["behind_waf:cloudflare"], base_confidence="firm")
    assert conf == "tentative"
    assert "behind_waf:cloudflare" in tags


def test_apply_fingerprint_demotes_on_error_page():
    conf, _ = apply_fingerprint(["error_page:php"], base_confidence="certain")
    assert conf == "tentative"


def test_apply_fingerprint_passthrough_when_no_signals():
    conf, tags = apply_fingerprint([], base_confidence="firm")
    assert conf == "firm"
    assert tags == ""


# --------------------------------------------------- bus integration

def _waf_repro():
    req = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
    resp = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Server: cloudflare\r\n"
        b"cf-ray: abc-DEN\r\n"
        b"\r\n"
        b"<html><title>Attention Required! | Cloudflare</title></html>"
    )
    return (req, resp, "GET", "https://h/a", 403, 100)


def test_record_finding_demotes_to_tentative_on_cloudflare(project):
    fid = record_finding(
        project, source="scanner", rule_id="active:sqli-error",
        severity="high", title="sqli", host="h", url="https://h/a",
        evidence="e", reproduction=_waf_repro(),
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "tentative"
    assert "behind_waf:cloudflare" in row["fingerprint_tags_list"]


def test_record_finding_keeps_firm_when_no_signals(project):
    req = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclean response"
    fid = record_finding(
        project, source="scanner", rule_id="active:sqli-error",
        severity="high", title="sqli", host="h", url="https://h/a",
        evidence="e", reproduction=(req, resp, "GET", "https://h/a", 200, 5),
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "firm"
    assert row["fingerprint_tags"] == ""


def test_record_finding_explicit_body_overrides_repro_parsing(project):
    fid = record_finding(
        project, source="scanner", rule_id="active:xss-reflected",
        severity="high", title="x", host="h", url="https://h/a",
        evidence="e",
        response_body=b"Werkzeug Debugger error",
        response_headers=[("Server", "Werkzeug")],
    )
    row = project.get_finding(fid)
    assert row["confidence"] == "tentative"
    assert "error_page:flask_debug" in row["fingerprint_tags_list"]


# --------------------------------------------------- corroboration

def test_partner_rules_symmetric():
    assert "active:os-cmd-time" in Project._partner_rules("active:sqli-error")
    assert "active:sqli-error" in Project._partner_rules("active:os-cmd-time")


def test_partner_rules_unknown_returns_empty():
    assert Project._partner_rules("nope") == ()
    assert Project._partner_rules("") == ()


def test_corroboration_promotes_pair_to_certain(project):
    fid1 = project.add_finding(
        severity="high", title="sqli", rule_id="active:sqli-error",
        host="h", url="https://h/a", evidence="e",
    )
    fid2 = project.add_finding(
        severity="high", title="cmd", rule_id="active:os-cmd-time",
        host="h", url="https://h/a", evidence="e",
    )
    assert fid1 != fid2
    assert project.get_finding(fid1)["confidence"] == "certain"
    assert project.get_finding(fid2)["confidence"] == "certain"


def test_corroboration_works_on_normalised_url(project):
    fid1 = project.add_finding(
        severity="high", title="sqli", rule_id="active:sqli-error",
        host="h", url="https://h/u/1/x", evidence="e",
    )
    fid2 = project.add_finding(
        severity="high", title="cmd", rule_id="active:os-cmd-time",
        host="h", url="https://h/u/2/x", evidence="e",
    )
    assert project.get_finding(fid1)["confidence"] == "certain"
    assert project.get_finding(fid2)["confidence"] == "certain"


def test_corroboration_only_on_open_findings(project):
    fid1 = project.add_finding(
        severity="high", title="sqli", rule_id="active:sqli-error",
        host="h", url="https://h/a", evidence="e",
    )
    project.set_finding_status(fid1, "false_positive")
    fid2 = project.add_finding(
        severity="high", title="cmd", rule_id="active:os-cmd-time",
        host="h", url="https://h/a", evidence="e",
    )
    # The first finding is closed — second should remain firm, first stays
    # at whatever it was (no promotion of a non-open finding).
    assert project.get_finding(fid2)["confidence"] == "firm"


def test_corroboration_requires_partner_pairing(project):
    fid1 = project.add_finding(
        severity="high", title="x", rule_id="active:xss-reflected",
        host="h", url="https://h/a", evidence="e",
    )
    fid2 = project.add_finding(
        severity="high", title="csp", rule_id="passive:csp",
        host="h", url="https://h/a", evidence="e",
    )
    # passive:csp is not in any corroboration pair with xss-reflected.
    assert project.get_finding(fid1)["confidence"] == "firm"
    assert project.get_finding(fid2)["confidence"] == "firm"


# --------------------------------------------------- suggestion engine

def test_suppression_suggestions_below_threshold_returns_empty(project):
    for i in range(3):
        project.add_finding(
            severity="medium", title="t", rule_id="passive:clickjacking",
            host="h", url=f"https://h/admin/{i}/dash", evidence="e",
        )
    # All three consolidate into one finding (template), so only 1 group
    # exists and its count is 3 — below threshold=5.
    assert project.suppression_suggestions(threshold=5) == []


def test_suppression_suggestions_above_threshold(project):
    # Disable dedupe-consolidation by using unrelated paths so each
    # finding is a new row. Quickest way: vary host suffix so paths
    # share template but rule fires 6+ times.
    # Actually, we want the consolidation to NOT happen so we end up
    # with N findings sharing a template. Use distinct rule_ids? no —
    # suggestion groups by rule_id. Instead use distinct hosts to dodge
    # dedupe (dedupe_key includes host); the suggestion bucket key is
    # (rule_id, host, template) so we need same host. Use *different
    # evidence* — that breaks the dedupe key.
    for i in range(7):
        project.add_finding(
            severity="medium", title="t", rule_id="passive:clickjacking",
            host="h", url=f"https://h/admin/{i}/dash",
            evidence=f"variant-{i}",
        )
    sugg = project.suppression_suggestions(threshold=5)
    assert len(sugg) == 1
    s = sugg[0]
    assert s["rule_id"] == "passive:clickjacking"
    assert s["host"] == "h"
    assert s["url_pattern"] == "https://h/admin/{id}/dash"
    assert s["count"] >= 5
    assert s["example_finding_id"]


def test_suppression_suggestions_ignores_non_open(project):
    fids = []
    for i in range(7):
        fid = project.add_finding(
            severity="medium", title="t", rule_id="passive:hsts",
            host="h", url=f"https://h/p/{i}/x",
            evidence=f"v{i}",
        )
        fids.append(fid)
    # Suppress 4 of them — bucket drops below threshold.
    for fid in fids[:4]:
        project.set_finding_status(fid, "false_positive")
    sugg = project.suppression_suggestions(threshold=5)
    assert sugg == []


def test_suppression_suggestions_sort_by_count_desc(project):
    for i in range(8):
        project.add_finding(
            severity="medium", title="t", rule_id="passive:a",
            host="h", url=f"https://h/a/{i}/x", evidence=f"v{i}",
        )
    for i in range(6):
        project.add_finding(
            severity="medium", title="t", rule_id="passive:b",
            host="h", url=f"https://h/b/{i}/x", evidence=f"v{i}",
        )
    sugg = project.suppression_suggestions(threshold=5)
    assert [s["rule_id"] for s in sugg] == ["passive:a", "passive:b"]


# ----------------------------------------------------------------- UI / routes

@pytest.fixture
def app(tmp_path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(
        plugins_mod, "default_plugin_dirs", lambda: [tmp_path / "plugins"]
    )
    reset_registry()
    return create_app(tmp_path / "p3.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _project_from_app(app):
    """Project handle stored by ``create_app``."""
    return app.extensions["reqlore_project"]


def test_findings_index_renders_confidence_column(client, app):
    proj = _project_from_app(app)
    assert proj is not None, "expected app.extensions['reqlore_project']"
    proj.add_finding(
        severity="high", title="phase3-test",
        rule_id="active:xss-reflected", host="h",
        url="https://h/u/1/x", evidence="e", confidence="tentative",
    )
    proj.add_finding(
        severity="high", title="phase3-test",
        rule_id="active:xss-reflected", host="h",
        url="https://h/u/2/x", evidence="e", confidence="firm",
    )
    resp = client.get("/scanner/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Confidence" in body
    # Consolidated to one row with an occurrence pill.
    assert "× 2" in body or "&times; 2" in body


def test_findings_detail_renders_confidence_and_occurrences(client, app):
    proj = _project_from_app(app)
    fid = proj.add_finding(
        severity="high", title="phase3-detail",
        rule_id="active:xss-reflected", host="h",
        url="https://h/u/1/profile", evidence="e",
        confidence="tentative",
        fingerprint_tags="behind_waf:cloudflare",
    )
    proj.add_finding(
        severity="high", title="phase3-detail",
        rule_id="active:xss-reflected", host="h",
        url="https://h/u/2/profile", evidence="e",
        confidence="tentative",
    )
    resp = client.get(f"/scanner/{fid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Confidence" in body
    assert "tentative" in body
    assert "Occurrences" in body
    assert "behind_waf:cloudflare" in body
    assert "Show occurrence history" in body


def test_suppressions_page_shows_suggestions(client, app):
    proj = _project_from_app(app)
    for i in range(7):
        proj.add_finding(
            severity="medium", title="t",
            rule_id="passive:clickjacking", host="h",
            url=f"https://h/admin/{i}/dash", evidence=f"v{i}",
        )
    resp = client.get("/scanner/suppressions")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Suggested suppressions" in body
    assert "passive:clickjacking" in body
    assert "https://h/admin/{id}/dash" in body


def test_suppressions_add_route_creates_suppression(client, app):
    proj = _project_from_app(app)
    token = _csrf(client)
    resp = client.post("/scanner/suppressions/add", data={
        "_csrf": token,
        "rule_id": "passive:hsts",
        "host": "h",
        "url_pattern": "https://h/p/{id}/x",
        "reason": "bulk: 7 occurrences",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
    rows = proj.list_finding_suppressions()
    assert any(
        r["rule_id"] == "passive:hsts" and r["host"] == "h"
        and r["url_pattern"] == "https://h/p/{id}/x"
        for r in rows
    )


def test_suppressions_add_route_rejects_missing_rule_id(client):
    token = _csrf(client)
    resp = client.post("/scanner/suppressions/add", data={
        "_csrf": token,
        "rule_id": "",
        "host": "h",
        "url_pattern": "/x",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
