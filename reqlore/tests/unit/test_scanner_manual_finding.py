"""A.3 verification: manual finding UI writes via the bus."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(plugins_mod, "default_plugin_dirs",
                         lambda: [tmp_path / "plugins"])
    reset_registry()
    return create_app(tmp_path / "manual.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# ----------------------------------------- GET form
def test_manual_form_renders(client):
    r = client.get("/scanner/manual")
    assert r.status_code == 200
    assert b"Add a manual finding" in r.data
    assert b'name="title"' in r.data
    assert b'name="severity"' in r.data
    assert b'name="rule_id_slug"' in r.data
    # Severity options must include every severity from the rules module.
    for s in (b"info", b"low", b"medium", b"high", b"critical"):
        assert s in r.data


def test_manual_form_prefills_from_request_id(client, app):
    proj = app.extensions["reqlore_project"]
    hid = proj.add_history(
        host="seed.test", method="GET", url="https://seed.test/x",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
    )
    r = client.get(f"/scanner/manual?request_id={hid}")
    assert r.status_code == 200
    assert b"seed.test" in r.data
    assert b"https://seed.test/x" in r.data


# ----------------------------------------- POST happy path
def test_post_creates_finding_via_bus(client, app):
    proj = app.extensions["reqlore_project"]
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token,
        "title": "Hand-found IDOR on /accounts/<id>",
        "severity": "high",
        "rule_id_slug": "idor-accounts",
        "cwe": "CWE-639",
        "owasp": "A01:2021-Broken Access Control",
        "host": "victim.test",
        "url": "https://victim.test/accounts/42",
        "description": "Changing the id returns another user's record.",
        "evidence": "GET /accounts/41 -> 200 with email of unrelated user",
        "payload": "id=41",
        "remediation": "Enforce per-row authorisation on /accounts/<id>.",
        "references": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    }, follow_redirects=False)
    assert r.status_code == 302
    findings = proj.list_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "manual"
    assert f["rule_id"] == "manual:idor-accounts"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-639"
    assert f["host"] == "victim.test"
    assert "/accounts/42" in f["url"]


def test_post_slugifies_from_title_when_slug_blank(client, app):
    proj = app.extensions["reqlore_project"]
    token = _csrf(client)
    client.post("/scanner/manual", data={
        "_csrf": token,
        "title": "Reflected XSS in search box!!",
        "severity": "high",
    })
    f = proj.list_findings()[0]
    assert f["rule_id"] == "manual:reflected-xss-in-search-box"


# ----------------------------------------- Validation
def test_missing_title_re_renders_with_error(client, app):
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token, "title": "", "severity": "medium",
    })
    assert r.status_code == 200
    assert b"Title is required" in r.data
    proj = app.extensions["reqlore_project"]
    assert proj.list_findings() == []


def test_bad_severity_re_renders_with_error(client, app):
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token, "title": "ok", "severity": "catastrophic",
    })
    assert r.status_code == 200
    assert b"Severity must be one of" in r.data
    proj = app.extensions["reqlore_project"]
    assert proj.list_findings() == []


def test_bad_cwe_re_renders_with_error(client, app):
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token, "title": "ok", "severity": "high", "cwe": "cwe-79",
    })
    assert r.status_code == 200
    assert b"CWE must be empty" in r.data
    proj = app.extensions["reqlore_project"]
    assert proj.list_findings() == []


def test_unknown_request_id_re_renders_with_error(client, app):
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token, "title": "x", "severity": "low",
        "request_id": "9999",
    })
    assert r.status_code == 200
    assert b"No history row with id 9999" in r.data
    proj = app.extensions["reqlore_project"]
    assert proj.list_findings() == []


# ----------------------------------------- Bus behaviour
def test_suppression_blocks_create_and_flashes_warn(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding_suppression(rule_id="manual:dup-test",
                                  host="vt.test", url_pattern="")
    token = _csrf(client)
    r = client.post("/scanner/manual", data={
        "_csrf": token, "title": "dup test", "severity": "low",
        "rule_id_slug": "dup-test", "host": "vt.test",
    }, follow_redirects=True)
    assert b"suppressed" in r.data
    assert proj.list_findings() == []


def test_dedup_same_finding_collapses(client, app):
    proj = app.extensions["reqlore_project"]
    token = _csrf(client)
    data = {
        "_csrf": token, "title": "Dedupe me", "severity": "low",
        "rule_id_slug": "dedupe-me", "host": "h.test",
        "url": "https://h.test/", "evidence": "same evidence text",
    }
    client.post("/scanner/manual", data=data)
    client.post("/scanner/manual", data=data)
    rows = [f for f in proj.list_findings() if f["rule_id"] == "manual:dedupe-me"]
    assert len(rows) == 1


def test_references_split_on_newlines(client, app):
    proj = app.extensions["reqlore_project"]
    token = _csrf(client)
    client.post("/scanner/manual", data={
        "_csrf": token, "title": "with refs", "severity": "info",
        "references": "https://a.example\nhttps://b.example\n",
    })
    f = proj.get_finding(proj.list_findings()[0]["id"])
    assert f["references"] == ["https://a.example", "https://b.example"]


# ----------------------------------------- Index page wiring
def test_manual_link_present_on_scanner_index(client):
    r = client.get("/scanner/")
    assert b"Add manual finding" in r.data
    assert b"/scanner/manual" in r.data


def test_history_detail_links_to_manual(client, app):
    proj = app.extensions["reqlore_project"]
    hid = proj.add_history(
        host="h.test", method="GET", url="https://h.test/p",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET /p HTTP/1.1\r\n\r\n", raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
    )
    r = client.get(f"/history/{hid}")
    assert r.status_code == 200
    assert (f"/scanner/manual?request_id={hid}".encode()) in r.data
