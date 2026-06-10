"""Smoke tests for the Phase 3 blueprints."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    # Point the plugin loader at an empty temp folder so tests are hermetic.
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(plugins_mod, "default_plugin_dirs",
                         lambda: [tmp_path / "plugins"])
    reset_registry()
    return create_app(tmp_path / "phase3.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_scanner_index(client):
    r = client.get("/scanner/")
    assert r.status_code == 200
    # After the redesign, /scanner/ is the Findings dashboard. The passive-
    # scan form lives on /scanner/run and is linked from the section nav.
    assert b"<h1>Findings</h1>" in r.data
    assert b"Run scan" in r.data


def test_scanner_run_page_has_both_forms(client):
    r = client.get("/scanner/run")
    assert r.status_code == 200
    assert b"Run passive scan" in r.data or b"Run <u>p</u>assive scan" in r.data
    assert b"Run active scan" in r.data or b"Run <u>a</u>ctive scan" in r.data


def test_scanner_run_with_no_history(client):
    token = _csrf(client)
    r = client.post("/scanner/run", data={"_csrf": token, "limit": "100"})
    assert r.status_code == 302
    follow = client.get(r.headers["Location"])
    assert b"Passive scan complete" in follow.data


def test_scanner_finds_and_displays_finding(client, app):
    # Seed history with a missing-CSP HTML response.
    proj = app.extensions["reqlore_project"]
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    proj.add_history(
        host="x.test", method="GET", url="https://x.test/",
        status=200, duration_ms=5, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\n\r\n", raw_resp=head,
    )
    token = _csrf(client)
    client.post("/scanner/run", data={"_csrf": token})
    r = client.get("/scanner/")
    assert b"Missing response header" in r.data


def test_reporter_index(client):
    r = client.get("/reporter/")
    assert r.status_code == 200
    assert b"Reporter" in r.data
    assert b"Markdown" in r.data


def test_reporter_export_md(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding(severity="high", title="HFinding",
                      host="h", url="https://h/", evidence="ev")
    r = client.get("/reporter/export.md")
    assert r.status_code == 200
    assert r.mimetype.startswith("text/markdown")
    assert b"HFinding" in r.data
    assert b"## High (1)" in r.data


def test_reporter_export_html_is_self_contained(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding(severity="medium", title="MFinding")
    r = client.get("/reporter/export.html")
    assert r.status_code == 200
    assert r.data.startswith(b"<!doctype html>")
    assert b"<script" not in r.data


def test_reporter_docx_404_or_ok(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding(severity="info", title="I")
    r = client.get("/reporter/export.docx")
    # Either we have python-docx (200 + PK magic) or we don't (400 with hint).
    if r.status_code == 200:
        assert r.data[:2] == b"PK"
    else:
        assert r.status_code == 400
        assert b"python-docx" in r.data


def test_plugins_index_empty(client):
    r = client.get("/plugins/")
    assert r.status_code == 200
    assert b"Plugins" in r.data
    assert b"No plugins found" in r.data


def test_plugins_reload_discovers_new_plugin(client, tmp_path: Path):
    pdir = tmp_path / "plugins"
    pdir.mkdir()
    (pdir / "ex.py").write_text(
        'PLUGIN_INFO = {"name": "ex", "version": "0.1", "description": "demo"}\n',
        encoding="utf-8",
    )
    token = _csrf(client)
    r = client.post("/plugins/reload", data={"_csrf": token})
    assert r.status_code == 302
    follow = client.get(r.headers["Location"])
    assert b"ex" in follow.data
    assert b"loaded" in follow.data


def test_dashboard_shows_findings_count(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding(severity="high", title="t")
    r = client.get("/")
    assert b"Scanner findings" in r.data


def test_nav_lists_scanner_reporter_plugins(client):
    r = client.get("/")
    assert b"Scanner" in r.data
    assert b"Reporter" in r.data
    assert b"Plugins" in r.data
