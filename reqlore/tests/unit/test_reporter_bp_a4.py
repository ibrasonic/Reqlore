"""A.4 reporter blueprint route tests: JSON / SARIF / coverage / classification."""
from __future__ import annotations

import json
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
    return create_app(tmp_path / "rpt.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed(app) -> None:
    proj = app.extensions["reqlore_project"]
    proj.add_finding(
        severity="high", title="HFinding", host="h", url="https://h/",
        evidence="ev", source="manual", rule_id="manual:h",
        description="d", remediation="fix", references=["https://r/"],
        cwe="CWE-79", owasp="A03:2021",
    )
    proj.record_rule_run(rule_id="passive:hsts-missing", fired=False,
                          host="h", url="https://h/")


def test_export_json_route_returns_versioned_schema(client, app):
    _seed(app)
    r = client.get("/reporter/export.json")
    assert r.status_code == 200
    assert r.mimetype.startswith("application/json")
    parsed = json.loads(r.data.decode("utf-8"))
    assert parsed["schema"] == "reqlore.findings/1"
    assert parsed["findings"][0]["rule_id"] == "manual:h"


def test_export_sarif_route_returns_sarif210(client, app):
    _seed(app)
    r = client.get("/reporter/export.sarif")
    assert r.status_code == 200
    assert r.mimetype == "application/sarif+json"
    parsed = json.loads(r.data.decode("utf-8"))
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "reqlore"


def test_export_md_with_coverage_and_classification(client, app):
    _seed(app)
    r = client.get(
        "/reporter/export.md"
        "?coverage=1&classification=CONFIDENTIAL"
    )
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "> **CONFIDENTIAL**" in body
    assert "## Coverage" in body
    assert "`passive:hsts-missing`" in body


def test_reporter_index_lists_json_and_sarif_links(client):
    r = client.get("/reporter/")
    assert r.status_code == 200
    assert b"export.json" in r.data
    assert b"export.sarif" in r.data


def test_export_unknown_format_returns_404(client, app):
    _seed(app)
    r = client.get("/reporter/export.csv")
    assert r.status_code == 404
