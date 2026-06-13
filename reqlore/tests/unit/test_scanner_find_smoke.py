"""Smoke tests for find-in-body on the Scanner finding-detail page.

Findings can carry long evidence and payload blocks that sit inside
read-only ``<pre>`` elements; the find widget adds line-numbered jump
anchors and a marked-up second view so screen-reader users can skim
without scrolling the whole evidence block. Evidence and payload have
independent state.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "scanner.rlr"
    project = Project(db)
    # Evidence mentions "admin" twice, payload mentions "script" once —
    # exercises plural+singular sentences and independent regions.
    fid = project.add_finding(
        severity="medium",
        title="Reflected token in body",
        host="example.test",
        url="http://example.test/q",
        evidence=("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                  "Welcome admin. Your admin token is here."),
        payload="<script>alert(1)</script>",
        source="test",
    )
    assert fid == 1
    settings = Settings()
    app = create_app(db, settings)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _text(client, url):
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    raw = r.get_data(as_text=True)
    return raw, html.unescape(raw)


def test_finding_detail_renders_without_query(client):
    raw, _ = _text(client, "/scanner/1")
    # Both find forms exist even with no query.
    assert 'id="evidence-find-q"' in raw
    assert 'id="payload-find-q"' in raw
    # No marks yet.
    assert "<mark" not in raw


def test_evidence_find_marks_two_matches(client):
    raw, body = _text(client, "/scanner/1?evidence_find=admin")
    assert '2 matches for "admin" in evidence.' in body
    assert 'id="evidence-m1"' in raw
    assert 'id="evidence-m2"' in raw
    assert "Match 1 of 2 in evidence" in body


def test_payload_find_singular(client):
    raw, body = _text(client, "/scanner/1?payload_find=script")
    # The payload is "<script>alert(1)</script>" — two occurrences of "script".
    assert '2 matches for "script" in payload.' in body
    assert 'id="payload-m1"' in raw


def test_independent_evidence_and_payload_state(client):
    """Searching evidence must not blow away the payload query and vice
    versa — both regions live in the same URL via hidden preserve inputs."""
    raw, body = _text(client,
                       "/scanner/1?evidence_find=admin&payload_find=script")
    assert '2 matches for "admin" in evidence.' in body
    assert '2 matches for "script" in payload.' in body
    assert 'id="evidence-m1"' in raw
    assert 'id="payload-m1"' in raw
