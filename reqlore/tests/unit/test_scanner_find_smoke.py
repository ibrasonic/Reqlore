"""Smoke tests for find-in-body on the Scanner finding-detail page.

Findings can carry long evidence and payload blocks that sit inside
read-only ``<pre>`` elements; the find widget adds line-numbered jump
anchors and a marked-up second view so screen-reader users can skim
without scrolling the whole evidence block. A single Find box searches
both regions at once — when both are populated the regions are merged
with visible ``--- Evidence ---`` / ``--- Payload ---`` section
markers so screen-reader users can tell which region a highlighted
match lives in.
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
    # Evidence mentions "admin" twice. Payload also includes "admin" once
    # so a single shared query can hit both regions at once and we can
    # verify the merged counter ("3 matches") instead of two separate
    # per-region counters. Payload also has "script" twice for the
    # payload-only assertion.
    fid = project.add_finding(
        severity="medium",
        title="Reflected token in body",
        host="example.test",
        url="http://example.test/q",
        evidence=("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                  "Welcome admin. Your admin token is here."),
        payload="<script>admin=true</script>",
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
    # One unified find form exists even with no query.
    assert 'id="body-find-q"' in raw
    # The legacy per-region inputs are gone.
    assert 'id="evidence-find-q"' not in raw
    assert 'id="payload-find-q"' not in raw
    # No marks yet.
    assert "<mark" not in raw


def test_find_marks_matches_in_payload_only(client):
    raw, body = _text(client, "/scanner/1?find=script")
    # The payload is "<script>admin=true</script>" — two occurrences of "script".
    assert '2 matches for "script" in finding body.' in body
    assert 'id="body-m1"' in raw
    assert 'id="body-m2"' in raw


def test_find_spans_both_regions(client):
    """A single query that occurs in both evidence and payload should
    return one combined match count and visible section markers so a
    screen-reader user can tell which region each highlighted match
    lives in."""
    raw, body = _text(client, "/scanner/1?find=admin")
    # 2 in evidence + 1 in payload = 3 across the merged blob.
    assert '3 matches for "admin" in finding body.' in body
    assert "Match 1 of 3 in finding body" in body
    assert "Match 3 of 3 in finding body" in body
    # Both section markers survive intact (the query doesn't break them).
    assert "--- Evidence ---" in body
    assert "--- Payload ---" in body
    # Three highlighted marks with stable ids.
    assert 'id="body-m1"' in raw
    assert 'id="body-m2"' in raw
    assert 'id="body-m3"' in raw


def test_only_evidence_present_no_section_markers(tmp_path):
    """When a finding has only evidence (no payload) the merged blob
    is just the raw evidence — no '--- Evidence ---' marker appears."""
    db = tmp_path / "ev_only.rlr"
    project = Project(db)
    fid = project.add_finding(
        severity="info", title="ev only", host="h", url="u",
        evidence="hello admin world", source="test",
    )
    assert fid == 1
    app = create_app(db, Settings())
    app.config["TESTING"] = True
    with app.test_client() as c:
        raw, body = _text(c, "/scanner/1?find=admin")
    assert '1 match for "admin" in finding body.' in body
    assert "--- Evidence ---" not in body
    assert "--- Payload ---" not in body
