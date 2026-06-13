"""Smoke tests for find-in-body on the Scanner finding-detail page.

Findings can carry long evidence and payload blocks that sit inside
read-only ``<pre>`` elements; the find widget adds line-numbered jump
anchors and marks each match in place inside its original pane so
screen-reader users can skim without scrolling the whole evidence
block. A single Find box searches both regions at once. Each pane has
its own anchor namespace (``evidence-mN`` / ``payload-mN``) so the
jump list links into the natural pane location — no synthetic merged
duplicate.
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
    raw, body = _text(client, "/scanner/1?body_find=script")
    # The payload is "<script>admin=true</script>" — two occurrences of "script".
    assert '2 matches for "script" in finding body.' in body
    assert 'id="payload-m1"' in raw
    assert 'id="payload-m2"' in raw
    # "script" does not appear in evidence — no evidence anchors.
    assert 'id="evidence-m1"' not in raw


def test_find_spans_both_regions(client):
    """A single query that occurs in both evidence and payload should
    return one combined match count, with anchors landing in each
    pane's own namespace so the jump list links into the original
    pane location — not a synthetic merged copy."""
    raw, body = _text(client, "/scanner/1?body_find=admin")
    # 2 in evidence + 1 in payload = 3 across both panes.
    assert '3 matches for "admin" in finding body.' in body
    assert "Match 1 of 2 in evidence" in body
    assert "Match 1 of 1 in payload" in body
    # Old merged-blob section markers must not leak through.
    assert "--- Evidence ---" not in body
    assert "--- Payload ---" not in body
    # Per-pane anchor namespaces.
    assert 'id="evidence-m1"' in raw
    assert 'id="evidence-m2"' in raw
    assert 'id="payload-m1"' in raw


def test_only_evidence_present_no_section_markers(tmp_path):
    """When a finding has only evidence (no payload) the marked-up
    pane is the evidence alone — no payload anchors, no legacy
    section markers."""
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
        raw, body = _text(c, "/scanner/1?body_find=admin")
    assert '1 match for "admin" in finding body.' in body
    assert 'id="evidence-m1"' in raw
    assert 'id="payload-m1"' not in raw
    assert "--- Evidence ---" not in body
    assert "--- Payload ---" not in body


def test_form_action_and_input_name_round_trip(client):
    """Regression guard: the URL the form actually submits must match
    what the blueprint reads. Render the page, scrape the form's
    `action` URL and the search-input's `name`, then submit a GET to
    that URL with that name — it must produce the same matches as a
    hand-crafted ``?body_find=...`` URL would."""
    raw, _ = _text(client, "/scanner/1")
    # The form's action is set by build_find_multi(action=...).
    assert 'action="/scanner/1"' in raw
    # The search input name must be exactly body_find (matching what
    # the blueprint reads from request.args).
    assert 'name="body_find"' in raw
    # Now drive the form as a browser would.
    raw2, body2 = _text(client, "/scanner/1?body_find=admin")
    assert '3 matches for "admin" in finding body.' in body2
    assert 'id="evidence-m1"' in raw2
    assert 'id="payload-m1"' in raw2
