"""Smoke tests for the find-in-body widget on History detail.

This is the first end-to-end web-layer test in the repo. The find
widget is the visible payoff of `a11y.find_in_text` and the
`_find.html` macros, so it warrants a render check: a regex slip in
the macro would otherwise only surface in manual browser testing.

The fixture builds a real Flask app on a tmp SQLite project, inserts
one history row whose request and response bodies each contain a known
token, then issues GETs and asserts what the screen reader and the
sighted user actually see.

A single Find box searches **both** the request and the response — when
both are populated the two regions are merged with visible
``--- Request ---`` / ``--- Response ---`` section markers so
screen-reader users can tell which region each highlighted match lives in.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "smoke.rlr"
    project = Project(db)
    # One row whose request mentions "admin" twice and whose response
    # mentions "session" once and "admin" once — enough to exercise the
    # singular/plural status sentence, the multi-anchor jump list, and
    # the cross-region merged-count case.
    project.add_history(
        host="example.test", method="POST", url="http://example.test/login",
        status=200, duration_ms=42, engine="httpx",
        raw_req=(b"POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n"
                 b"username=admin&password=admin"),
        raw_resp=(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
                  b"logged in as admin; session=abc123"),
    )
    settings = Settings()
    app = create_app(db, settings)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_detail_renders_without_query(client):
    """Baseline: existing pages must still work when no ?find is given."""
    r = client.get("/history/1")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # One unified find form is always present.
    assert 'id="body-find-q"' in body
    # Legacy per-region inputs are gone.
    assert 'id="req-find-q"' not in body
    assert 'id="resp-find-q"' not in body
    # No status region and no <mark> elements yet.
    assert 'id="body-find-status"' not in body
    assert "<mark" not in body


def _text(client, url):
    """Fetch `url` and return the body with HTML entities decoded so the
    test asserts on what a screen reader actually announces."""
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    return r.get_data(as_text=True), html.unescape(r.get_data(as_text=True))


def test_find_marks_matches_across_both_regions(client):
    """One query covers both request (2 hits) and response (1 hit) →
    one combined count of 3 and ordered jump anchors."""
    raw, body = _text(client, "/history/1?body_find=admin")
    assert '3 matches for "admin" in exchange.' in body
    assert 'id="body-m1"' in raw
    assert 'id="body-m2"' in raw
    assert 'id="body-m3"' in raw
    assert "Match 1 of 3 in exchange" in body
    assert "Match 3 of 3 in exchange" in body
    # Both section markers survive intact in the merged blob.
    assert "--- Request ---" in body
    assert "--- Response ---" in body


def test_find_singular_sentence(client):
    raw, body = _text(client, "/history/1?body_find=session")
    assert '1 match for "session" in exchange.' in body
    assert 'id="body-m1"' in raw


def test_no_match_renders_clear_status(client):
    raw, body = _text(client, "/history/1?body_find=nope-not-there")
    assert 'No matches for "nope-not-there" in exchange.' in body
    assert 'id="body-m1"' not in raw


def test_regex_error_is_reported_in_status(client):
    raw, body = _text(client, "/history/1?body_find=%28unclosed&body_re=1")
    assert "Regex error in exchange" in body


def test_only_request_present_no_section_markers(tmp_path):
    """When a row has only a request blob (no response captured yet)
    the merged blob is just the request — no section markers appear."""
    db = tmp_path / "req_only.rlr"
    project = Project(db)
    project.add_history(
        host="h", method="GET", url="http://h/", status=0, duration_ms=0,
        engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\nHost: h\r\n\r\nadmin in request only",
        raw_resp=b"",
    )
    app = create_app(db, Settings())
    app.config["TESTING"] = True
    with app.test_client() as c:
        r = c.get("/history/1?body_find=admin")
        assert r.status_code == 200
        body = html.unescape(r.get_data(as_text=True))
    assert '1 match for "admin" in exchange.' in body
    assert "--- Request ---" not in body
    assert "--- Response ---" not in body


def test_form_action_and_input_name_round_trip(client):
    """Regression guard: the URL the form actually submits must match
    what the blueprint reads. Render the page, confirm the form's
    `action` URL and the search-input's `name`, then submit a GET via
    those names — it must produce matches."""
    raw, _ = _text(client, "/history/1")
    assert 'action="/history/1"' in raw
    assert 'name="body_find"' in raw
    raw2, body2 = _text(client, "/history/1?body_find=admin")
    assert '3 matches for "admin" in exchange.' in body2
    assert 'id="body-m1"' in raw2
