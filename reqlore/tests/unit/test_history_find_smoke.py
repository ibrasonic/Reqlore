"""Smoke tests for the find-in-body widget on History detail.

This is the first end-to-end web-layer test in the repo. The find
widget is the visible payoff of `a11y.find_in_text` and the
`_find.html` macros, so it warrants a render check: a regex slip in
the macro would otherwise only surface in manual browser testing.

The fixture builds a real Flask app on a tmp SQLite project, inserts
one history row whose request and response bodies each contain a known
token, then issues GETs and asserts what the screen reader and the
sighted user actually see.
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
    # mentions "session" once — enough to exercise the singular vs
    # plural status sentence and the multi-anchor jump list.
    project.add_history(
        host="example.test", method="POST", url="http://example.test/login",
        status=200, duration_ms=42, engine="httpx",
        raw_req=(b"POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n"
                 b"username=admin&password=admin"),
        raw_resp=(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
                  b"logged in; session=abc123"),
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
    # Form is always present.
    assert 'id="req-find-q"' in body
    assert 'id="resp-find-q"' in body
    # No status region and no <mark> elements yet.
    assert 'id="req-find-status"' not in body
    assert "<mark" not in body


def _text(client, url):
    """Fetch `url` and return the body with HTML entities decoded so the
    test asserts on what a screen reader actually announces."""
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    return r.get_data(as_text=True), html.unescape(r.get_data(as_text=True))


def test_request_find_marks_two_matches(client):
    raw, body = _text(client, "/history/1?req_find=admin")
    # Status sentence visible and accurate.
    assert '2 matches for "admin" in request.' in body
    # Both anchors and both marks are present and numbered 1..2.
    assert 'id="req-m1"' in raw
    assert 'id="req-m2"' in raw
    # Jump list announces "Match N of M" sentences (WCAG 2.4.9 AAA).
    assert "Match 1 of 2 in request" in body
    assert "Match 2 of 2 in request" in body


def test_response_find_singular_sentence(client):
    raw, body = _text(client, "/history/1?resp_find=session")
    assert '1 match for "session" in response.' in body
    assert 'id="resp-m1"' in raw
    # Request-side form must remain unmarked.
    assert 'id="req-m1"' not in raw


def test_no_match_renders_clear_status(client):
    raw, body = _text(client, "/history/1?req_find=nope-not-there")
    assert 'No matches for "nope-not-there" in request.' in body
    assert 'id="req-m1"' not in raw


def test_regex_error_is_reported_in_status(client):
    raw, body = _text(client, "/history/1?resp_find=%28unclosed&resp_re=1")
    assert "Regex error in response" in body


def test_independent_state_for_request_and_response(client):
    raw, body = _text(client, "/history/1?req_find=admin&resp_find=session")
    assert '2 matches for "admin" in request.' in body
    assert '1 match for "session" in response.' in body
    assert 'id="req-m1"' in raw
    assert 'id="resp-m1"' in raw
