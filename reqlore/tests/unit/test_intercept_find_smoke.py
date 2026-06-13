"""Smoke tests for find-in-body on the Intercept-detail page.

The held-request body sits in an editable <textarea> that browser
Ctrl+F cannot search, so the server-side find form is the only
AAA-clean way to point a screen-reader user at a substring inside the
held bytes. This file verifies the form is a SEPARATE <form
method=\"get\"> outside the POST edit form (so the find submit cannot
accidentally forward/drop the flow) and that match marks render.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "intercept.rlr"
    project = Project(db)
    project.enqueue_intercept(
        "request",
        (b"POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n"
         b"username=admin&password=admin"),
        "manual",
    )
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


def test_intercept_detail_renders_without_query(client):
    raw, _ = _text(client, "/proxy/intercept/1")
    # The find form is always present even with no query.
    assert 'id="body-find-q"' in raw
    # Status region and <mark> only appear after submitting.
    assert 'id="body-find-status"' not in raw
    assert "<mark" not in raw


def test_intercept_find_marks_two_matches(client):
    raw, body = _text(client, "/proxy/intercept/1?body_find=admin")
    assert '2 matches for "admin" in held request.' in body
    assert 'id="body-m1"' in raw
    assert 'id="body-m2"' in raw


def test_find_form_is_separate_from_edit_form(client):
    """The Find form must NOT be nested inside the POST edit form \u2014 a
    nested <form> would either be silently dropped by the browser or,
    worse, let the find submit re-issue the edit (forward edited).

    Find now renders ABOVE the editable textarea so a screen-reader
    user reaches the search and its jump list first, but the
    non-nesting invariant still holds: the find form must close
    before the edit form opens (or open after it closes).
    """
    raw, _ = _text(client, "/proxy/intercept/1")
    edit_form_start = raw.find('<form method="post"')
    edit_form_end = raw.find("</form>", edit_form_start)
    find_form_start = raw.find('class="find-form"')
    find_form_end = raw.find("</form>", find_form_start)
    assert edit_form_start != -1
    assert find_form_start != -1
    # Non-nesting invariant: either find closes before edit opens, or
    # find opens after edit closes. Either way, no overlap.
    assert find_form_end < edit_form_start or find_form_start > edit_form_end


def test_intercept_no_match(client):
    raw, body = _text(client, "/proxy/intercept/1?body_find=nothinghere")
    assert 'No matches for "nothinghere" in held request.' in body
    assert 'id="body-m1"' not in raw
