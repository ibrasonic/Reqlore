"""Smoke tests for find-in-body on the Repeater response panel.

Repeater is the high-value target for response-body find: the user
sends a payload, gets back a long JSON / HTML response, and wants to
locate a token without reading the lot. We stash a fake response in
the Repeater's PRG cache so we can render the response panel without
actually making a network call.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.engines import Response, Timings
from reqlore.storage import Project
from reqlore.web import create_app
from reqlore.web.blueprints.repeater import _cache as repeater_cache


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "rep.rlr"
    Project(db)
    settings = Settings()
    app = create_app(db, settings)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _stash_resp(body: bytes) -> str:
    resp = Response(
        status=200, reason="OK",
        headers=[("Content-Type", "text/plain")],
        body=body, http_version="1.1",
        timings=Timings(total_ms=10), engine="httpx",
    )
    return repeater_cache.put({
        "form": {
            "method": "GET", "url": "http://x.test/",
            "headers_text": "", "body": "",
            "engine": "httpx", "http_version": "1.1",
        },
        "resp_obj": resp,
        "summary": "200 OK in 10 ms",
        "render_blocks": {},
    })


def _text(client, url):
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    raw = r.get_data(as_text=True)
    return raw, html.unescape(raw)


def test_repeater_with_no_response_renders_no_find_form(client):
    """When there's no response, the response section is hidden, so the
    response-body find form must not appear either."""
    raw, _ = _text(client, "/repeater/")
    assert 'id="resp-body-find-q"' not in raw


def test_repeater_response_body_find_marks_match(client):
    tok = _stash_resp(b"alpha admin beta admin gamma")
    raw, body = _text(client,
                      f"/repeater/?t={tok}&resp_body_find=admin")
    # Form rendered and query echoed back.
    assert 'id="resp-body-find-q"' in raw
    assert 'value="admin"' in raw
    # Status sentence + at least one mark anchor.
    assert '2 matches for "admin" in response body.' in body
    assert 'id="resp-body-m1"' in raw
    assert 'id="resp-body-m2"' in raw


def test_repeater_response_find_no_match(client):
    tok = _stash_resp(b"alpha beta gamma")
    raw, body = _text(client,
                      f"/repeater/?t={tok}&resp_body_find=missing")
    assert 'No matches for "missing" in response body.' in body
    assert 'id="resp-body-m1"' not in raw
