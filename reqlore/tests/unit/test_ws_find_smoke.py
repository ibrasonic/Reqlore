"""Smoke tests for find-in-body on the WebSocket transcript page.

A transcript page can hold dozens of large message bodies; the find
widget flattens them into one searchable text block (with a one-line
header per message) so the user can locate a substring with a real
line number instead of paging through table rows.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app
from reqlore.websocket import WSMessage, WSTranscript


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "ws.rlr"
    project = Project(db)
    transcript = WSTranscript(url="ws://example.test/socket", closed=True)
    transcript.messages.append(WSMessage(
        direction="send", ts=1, kind="text",
        data='{"hello": "admin"}', size=18,
    ))
    transcript.messages.append(WSMessage(
        direction="recv", ts=2, kind="text",
        data='{"role": "admin", "token": "abc"}', size=33,
    ))
    project.set_state("ws:next_id", "2")
    project.set_state("ws:1", transcript.to_json())
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


def test_ws_show_renders_without_query(client):
    raw, _ = _text(client, "/ws/1")
    # Form is present once the transcript has messages.
    assert 'id="tx-find-q"' in raw
    assert "<mark" not in raw


def test_ws_find_marks_two_matches(client):
    raw, body = _text(client, "/ws/1?tx_find=admin")
    assert '2 matches for "admin" in transcript.' in body
    assert 'id="tx-m1"' in raw
    assert 'id="tx-m2"' in raw


def test_ws_no_match(client):
    raw, body = _text(client, "/ws/1?tx_find=nothinghere")
    assert 'No matches for "nothinghere" in transcript.' in body
    assert "<mark" not in raw
