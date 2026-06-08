"""Phase 5 - smoke tests for the 4 new blueprints (sequencer / oast / h2 / smuggling)."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p5.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# ---- Sequencer ----

def test_sequencer_index(client):
    r = client.get("/sequencer/")
    assert r.status_code == 200
    assert b"token quality" in r.data.lower()


def test_sequencer_post_analyses_tokens(client):
    token = _csrf(client)
    r = client.post("/sequencer/", data={
        "_csrf": token,
        "tokens": "abc123\ndef456\nghi789\njkl012",
    })
    assert r.status_code == 200
    assert b"Result &mdash;" in r.data or b"Result" in r.data
    assert b"sample(s)" in r.data


# ---- OAST ----

def test_oast_index(client):
    r = client.get("/oast/")
    assert r.status_code == 200
    assert b"out-of-band" in r.data.lower()


def test_oast_start_and_stop_lifecycle(client, app):
    token = _csrf(client)
    r = client.post("/oast/start", data={"_csrf": token})
    assert r.status_code == 302
    follow = client.get(r.headers["Location"])
    assert b"running on http://127.0.0.1" in follow.data
    # Stop releases the socket
    r = client.post("/oast/stop", data={"_csrf": token})
    assert r.status_code == 302


def test_oast_new_token_creates_one(client):
    token = _csrf(client)
    client.post("/oast/start", data={"_csrf": token})
    r = client.post("/oast/new-token", data={"_csrf": token})
    follow = client.get(r.headers["Location"])
    assert b"New token:" in follow.data
    client.post("/oast/stop", data={"_csrf": token})


# ---- H2 ----

def test_h2_index(client):
    r = client.get("/h2/")
    assert r.status_code == 200
    assert b"HTTP/2 frame tool" in r.data


def test_h2_parse_hex(client):
    token = _csrf(client)
    # Pre-built SETTINGS frame (ACK).
    r = client.post("/h2/", data={
        "_csrf": token, "action": "parse",
        "hex": "00 00 00 04 01 00 00 00 00",
    })
    assert r.status_code == 200
    assert b"SETTINGS" in r.data
    assert b"ACK" in r.data


def test_h2_build_ping(client):
    token = _csrf(client)
    r = client.post("/h2/", data={
        "_csrf": token, "action": "build",
        "frame": "ping", "opaque": "reqlore!",
    })
    assert r.status_code == 200
    assert b"Built frame (hex)" in r.data


# ---- Smuggling ----

def test_smuggling_index(client):
    r = client.get("/smuggling/")
    assert r.status_code == 200
    assert b"smuggling helpers" in r.data.lower()


def test_smuggling_generate_payload(client):
    token = _csrf(client)
    r = client.post("/smuggling/", data={
        "_csrf": token,
        "url": "https://x.test/some/path",
        "technique": "cl.te",
        "smuggled_method": "GET",
        "smuggled_path": "/admin",
    })
    assert r.status_code == 200
    assert b"CL.TE" in r.data
    assert b"Transfer-Encoding: chunked" in r.data


def test_smuggling_download_returns_bytes(client):
    token = _csrf(client)
    r = client.post("/smuggling/", data={
        "_csrf": token,
        "url": "https://x.test/",
        "technique": "te.cl",
        "smuggled_method": "GET",
        "smuggled_path": "/admin",
        "download": "1",
    })
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert b"Transfer-Encoding: chunked" in r.data


# ---- Dashboard + nav links ----

def test_dashboard_links_phase5_modules(client):
    r = client.get("/")
    for href in (b"/sequencer/", b"/oast/", b"/h2/", b"/smuggling/"):
        assert href in r.data, f"dashboard missing link {href!r}"


def test_nav_lists_phase5(client):
    r = client.get("/")
    for label in (b"Sequencer", b"OAST", b"Smuggling"):
        assert label in r.data
