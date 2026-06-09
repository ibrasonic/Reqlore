"""Smoke tests for Phase 2 blueprints."""
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p2.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def test_intruder_index(client):
    r = client.get("/intruder/")
    assert r.status_code == 200
    assert b"Intruder" in r.data


def test_intruder_new_form(client):
    r = client.get("/intruder/new")
    assert r.status_code == 200
    assert b"Sniper" in r.data
    assert b"Cluster Bomb" in r.data


def test_matchreplace_index(client):
    r = client.get("/match-replace/")
    assert r.status_code == 200
    assert b"Match" in r.data


def test_comparer_index(client):
    r = client.get("/comparer/")
    assert r.status_code == 200
    assert b"Comparer" in r.data


def test_comparer_runs_diff(client):
    client.get("/comparer/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/comparer/", data={
        "a": "alpha\nbeta\ngamma", "b": "alpha\nBETA\ngamma\ndelta",
        "view": "request", "from_a": "", "from_b": "", "_csrf": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"changed" in r.data or b"only in" in r.data


def test_jwt_index(client):
    r = client.get("/jwt/")
    assert r.status_code == 200
    assert b"JWT" in r.data


def test_jwt_decode_round_trip(client):
    client.get("/jwt/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    jwt = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
           "eyJzdWIiOiJhbGljZSJ9.")
    r = client.post("/jwt/", data={
        "action": "decode", "token": jwt, "_csrf": token,
        "header_text": "", "payload_text": "", "alg": "HS256",
        "secret": "", "private_key": "", "public_key": "", "kid_values": "",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"alice" in r.data
    assert b"alg=none" in r.data  # warning surfaces


def test_sitemap_index(client):
    r = client.get("/sitemap/")
    assert r.status_code == 200
    assert b"Sitemap" in r.data


def test_search_index_empty(client):
    r = client.get("/search/")
    assert r.status_code == 200


def test_cues_wav_is_audio(client):
    r = client.get("/cues/ok.wav")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("audio/")
    # WAV magic
    assert r.data[:4] == b"RIFF"
    assert r.data[8:12] == b"WAVE"


def test_csp_includes_media(client):
    r = client.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "media-src 'self'" in csp
