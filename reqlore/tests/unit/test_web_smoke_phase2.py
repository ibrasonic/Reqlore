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


def test_comparer_download_diff(client):
    """POST a manual compare, follow PRG to extract the stash token, then
    fetch /comparer/export.diff?t=... and assert a valid unified-diff
    attachment comes back."""
    from urllib.parse import parse_qs, urlsplit
    client.get("/comparer/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/comparer/", data={
        "a": "alpha\nbeta\ngamma", "b": "alpha\nBETA\ngamma\ndelta",
        "view": "request", "from_a": "", "from_b": "", "_csrf": token,
    })
    assert r.status_code == 302
    qs = parse_qs(urlsplit(r.headers["Location"]).query)
    assert "t" in qs and qs["t"][0]
    t = qs["t"][0]

    # Download link is rendered on the results page.
    page = client.get(f"/comparer/?t={t}")
    assert page.status_code == 200
    assert b"Download unified diff" in page.data
    assert f"/comparer/export.diff?t={t}".encode() in page.data

    dl = client.get(f"/comparer/export.diff?t={t}")
    assert dl.status_code == 200
    assert dl.mimetype == "text/x-diff"
    cd = dl.headers["Content-Disposition"]
    assert "attachment" in cd and ".diff" in cd
    body = dl.data.decode("utf-8")
    assert body.startswith("--- A\n+++ B\n")
    assert "-beta" in body and "+BETA" in body and "+delta" in body


def test_comparer_export_404_when_empty(client):
    """No token, no from_a/from_b → 404 (nothing to export)."""
    r = client.get("/comparer/export.diff")
    assert r.status_code == 404


def test_comparer_export_identical_inputs_serves_notice(client):
    from urllib.parse import parse_qs, urlsplit
    client.get("/comparer/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/comparer/", data={
        "a": "same\ntext", "b": "same\ntext",
        "view": "request", "from_a": "", "from_b": "", "_csrf": token,
    })
    t = parse_qs(urlsplit(r.headers["Location"]).query)["t"][0]
    dl = client.get(f"/comparer/export.diff?t={t}")
    assert dl.status_code == 200
    assert b"No differences" in dl.data


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


def test_search_renders_result_link(client, app):
    """Regression: search/index.html linked to non-existent 'history.detail'."""
    proj = app.extensions["reqlore_project"]
    hid = proj.add_history(
        host="127.0.0.1", method="GET", url="http://127.0.0.1/needle",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET /needle HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    )
    r = client.get("/search/?q=needle&where=url")
    assert r.status_code == 200
    assert f'/history/{hid}'.encode() in r.data


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
