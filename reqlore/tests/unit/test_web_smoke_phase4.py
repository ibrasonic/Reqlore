"""Phase 4 web smoke tests: every new route must answer 200 (GET) / OK (POST)."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p4.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def test_scanner_active_form_present(client):
    r = client.get("/scanner/")
    assert r.status_code == 200
    assert b"Active scan" in r.data
    # All built-in check names appear as checkboxes
    for name in (b"xss-reflected", b"sqli-error", b"open-redirect",
                  b"ssti", b"os-cmd-time", b"jwt-alg-none",
                  b"prototype-pollution", b"graphql-introspection"):
        assert name in r.data


def test_graphql_index(client):
    r = client.get("/graphql/")
    assert r.status_code == 200
    assert b"GraphQL workbench" in r.data


def test_ws_index(client):
    r = client.get("/ws/")
    assert r.status_code == 200
    assert b"WebSocket" in r.data


def test_ws_new_form(client):
    r = client.get("/ws/new")
    assert r.status_code == 200
    assert b"WS URL" in r.data


def test_saml_index(client):
    r = client.get("/saml/")
    assert r.status_code == 200
    assert b"SAML inspector" in r.data


def test_saml_decode_post(client):
    import base64
    xml = ('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'ID="x"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            'idp</saml:Issuer></samlp:Response>')
    blob = base64.b64encode(xml.encode()).decode()
    client.get("/saml/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/saml/", data={"blob": blob, "_csrf": token},
                      follow_redirects=True)
    assert r.status_code == 200
    assert b"http-post" in r.data
    assert b"idp" in r.data


def test_poc_index(client):
    r = client.get("/poc/")
    assert r.status_code == 200
    assert b"CSRF PoC" in r.data
    assert b"Clickjacking PoC" in r.data


def test_poc_clickjacking_form(client):
    r = client.get("/poc/clickjacking")
    assert r.status_code == 200
    assert b"Target URL" in r.data


def test_poc_clickjacking_download(client):
    client.get("/poc/clickjacking")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/poc/clickjacking",
                     data={"url": "https://x.test/", "overlay": "go",
                           "_csrf": token})
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/html")
    assert b"<iframe" in r.data
    assert b'src="https://x.test/"' in r.data


def test_poc_csrf_form_download_from_history(client, app):
    proj = app.extensions["reqlore_project"]
    hid = proj.add_history(
        host="x.test", method="POST", url="https://x.test/transfer",
        status=200, duration_ms=1, engine="httpx",
        raw_req=(b"POST /transfer HTTP/1.1\r\n"
                  b"Host: x.test\r\n"
                  b"Content-Type: application/x-www-form-urlencoded\r\n"
                  b"\r\n"
                  b"to=bob&amount=999"),
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
    )
    r = client.get(f"/poc/csrf/{hid}")
    assert r.status_code == 200
    assert b"<form" in r.data
    assert b'name="amount"' in r.data and b'value="999"' in r.data


def test_macros_index(client):
    r = client.get("/macros/")
    assert r.status_code == 200
    assert b"Session-handling macros" in r.data


def test_macros_new_form(client):
    r = client.get("/macros/new")
    assert r.status_code == 200
    assert b"Definition" in r.data


def test_dashboard_links_all_modules(client):
    r = client.get("/")
    for href in (b"/scanner/", b"/reporter/", b"/plugins/", b"/graphql/",
                  b"/ws/", b"/saml/", b"/poc/", b"/macros/"):
        assert href in r.data, f"dashboard missing link {href!r}"
