"""Phase 4 — blueprint integration for built-in wordlists and file source."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.intruder import DEFAULT_MARKER
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p4.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/intruder/new")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _template_with_marker() -> str:
    return (
        f"GET /?u={DEFAULT_MARKER}admin{DEFAULT_MARKER} HTTP/1.1\n"
        "Host: 127.0.0.1\n\n"
    )


def test_new_form_lists_builtin_wordlists(client):
    r = client.get("/intruder/new")
    assert r.status_code == 200
    assert b"common_passwords" in r.data
    assert b"sqli_payloads" in r.data
    assert b"Wordlist from file" in r.data
    # Arg-style processor hint is exposed
    assert b"prefix:&lt;arg&gt;" in r.data


def test_create_attack_from_builtin_wordlist(client, app):
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "wl-sqli", "attack_type": "sniper", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _template_with_marker(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "wordlist", "wordlist_name": "sqli_payloads",
        "payloads_text": "", "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302
    proj = app.extensions["reqlore_project"]
    attacks = proj.list_intruder()
    assert attacks and attacks[0]["name"] == "wl-sqli"
    detail = proj.get_intruder(attacks[0]["id"])
    assert len(detail["payloads"][0]) >= 10
    assert any("'" in p for p in detail["payloads"][0])


def test_create_attack_from_file_wordlist(client, app, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "wl-file", "attack_type": "sniper", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _template_with_marker(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "wordlist_file", "wordlist_path": str(wl),
        "payloads_text": "", "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert detail["payloads"][0] == ["alpha", "beta", "gamma"]


def test_file_wordlist_missing_renders_form_error(client):
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "wl-missing", "attack_type": "sniper", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _template_with_marker(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "wordlist_file", "wordlist_path": "/no/such/file.txt",
        "payloads_text": "", "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 200
    assert b"not found" in r.data
