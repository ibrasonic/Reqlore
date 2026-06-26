"""Body-decode parity on the Proxy intercept detail page.

When the operator holds a response with ``Content-Encoding: gzip`` (or
deflate / br / zstd) the detail page must show readable bytes by
default \u2014 same UX as the History detail page \u2014 instead of a
compressed binary smear that breaks the screen reader. This file pins
that parity plus the radio-toggle behaviour.

The parallel test_history_*_decodes_compressed_body tests in
``test_web_smoke.py`` cover the History side; this file covers the
Proxy side using the shared ``_decode_helpers`` module.
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    proj = tmp_path / "proxydecode.rlr"
    return create_app(proj, Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_gzip_response(project) -> int:
    """Hold a fake response whose body is gzip-compressed plaintext."""
    plain = b"<html><body>Invalid username or password.</body></html>"
    body = gzip.compress(plain)
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    return project.enqueue_intercept_sync("response", resp, "test", "flow-gz")


def _seed_plain_request(project) -> int:
    """Hold a request with no Content-Encoding so the toggle is hidden."""
    req = b"GET /p HTTP/1.1\r\nHost: x.test\r\n\r\n"
    return project.enqueue_intercept_sync("request", req, "test", "flow-plain")


def test_proxy_intercept_detail_default_decodes_compressed_body(app, client):
    iid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/proxy/intercept/{iid}")
    assert r.status_code == 200
    # Body-display toggle is present (the response is encoded).
    assert b"Body display" in r.data
    assert b"Raw on-wire bytes" in r.data
    # Default view is decoded \u2014 plaintext is visible.
    assert b"Invalid username or password" in r.data


def test_proxy_intercept_detail_raw_radio_keeps_compressed_body(app, client):
    iid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/proxy/intercept/{iid}?decode=0")
    assert r.status_code == 200
    # decode=0 opts out \u2014 plaintext must not leak through.
    assert b"Invalid username or password" not in r.data


def test_proxy_intercept_detail_decode_radio_reveals_plaintext(app, client):
    iid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/proxy/intercept/{iid}?decode=1")
    assert r.status_code == 200
    assert b"Invalid username or password" in r.data
    # Content-Encoding header is stripped on the decoded display blob
    # so the round-trip math (header says gzip vs body is plain) does
    # not confuse the operator.
    assert b"Content-Encoding: gzip" not in r.data
    # Status note announces what was decoded.
    assert b"gzip" in r.data and b"bytes" in r.data


def test_proxy_intercept_detail_no_encoding_hides_toggle(app, client):
    iid = _seed_plain_request(app.extensions["reqlore_project"])
    r = client.get(f"/proxy/intercept/{iid}")
    assert r.status_code == 200
    # No Body-display section at all when the radios would be a no-op.
    assert b"Body display" not in r.data
