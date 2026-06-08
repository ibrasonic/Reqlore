"""Phase 5 - Local OAST receiver."""
from __future__ import annotations

import socket
import time
import urllib.request

import pytest

from reqlore.oast import LocalOAST


@pytest.fixture
def oast():
    o = LocalOAST(host="127.0.0.1", port=0)
    o.start()
    yield o
    o.stop()


def _hit(url: str, *, method: str = "GET", data: bytes | None = None,
          headers: dict[str, str] | None = None) -> str:
    req = urllib.request.Request(url, data=data, method=method,
                                  headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode()


def test_receiver_starts_on_random_port(oast):
    assert oast.is_running()
    s = oast.status()
    assert s.port > 0
    assert s.base_url == f"http://127.0.0.1:{s.port}"


def test_records_get_interaction(oast):
    tok = oast.new_token()
    body = _hit(oast.url_for(tok) + "ping")
    assert body == "ok\n"
    # Allow the threaded HTTPServer a moment to enqueue
    for _ in range(10):
        if oast.interactions():
            break
        time.sleep(0.05)
    ix = oast.interactions()
    assert len(ix) == 1
    assert ix[0].token == tok
    assert ix[0].method == "GET"
    assert ix[0].path.startswith(f"/{tok}/ping")
    assert ix[0].bytes_in == 0


def test_records_post_body(oast):
    tok = oast.new_token()
    _hit(oast.url_for(tok), method="POST", data=b"hello", headers={"Content-Length": "5"})
    for _ in range(10):
        if oast.interactions():
            break
        time.sleep(0.05)
    ix = oast.interactions(token=tok)
    assert len(ix) == 1
    assert ix[0].method == "POST"
    assert ix[0].body == "hello"
    assert ix[0].bytes_in == 5


def test_unknown_token_logged_as_underscore(oast):
    _hit(f"{oast.base_url()}/foo/bar")
    for _ in range(10):
        if oast.interactions():
            break
        time.sleep(0.05)
    ix = oast.interactions()
    assert any(i.token == "_" for i in ix)


def test_clear_resets_log(oast):
    tok = oast.new_token()
    _hit(oast.url_for(tok))
    for _ in range(10):
        if oast.interactions():
            break
        time.sleep(0.05)
    assert oast.interactions()
    oast.clear()
    assert oast.interactions() == []


def test_stop_releases_socket(oast):
    s = oast.status()
    port = s.port
    oast.stop()
    # Port must be re-bindable.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    finally:
        sock.close()
