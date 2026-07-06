"""Sequencer live-capture tests.

Three layers:

1. **Extractors** -- pure functions on a fake :class:`Response`.
2. **Storage** -- round-trip through SQLite (capture + samples).
3. **Blueprint + runner** -- end-to-end over a local HTTP server that
   issues a different ``Set-Cookie: SESSIONID=...`` per request.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.engines import Response, Timings
from reqlore.sequencer_capture import (
    EXTRACTOR_KINDS,
    CaptureRunner,
    extract_token,
    parse_target_from_history,
)
from reqlore.storage import Project

# ---------------------------------------------------------------- helpers


def _resp(headers: list[tuple[str, str]] | None = None,
          body: bytes = b"", status: int = 200) -> Response:
    return Response(
        status=status, reason="OK",
        headers=list(headers or []),
        body=body,
        timings=Timings(total_ms=1),
        engine="test",
    )


# ---------------------------------------------------------------- extractors


def test_extract_cookie_simple():
    r = _resp([("Set-Cookie", "SESSIONID=abc123")])
    assert extract_token("cookie", "SESSIONID", r) == "abc123"


def test_extract_cookie_with_attributes():
    r = _resp([("Set-Cookie", "SESSIONID=abc123; Path=/; HttpOnly; Secure")])
    assert extract_token("cookie", "SESSIONID", r) == "abc123"


def test_extract_cookie_picks_named_one_among_many():
    r = _resp([
        ("Set-Cookie", "consent=1; Path=/"),
        ("Set-Cookie", "SESSIONID=zzz"),
        ("Set-Cookie", "tracker=qq"),
    ])
    assert extract_token("cookie", "SESSIONID", r) == "zzz"


def test_extract_cookie_missing_returns_none():
    r = _resp([("Set-Cookie", "consent=1")])
    assert extract_token("cookie", "SESSIONID", r) is None


def test_extract_cookie_empty_arg_returns_none():
    r = _resp([("Set-Cookie", "SESSIONID=abc")])
    assert extract_token("cookie", "", r) is None


def test_extract_header_case_insensitive():
    r = _resp([("X-CSRF-Token", "abc")])
    assert extract_token("header", "x-csrf-token", r) == "abc"


def test_extract_header_missing_returns_none():
    r = _resp([])
    assert extract_token("header", "X-CSRF-Token", r) is None


def test_extract_regex_first_capture_group():
    body = b'{"token":"abcXYZ","other":"x"}'
    assert extract_token("regex", r'"token":"([^"]+)"', _resp(body=body)) == "abcXYZ"


def test_extract_regex_no_match_returns_none():
    body = b"nope"
    assert extract_token("regex", r"foo", _resp(body=body)) is None


def test_extract_regex_no_capture_group_falls_back_to_full_match():
    body = b"abcXYZ"
    assert extract_token("regex", r"abc[A-Z]+", _resp(body=body)) == "abcXYZ"


def test_extract_regex_invalid_pattern_returns_none():
    body = b"x"
    assert extract_token("regex", r"(", _resp(body=body)) is None


def test_extract_json_simple_path():
    body = b'{"token":"abc"}'
    assert extract_token("json", "token", _resp(body=body)) == "abc"


def test_extract_json_nested_with_list_index():
    body = b'{"items":[{"t":"first"},{"t":"second"}]}'
    assert extract_token("json", "items.1.t", _resp(body=body)) == "second"


def test_extract_json_missing_key_returns_none():
    body = b'{"token":"abc"}'
    assert extract_token("json", "missing", _resp(body=body)) is None


def test_extract_json_invalid_body_returns_none():
    body = b"<html>nope</html>"
    assert extract_token("json", "token", _resp(body=body)) is None


def test_extract_token_unknown_kind():
    assert extract_token("bogus", "x", _resp()) is None


def test_extract_token_truncates_huge_token():
    huge = "x" * 9000
    body = ('{"token":"' + huge + '"}').encode()
    out = extract_token("json", "token", _resp(body=body))
    assert out is not None
    assert len(out) == 4096


def test_extractor_kinds_constant():
    assert EXTRACTOR_KINDS == ("cookie", "header", "regex", "json")


# ---------------------------------------------------- parse_target_from_history


def test_parse_target_picks_known_session_cookie():
    raw = (
        b"GET /api HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"Cookie: track=qq; SESSIONID=zzz; theme=dark\r\n"
        b"\r\n"
    )
    hint = parse_target_from_history(raw, "https://target/api")
    assert hint["extractor_kind"] == "cookie"
    assert hint["extractor_arg"] == "SESSIONID"
    assert hint["url"] == "https://target/api"


def test_parse_target_no_known_cookie_defaults_empty_arg():
    raw = (
        b"GET /api HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"\r\n"
    )
    hint = parse_target_from_history(raw, "https://target/api")
    assert hint["extractor_kind"] == "cookie"
    assert hint["extractor_arg"] == ""


# ---------------------------------------------------------------- storage


def test_storage_create_and_list_capture(tmp_path: Path):
    p = Project(tmp_path / "s.rlr")
    cid = p.create_sequencer_capture(
        name="My Capture", url="http://target/login",
        template=b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
        engine="httpx", extractor_kind="cookie", extractor_arg="SESSIONID",
        max_samples=100, delay_ms=0, concurrency=1, significance="0.01",
    )
    assert cid > 0
    rows = p.list_sequencer_captures()
    assert len(rows) == 1
    assert rows[0]["name"] == "My Capture"
    assert rows[0]["status"] == "idle"


def test_storage_get_capture_round_trips_template(tmp_path: Path):
    p = Project(tmp_path / "s.rlr")
    tpl = b"POST /a HTTP/1.1\r\nHost: x\r\n\r\nbody=1"
    cid = p.create_sequencer_capture(
        name="rt", url="http://x/", template=tpl, engine="httpx",
        extractor_kind="header", extractor_arg="X-T", max_samples=8,
        delay_ms=0, concurrency=1, significance="0.01",
    )
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["template"] == tpl
    assert cap["extractor_kind"] == "header"
    assert cap["max_samples"] == 8


def test_storage_set_status_and_error_count(tmp_path: Path):
    p = Project(tmp_path / "s.rlr")
    cid = p.create_sequencer_capture(
        name="x", url="http://x/", template=b"\r\n",
        engine="httpx", extractor_kind="cookie", extractor_arg="S",
        max_samples=8, delay_ms=0, concurrency=1, significance="0.01",
    )
    p.set_sequencer_capture_status(
        cid, "running", stop_reason="", error_count=3,
    )
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["status"] == "running"
    assert cap["error_count"] == 3
    p.set_sequencer_capture_status(
        cid, "errored", stop_reason="boom", error_count=4,
    )
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["status"] == "errored"
    assert cap["stop_reason"] == "boom"


def test_storage_add_and_count_samples(tmp_path: Path):
    p = Project(tmp_path / "s.rlr")
    cid = p.create_sequencer_capture(
        name="x", url="http://x/", template=b"\r\n",
        engine="httpx", extractor_kind="cookie", extractor_arg="S",
        max_samples=8, delay_ms=0, concurrency=1, significance="0.01",
    )
    for i in range(5):
        p.add_sequencer_sample(
            capture_id=cid, seq=i + 1, token=f"tok-{i}",
            status=200, duration_ms=12,
        )
    assert p.count_sequencer_samples(cid) == 5
    tokens = p.list_sequencer_tokens(cid)
    assert tokens == [f"tok-{i}" for i in range(5)]


def test_storage_delete_capture_cascades_samples(tmp_path: Path):
    p = Project(tmp_path / "s.rlr")
    cid = p.create_sequencer_capture(
        name="x", url="http://x/", template=b"\r\n",
        engine="httpx", extractor_kind="cookie", extractor_arg="S",
        max_samples=8, delay_ms=0, concurrency=1, significance="0.01",
    )
    for i in range(3):
        p.add_sequencer_sample(
            capture_id=cid, seq=i, token="t", status=200, duration_ms=1,  # noqa: S106  # test fixture sequencer token, not a real credential
        )
    assert p.count_sequencer_samples(cid) == 3
    p.delete_sequencer_capture(cid)
    assert p.get_sequencer_capture(cid) is None
    assert p.count_sequencer_samples(cid) == 0


# ---------------------------------------------------------------- blueprint


def _client(tmp_path: Path):
    from reqlore.config import Settings
    from reqlore.web import create_app
    app = create_app(tmp_path / "p.rlr", Settings(), proxy=None)
    app.config["TESTING"] = True
    return app, app.test_client()


def _csrf(client) -> str:
    client.get("/sequencer/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_capture_new_get_renders(tmp_path: Path):
    _, c = _client(tmp_path)
    r = c.get("/sequencer/capture/new")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "New live capture" in body
    assert "Extractor kind" in body


def test_capture_new_post_requires_extractor_arg(tmp_path: Path):
    _, c = _client(tmp_path)
    csrf = _csrf(client=c)
    r = c.post("/sequencer/capture/new", data={
        "_csrf": csrf,
        "name": "x", "url": "http://127.0.0.1/", "engine": "httpx",
        "extractor_kind": "cookie", "extractor_arg": "",
        "max_samples": "100", "delay_ms": "0", "concurrency": "1",
        "significance": "0.01",
        "template": "GET / HTTP/1.1\nHost: x\n\n",
    })
    # No redirect: form re-renders with error message.
    assert r.status_code == 200
    assert b"Extractor argument is required" in r.data


def test_capture_new_post_creates_capture(tmp_path: Path):
    _, c = _client(tmp_path)
    csrf = _csrf(client=c)
    r = c.post("/sequencer/capture/new", data={
        "_csrf": csrf,
        "name": "Demo", "url": "http://127.0.0.1/", "engine": "httpx",
        "extractor_kind": "cookie", "extractor_arg": "SESSIONID",
        "max_samples": "100", "delay_ms": "0", "concurrency": "1",
        "significance": "0.01",
        "template": "GET / HTTP/1.1\nHost: 127.0.0.1\n\n",
    })
    assert r.status_code == 302
    assert "/sequencer/capture/" in r.headers["Location"]
    follow = c.get(r.headers["Location"])
    assert follow.status_code == 200
    body = follow.get_data(as_text=True)
    assert "Demo" in body
    assert "Start" in body  # not yet running, Start button visible


def test_capture_detail_404(tmp_path: Path):
    _, c = _client(tmp_path)
    assert c.get("/sequencer/capture/9999").status_code == 404


def test_capture_detail_reconciles_stale_running(tmp_path: Path):
    """If the DB says ``running`` but no in-process runner exists (server
    restart), the detail page must auto-reconcile to ``idle`` so the
    operator sees a Start button instead of a stale Pause button."""
    _, c = _client(tmp_path)
    # Lazy-create the project on first request, then write a stale row.
    c.get("/sequencer/")
    p = Project(tmp_path / "p.rlr")
    cid = p.create_sequencer_capture(
        name="stale", url="http://127.0.0.1/", template=b"GET / HTTP/1.1\r\n\r\n",
        engine="httpx", extractor_kind="cookie", extractor_arg="X",
        max_samples=10, delay_ms=0, concurrency=1, significance="0.01",
    )
    p.set_sequencer_capture_status(cid, "running")
    r = c.get(f"/sequencer/capture/{cid}")
    assert r.status_code == 200
    cap_after = Project(tmp_path / "p.rlr").get_sequencer_capture(cid)
    assert cap_after is not None
    assert cap_after["status"] == "idle"


# ---------------------------------------------------- runner integration


class _CookieIssuer(BaseHTTPRequestHandler):
    """Issues a fresh, predictable token per request."""

    counter_lock = threading.Lock()
    counter = 0

    def do_GET(self):  # noqa: N802
        with _CookieIssuer.counter_lock:
            _CookieIssuer.counter += 1
            n = _CookieIssuer.counter
        token = f"sess-{n:06d}"
        self.send_response(200)
        self.send_header("Set-Cookie", f"SESSIONID={token}; Path=/; HttpOnly")
        self.send_header("Content-Type", "text/plain")
        body = b"ok"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_k):
        pass


@pytest.fixture
def issuer_server():
    _CookieIssuer.counter = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CookieIssuer)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()


def test_runner_collects_session_cookies(tmp_path: Path, issuer_server: int):
    """End-to-end: runner should drive the local server enough times to
    collect the configured ``max_samples`` and persist them in order."""
    p = Project(tmp_path / "r.rlr")
    target = 12
    template = (
        f"GET / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{issuer_server}\r\n"
        f"\r\n"
    ).encode()
    cid = p.create_sequencer_capture(
        name="e2e", url=f"http://127.0.0.1:{issuer_server}/",
        template=template, engine="httpx",
        extractor_kind="cookie", extractor_arg="SESSIONID",
        max_samples=target, delay_ms=0, concurrency=1, significance="0.01",
    )
    runner = CaptureRunner(p, cid)
    runner.start()
    assert runner.wait(timeout=30), "runner did not complete in time"
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["status"] == "done"
    assert p.count_sequencer_samples(cid) == target
    tokens = p.list_sequencer_tokens(cid)
    assert all(t.startswith("sess-") for t in tokens)
    # All collected tokens must be unique (the issuer assigns a fresh id).
    assert len(set(tokens)) == target


class _NoCookieServer(BaseHTTPRequestHandler):
    """Always returns 200 with no Set-Cookie -- triggers extractor failure."""

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        body = b"ok"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_k):
        pass


@pytest.fixture
def empty_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _NoCookieServer)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()


def test_runner_aborts_when_no_token_is_extractable(tmp_path: Path,
                                                     empty_server: int):
    """If 10 responses come back with nothing the extractor can find,
    the runner must mark the capture ``errored`` and stop -- not loop
    forever."""
    p = Project(tmp_path / "r.rlr")
    template = (
        f"GET / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{empty_server}\r\n"
        f"\r\n"
    ).encode()
    cid = p.create_sequencer_capture(
        name="bad", url=f"http://127.0.0.1:{empty_server}/",
        template=template, engine="httpx",
        extractor_kind="cookie", extractor_arg="SESSIONID",
        max_samples=200, delay_ms=0, concurrency=1, significance="0.01",
    )
    runner = CaptureRunner(p, cid)
    runner.start()
    assert runner.wait(timeout=15)
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["status"] == "errored"
    assert "extractor" in cap["stop_reason"]
    assert p.count_sequencer_samples(cid) == 0


def test_runner_cancel_stops_quickly(tmp_path: Path, issuer_server: int):
    p = Project(tmp_path / "r.rlr")
    template = (
        f"GET / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{issuer_server}\r\n"
        f"\r\n"
    ).encode()
    cid = p.create_sequencer_capture(
        name="cancel", url=f"http://127.0.0.1:{issuer_server}/",
        template=template, engine="httpx",
        extractor_kind="cookie", extractor_arg="SESSIONID",
        max_samples=20000, delay_ms=5, concurrency=1, significance="0.01",
    )
    runner = CaptureRunner(p, cid)
    runner.start()
    # Let the thread pick up some samples then cancel.
    deadline = time.monotonic() + 5
    while p.count_sequencer_samples(cid) < 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    runner.cancel()
    assert runner.wait(timeout=10)
    cap = p.get_sequencer_capture(cid)
    assert cap is not None
    assert cap["status"] == "cancelled"
    # Sanity: we collected at least a handful, far short of max_samples.
    assert 3 <= p.count_sequencer_samples(cid) < 20000
