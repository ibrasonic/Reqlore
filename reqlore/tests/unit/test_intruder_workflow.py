"""Phase 5 — advanced workflow: stop-on-match, stop-on-status, retries, progress."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.intruder import AttackRunner, find_positions
from reqlore.storage import Project


_MARKER = "\u00a7"
_TPL = (
    f"GET /?q={_MARKER}X{_MARKER} HTTP/1.1\r\n"
    "Host: 127.0.0.1:%d\r\n"
    "\r\n"
)


class _PathEcho(BaseHTTPRequestHandler):
    """200 with the request path echoed in the body."""
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        body = self.path.encode()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_k):  # silence test output
        pass


class _StatusByPayload(BaseHTTPRequestHandler):
    """Returns 200 except for ``q=admin`` which returns 302."""
    def do_GET(self):  # noqa: N802
        status = 302 if "q=admin" in self.path else 200
        self.send_response(status)
        self.send_header("Content-Length", "0")
        if status == 302:
            self.send_header("Location", "/landing")
        self.end_headers()

    def log_message(self, *_a, **_k):
        pass


def _start_server(handler) -> tuple[int, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv.server_address[1], srv


@pytest.fixture
def echo_server():
    port, srv = _start_server(_PathEcho)
    yield port
    srv.shutdown(); srv.server_close()


@pytest.fixture
def status_server():
    port, srv = _start_server(_StatusByPayload)
    yield port
    srv.shutdown(); srv.server_close()


def _create_attack(p: Project, port: int, payloads: list[str], **opts) -> int:
    tpl = (_TPL % port).encode()
    return p.create_intruder(
        name="t", attack_type="sniper",
        template=tpl, positions=find_positions(tpl),
        payloads=[payloads],
        options={"concurrency": 1, "max_requests": 100,
                  "timeout": 5.0, **opts},
        url=f"http://127.0.0.1:{port}/", engine="httpx",
    )


# ---------- stop on match ----------

def test_stop_on_match_cancels_remaining(tmp_path: Path, echo_server: int):
    p = Project(tmp_path / "som.rlr")
    aid = _create_attack(
        p, echo_server,
        ["alpha", "TRIGGER", "gamma", "delta", "epsilon"],
        grep=[r"TRIGGER"], stop_on_match=True,
    )
    r = AttackRunner(p, aid)
    r.start(); r.wait(timeout=30)
    results = p.list_intruder_results(aid)
    # We must see the trigger row and *fewer* total rows than the 5 planned.
    seqs = sorted(x["seq"] for x in results)
    assert any(x["matched"] for x in results)
    assert len(seqs) < 5
    # 'done' final status, with stop_reason explaining the auto-stop.
    assert p.get_intruder(aid)["status"] == "done"
    assert "grep match" in r.stop_reason


def test_no_stop_on_match_runs_all(tmp_path: Path, echo_server: int):
    p = Project(tmp_path / "noms.rlr")
    aid = _create_attack(
        p, echo_server, ["a", "b", "c"],
        grep=[r"q=b"], stop_on_match=False,
    )
    r = AttackRunner(p, aid)
    r.start(); r.wait(timeout=30)
    assert len(p.list_intruder_results(aid)) == 3
    assert p.get_intruder(aid)["status"] == "done"
    assert r.stop_reason == ""


# ---------- stop on status ----------

def test_stop_on_status_cancels_on_match(tmp_path: Path, status_server: int):
    p = Project(tmp_path / "sos.rlr")
    aid = _create_attack(
        p, status_server,
        ["root", "guest", "admin", "test", "demo"],
        stop_on_status=[302],
    )
    r = AttackRunner(p, aid)
    r.start(); r.wait(timeout=30)
    results = p.list_intruder_results(aid)
    assert any(x["status"] == 302 for x in results)
    assert len(results) < 5
    assert "status 302" in r.stop_reason
    assert p.get_intruder(aid)["status"] == "done"


# ---------- retries ----------

def test_retries_recover_from_transient_send_exception(tmp_path: Path, echo_server: int):
    """Monkeypatch send to fail twice, then succeed; with retries=2 the row lands."""
    p = Project(tmp_path / "rt.rlr")
    aid = _create_attack(p, echo_server, ["only"], retries=2, delay_ms=0)

    from reqlore import intruder as mod
    real = mod.httpx_engine.send
    calls = {"n": 0}

    def flaky(req, **kw):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("simulated network blip")
        return real(req, **kw)

    mod.httpx_engine.send = flaky
    try:
        r = AttackRunner(p, aid)
        r.start(); r.wait(timeout=30)
    finally:
        mod.httpx_engine.send = real

    results = p.list_intruder_results(aid)
    assert len(results) == 1
    assert results[0]["status"] == 200
    assert calls["n"] == 3  # 1 initial + 2 retries


def test_retries_exhausted_marks_attack_errored_without_row(tmp_path: Path, echo_server: int):
    """All retries fail → the row is not persisted and the attack is marked errored.

    The runner used to mark this 'done', which was indistinguishable from
    a clean run. Failures now surface as 'errored' with ``stop_reason``
    pointing at the first underlying exception.
    """
    p = Project(tmp_path / "rt2.rlr")
    aid = _create_attack(p, echo_server, ["x"], retries=1, delay_ms=0)

    from reqlore import intruder as mod
    real = mod.httpx_engine.send

    def always_fail(req, **kw):
        raise RuntimeError("nope")

    mod.httpx_engine.send = always_fail
    try:
        r = AttackRunner(p, aid)
        r.start(); r.wait(timeout=30)
    finally:
        mod.httpx_engine.send = real

    assert p.list_intruder_results(aid) == []
    assert p.get_intruder(aid)["status"] == "errored"
    assert r.errors  # at least one job recorded its error
    assert "nope" in r.stop_reason


# ---------- progress ----------

def test_runner_exposes_total_jobs(tmp_path: Path, echo_server: int):
    p = Project(tmp_path / "pj.rlr")
    aid = _create_attack(p, echo_server, ["a", "b", "c", "d"])
    r = AttackRunner(p, aid)
    r.start(); r.wait(timeout=30)
    assert r.total_jobs == 4
