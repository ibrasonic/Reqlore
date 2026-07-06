"""Integration test: run an Intruder attack against a local test server."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.intruder import SQLI_PAYLOADS, AttackRunner
from reqlore.storage import Project


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        body = self.path.encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        out = b"POST body=" + body
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_a, **_k):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()


def test_intruder_run_against_local(tmp_path: Path, server: int):
    p = Project(tmp_path / "i.rlr")
    marker = "\u00a7"
    tpl = (
        f"GET /?q={marker}X{marker} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        f"\r\n"
    ).encode()
    from reqlore.intruder import find_positions
    positions = find_positions(tpl)
    aid = p.create_intruder(
        name="echo", attack_type="sniper",
        template=tpl, positions=positions,
        payloads=[["alpha", "beta", "gamma"]],
        options={"concurrency": 2, "max_requests": 100,
                  "grep": [r"^/\?q=[a-z]+$"], "timeout": 5.0},
        url=f"http://127.0.0.1:{server}/",
        engine="httpx",
    )
    r = AttackRunner(p, aid)
    r.start()
    r.wait(timeout=30)
    results = p.list_intruder_results(aid)
    assert len(results) == 3
    statuses = sorted(x["status"] for x in results)
    assert statuses == [200, 200, 200]
    # grep matched the echoed path
    assert all("q=" in x["grep_hits"] for x in results)


def test_intruder_run_stale_content_length_in_template(tmp_path: Path, server: int):
    """Regression: a POST template carries a Content-Length copied from
    History. Payload substitution changes the body length on every
    iteration, so the header is stale by definition. The framework must
    drop it (and let the engine recompute from the actual body) instead
    of forwarding the stale value -- httpx's underlying h11 raises
    ``LocalProtocolError`` and the raw engine sends a frame the server
    rejects. Without the fix this attack ends in ``errored`` with zero
    results, which is exactly what an operator hit when running a SQLi
    sniper through a login form.
    """
    p = Project(tmp_path / "stale.rlr")
    marker = "\u00a7"
    # Original body 'username=admin&password=x' -> Content-Length: 25.
    # SQLi payloads vary in length (1 .. 30+ bytes) so substitution makes
    # the header wrong every which way.
    tpl = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 25\r\n"
        f"\r\n"
        f"username={marker}admin{marker}&password=x"
    ).encode()
    from reqlore.intruder import find_positions
    positions = find_positions(tpl)
    assert len(positions) == 1

    aid = p.create_intruder(
        name="sqli-stale-cl",
        attack_type="sniper",
        template=tpl,
        positions=positions,
        payloads=[list(SQLI_PAYLOADS)],
        options={"concurrency": 2, "max_requests": 100, "timeout": 5.0,
                  "grep": []},
        url=f"http://127.0.0.1:{server}/",
        engine="httpx",
    )
    r = AttackRunner(p, aid)
    r.start()
    r.wait(timeout=30)

    attack = p.get_intruder(aid)
    assert attack is not None
    assert attack["status"] == "done", (
        f"attack did not complete cleanly: status={attack['status']}, "
        f"stop_reason={r.stop_reason!r}, errors={dict(list(r.errors.items())[:3])}"
    )
    results = p.list_intruder_results(aid)
    assert len(results) == len(SQLI_PAYLOADS)
    assert all(row["status"] == 200 for row in results), (
        f"expected every request to succeed, got statuses "
        f"{sorted({row['status'] for row in results})}"
    )
    assert not r.errors


def test_intruder_run_drops_transfer_encoding_from_template(tmp_path: Path, server: int):
    """Transfer-Encoding has the same problem class as Content-Length --
    if the template carries ``Transfer-Encoding: chunked`` but the
    framework sends a plain body, the request is malformed. Dropping it
    in ``template_to_request`` lets the engine pick the right framing.
    """
    p = Project(tmp_path / "te.rlr")
    marker = "\u00a7"
    tpl = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"user={marker}x{marker}"
    ).encode()
    from reqlore.intruder import find_positions
    positions = find_positions(tpl)
    aid = p.create_intruder(
        name="te-stale",
        attack_type="sniper",
        template=tpl,
        positions=positions,
        payloads=[["alpha", "beta"]],
        options={"concurrency": 1, "max_requests": 5, "timeout": 5.0,
                  "grep": []},
        url=f"http://127.0.0.1:{server}/",
        engine="httpx",
    )
    r = AttackRunner(p, aid)
    r.start()
    r.wait(timeout=15)
    row_te = p.get_intruder(aid)
    assert row_te is not None
    assert row_te["status"] == "done"
    results = p.list_intruder_results(aid)
    assert len(results) == 2
    assert all(row["status"] == 200 for row in results)
