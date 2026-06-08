"""Integration test: run an Intruder attack against a local test server."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.intruder import AttackRunner
from reqlore.storage import Project


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        body = self.path.encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
