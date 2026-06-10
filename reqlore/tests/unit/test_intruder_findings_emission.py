"""A.1 verification: Intruder grep matches flow into the unified findings
ledger via the write bus."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.intruder import AttackRunner, find_positions
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
        return


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()


def _start_attack(p: Project, port: int, *, options: dict) -> int:
    marker = "\u00a7"
    tpl = (
        f"GET /?q={marker}X{marker} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"\r\n"
    ).encode()
    aid = p.create_intruder(
        name="emit", attack_type="sniper",
        template=tpl, positions=find_positions(tpl),
        payloads=[["alpha", "beta"]],
        options=options,
        url=f"http://127.0.0.1:{port}/",
        engine="httpx",
    )
    r = AttackRunner(p, aid)
    r.start()
    r.wait(timeout=30)
    return aid


def test_grep_match_emits_finding(tmp_path: Path, server: int):
    p = Project(tmp_path / "emit.rlr")
    _start_attack(p, server, options={
        "concurrency": 1, "max_requests": 100, "timeout": 5.0,
        "grep": [r"^/\?q=[a-z]+$"],
    })
    findings = p.list_findings()
    # Both responses match the grep -> 2 hits, but dedupe key uses evidence
    # text which includes the seq number, so we expect two distinct rows.
    intruder_rows = [f for f in findings if f["source"] == "intruder"]
    assert intruder_rows, "expected at least one intruder-sourced finding"
    for row in intruder_rows:
        assert row["rule_id"] == "intruder:grep"
        assert row["severity"] == "medium"
        assert row["title"] == "Intruder grep match"
        assert row["url"].startswith(f"http://127.0.0.1:{server}/")


def test_no_grep_no_finding(tmp_path: Path, server: int):
    p = Project(tmp_path / "noemit.rlr")
    _start_attack(p, server, options={
        "concurrency": 1, "max_requests": 100, "timeout": 5.0,
        # No grep configured -> grep_matched is always False
    })
    intruder_rows = [f for f in p.list_findings() if f["source"] == "intruder"]
    assert intruder_rows == []


def test_emit_findings_disabled(tmp_path: Path, server: int):
    p = Project(tmp_path / "disabled.rlr")
    _start_attack(p, server, options={
        "concurrency": 1, "max_requests": 100, "timeout": 5.0,
        "grep": [r"^/\?q=[a-z]+$"],
        "emit_findings": False,
    })
    intruder_rows = [f for f in p.list_findings() if f["source"] == "intruder"]
    assert intruder_rows == []
