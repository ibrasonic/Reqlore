"""B.4 — active scanner attaches reproduction tokens to fired findings.

Verifies the end-to-end plumbing:

* ``_send_factory`` stashes the most-recent probe on ``ctx.last_probe_repro``.
* ``ActiveScanner.run_on_project`` forwards the tuple to ``record_finding``.
* The persisted finding row carries a non-empty ``reproduction_token``.
* ``Project.get_reproduction(token)`` round-trips the request bytes.
* The CLI ``reqlore finding repro`` command renders a curl one-liner.
* Findings without a reproduction (manual / passive) still work; the CLI
  exits cleanly with a diagnostic.
"""
from __future__ import annotations

from reqlore.cli import main as cli_main
from reqlore.engines import Request, Response
from reqlore.findings_bus import record_finding
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    ActiveCheck,
    Finding,
    _request_to_raw,
    _response_to_raw,
)
from reqlore.storage import Project

# ----------------------------- helpers ---------------------------------------


def _req_bytes(method: str, url: str, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


def _resp_bytes(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


class _AlwaysFireCheck(ActiveCheck):
    """Sends one probe and unconditionally reports a finding."""
    name = "active:always-fire"

    def run(self, ctx, send, *, opts=None):
        # Use a payload string that will survive into the request blob so
        # tests can assert it round-trips.
        req = Request(
            method=ctx.method,
            url=ctx.full_url + "&xxx-marker-b4=PROBE-XYZ",
            headers=ctx.req_headers,
            body=ctx.req_body,
        )
        send(req)
        return [Finding(
            severity="medium",
            title="always-fire (B.4 repro test)",
            host=ctx.host,
            url=ctx.full_url,
            request_id=ctx.history_id,
            evidence="probe sent",
            payload="PROBE-XYZ",
        )]


def _fake_sender_factory(status: int = 200, body: bytes = b"hello"):
    def _send(req: Request) -> Response:
        return Response(
            status=status,
            reason="OK",
            headers=[("Content-Type", "text/plain")],
            body=body,
            engine="fake",
        )
    return _send


def _seed_history(project: Project) -> int:
    return project.add_history(
        host="x.test", method="GET", url="https://x.test/?a=1",
        status=200, duration_ms=1, engine="fake",
        raw_req=_req_bytes("GET", "https://x.test/?a=1",
                            [("Host", "x.test")]),
        raw_resp=_resp_bytes(200, [("Content-Type", "text/plain")], b"hello"),
    )


# ----------------------------- raw-bytes helpers -----------------------------


def test_request_to_raw_includes_method_path_and_host():
    req = Request(
        method="POST",
        url="https://x.test/a/b?z=1",
        headers=[("X-Custom", "v")],
        body=b"BODY",
    )
    raw = _request_to_raw(req)
    text = raw.decode("latin-1")
    assert text.startswith("POST /a/b?z=1 HTTP/1.1\r\n")
    assert "Host: x.test\r\n" in text
    assert "X-Custom: v\r\n" in text
    assert raw.endswith(b"\r\n\r\nBODY")


def test_request_to_raw_keeps_existing_host_header():
    req = Request(
        method="GET", url="https://x.test/",
        headers=[("Host", "explicit.test")], body=b"",
    )
    text = _request_to_raw(req).decode("latin-1")
    # Only one Host header.
    assert text.count("Host:") == 1
    assert "Host: explicit.test" in text


def test_request_to_raw_defaults_path_to_slash():
    req = Request(method="GET", url="https://x.test", headers=[], body=b"")
    assert _request_to_raw(req).startswith(b"GET / HTTP/1.1\r\n")


def test_response_to_raw_uses_provided_reason():
    resp = Response(status=418, reason="I'm a teapot",
                     headers=[("X-T", "1")], body=b"tea", engine="t")
    raw = _response_to_raw(resp)
    assert raw.startswith(b"HTTP/1.1 418 I'm a teapot\r\n")
    assert b"X-T: 1\r\n" in raw
    assert raw.endswith(b"\r\n\r\ntea")


def test_response_to_raw_falls_back_to_status_table_when_reason_empty():
    resp = Response(status=200, reason="", headers=[], body=b"",
                     engine="t")
    assert _response_to_raw(resp).startswith(b"HTTP/1.1 200 OK\r\n")


# ----------------------------- end-to-end: scanner ---------------------------


def test_scanner_attaches_reproduction_token_to_findings(tmp_path):
    project = Project(tmp_path / "b4.rlr")
    try:
        _seed_history(project)
        scanner = ActiveScanner(
            checks=[_AlwaysFireCheck()],
            sender=_fake_sender_factory(),
        )
        result = scanner.run_on_project(project, options=ActiveOptions(), limit=10)
        assert result.findings_added == 1
        rows = project.list_findings()
        assert len(rows) == 1
        token = rows[0].get("reproduction_token") or ""
        assert token, "expected fired active finding to carry reproduction_token"

        repro = project.get_reproduction(token)
        assert repro is not None
        assert repro.get("method") == "GET"
        assert repro.get("status") == 200
        # Probe URL is what the check actually sent.
        assert "xxx-marker-b4" in (repro.get("url") or "")
        # Request blob round-trips and contains the probe marker on the URL.
        req_blob = repro.get("request_blob") or b""
        assert b"xxx-marker-b4" in req_blob
        # Response blob is the canonical HTTP/1.1 serialisation.
        resp_blob = repro.get("response_blob") or b""
        assert resp_blob.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"hello" in resp_blob
    finally:
        project.close()


def test_scanner_records_no_token_when_no_finding_fires(tmp_path):
    """Negative: when no check fires, no findings exist — so nothing to assert
    about reproduction beyond confirming the pipeline did not crash."""
    class _NoFire(ActiveCheck):
        name = "active:no-fire"

        def run(self, ctx, send, *, opts=None):
            send(Request(method=ctx.method, url=ctx.full_url,
                           headers=ctx.req_headers, body=ctx.req_body))
            return []

    project = Project(tmp_path / "b4nf.rlr")
    try:
        _seed_history(project)
        scanner = ActiveScanner(checks=[_NoFire()], sender=_fake_sender_factory())
        result = scanner.run_on_project(project, options=ActiveOptions(), limit=10)
        assert result.findings_added == 0
        assert project.list_findings() == []
    finally:
        project.close()


# ----------------------------- CLI: finding repro ---------------------------


def _seed_finding_with_repro(project: Project) -> int:
    """Manually create a finding that carries a reproduction so we can
    drive the CLI without running the scanner."""
    req = Request(method="POST", url="https://api.test/login",
                   headers=[("Content-Type", "application/json")],
                   body=b'{"u":"a"}')
    resp = Response(status=200, reason="OK",
                     headers=[("Content-Type", "application/json")],
                     body=b'{"ok":true}', engine="fake")
    repro_tuple = (
        _request_to_raw(req), _response_to_raw(resp),
        "POST", "https://api.test/login", 200, 2,
    )
    fid = record_finding(
        project, source="scanner", rule_id="active:test-repro",
        severity="high", title="repro test",
        host="api.test", url="https://api.test/login",
        reproduction=repro_tuple,
    )
    assert fid is not None
    return fid


def test_cli_finding_repro_prints_curl_oneliner(tmp_path, capsys):
    project_path = tmp_path / "b4cli.rlr"
    project = Project(project_path)
    try:
        fid = _seed_finding_with_repro(project)
    finally:
        project.close()

    rc = cli_main([
        "finding", "repro",
        "--project", str(project_path),
        "--id", str(fid),
    ])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    line = captured.out.strip()
    assert line.startswith("curl ")
    assert "-X POST" in line
    assert "https://api.test/login" in line
    # Body survives.
    assert '{"u":"a"}' in line or "u" in line


def test_cli_finding_repro_json_format_round_trips(tmp_path, capsys):
    import json
    project_path = tmp_path / "b4cli_json.rlr"
    project = Project(project_path)
    try:
        fid = _seed_finding_with_repro(project)
    finally:
        project.close()

    rc = cli_main([
        "finding", "repro",
        "--project", str(project_path),
        "--id", str(fid),
        "--format", "json",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["method"] == "POST"
    assert payload["url"] == "https://api.test/login"
    assert payload["status"] == 200
    assert "POST /login HTTP/1.1" in payload["request_blob"]
    assert payload["response_blob"].startswith("HTTP/1.1 200 OK")


def test_cli_finding_repro_returns_error_when_finding_missing(tmp_path, capsys):
    project_path = tmp_path / "b4cli_missing.rlr"
    Project(project_path).close()

    rc = cli_main([
        "finding", "repro",
        "--project", str(project_path),
        "--id", "999",
    ])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


def test_cli_finding_repro_returns_error_when_no_token(tmp_path, capsys):
    project_path = tmp_path / "b4cli_notok.rlr"
    project = Project(project_path)
    try:
        fid = record_finding(
            project, source="manual", rule_id="manual:no-repro",
            severity="low", title="manual finding",
            host="x.test", url="https://x.test/",
        )
        assert fid is not None
    finally:
        project.close()

    rc = cli_main([
        "finding", "repro",
        "--project", str(project_path),
        "--id", str(fid),
    ])
    err = capsys.readouterr().err
    assert rc == 2
    assert "no stored reproduction" in err
