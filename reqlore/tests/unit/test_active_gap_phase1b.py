"""Phase 1b tests: HTTPSmugglingCheck, GraphQLActiveCheck, and the
sequencer auto-feed pass on Scanner.scan_project."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner, Scanner
from reqlore.scanner.active import (
    GraphQLActiveCheck,
    HTTPSmugglingCheck,
)
from reqlore.storage import Project

# --------------------------- shared row helpers ------------------------------


@dataclass
class _Row:
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _req(method: str, url: str, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


def _row(*, url="https://x.test/?a=1", host="x.test", method="GET",
          req_headers=None, req_body=b"",
          resp_status=200, resp_headers=None, resp_body=b"hi"):
    return _Row(
        id=1, host=host, url=url, method=method, status=resp_status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(resp_status, resp_headers or [], resp_body),
    )


def _scan_one(check, row, *, sender, opts=None) -> list:
    scanner = ActiveScanner(checks=[check], sender=sender)
    # Naming the check explicitly bypasses the intensity gate —
    # these tests intentionally exercise intrusive-tier checks one
    # at a time.
    base = opts or ActiveOptions()
    base.enabled_checks = base.enabled_checks or [check.name]
    return scanner.run_on_row(row, options=base)


# ============================ HTTPSmugglingCheck =============================


def test_smuggling_check_off_by_default():
    """Without ``allow_smuggling_probes`` the check must be a complete
    no-op — it must not even reach the raw_engine."""
    called: list = []

    def fail_send(req: Request) -> Response:
        called.append(req)
        raise AssertionError("send should not run when smuggling disabled")

    findings = _scan_one(
        HTTPSmugglingCheck(),
        _row(url="https://x.test/"),
        sender=fail_send,
    )
    assert findings == []
    assert called == []


def test_smuggling_check_fires_on_timing_threshold(monkeypatch):
    """When opt-in and the raw timing exceeds threshold, fire critical."""
    from reqlore import smuggling as smug

    def fake_detect(url, technique, *, sender, pause_ms_threshold):
        if technique == "cl.te":
            return smug.SmugglingTest(
                technique="cl.te", baseline_ms=80, probe_ms=2200,
                delta_ms=2120, likely_vulnerable=True,
                reason="probe took 2200 ms vs baseline 80 ms",
            )
        return smug.SmugglingTest(
            technique=technique, baseline_ms=0, probe_ms=0,
            delta_ms=0, likely_vulnerable=False, reason="not run",
        )

    monkeypatch.setattr(smug, "detect", fake_detect)

    def passthrough(req: Request) -> Response:
        # Should not be hit because the smuggling check uses raw_engine
        # via smug.detect, which we've replaced.
        return Response(status=200, headers=[], body=b"", engine="fake")

    opts = ActiveOptions(allow_smuggling_probes=True)
    findings = _scan_one(
        HTTPSmugglingCheck(),
        _row(url="https://victim.test/api"),
        sender=passthrough, opts=opts,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert "CL.TE" in f.title
    assert "2200" in f.evidence


def test_smuggling_check_quiet_when_no_technique_triggers(monkeypatch):
    from reqlore import smuggling as smug

    def fake_detect(url, technique, *, sender, pause_ms_threshold):
        return smug.SmugglingTest(
            technique=technique, baseline_ms=70, probe_ms=80,
            delta_ms=10, likely_vulnerable=False,
            reason="probe took 80 ms vs baseline 70 ms (delta 10)",
        )

    monkeypatch.setattr(smug, "detect", fake_detect)

    def passthrough(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"", engine="fake")

    opts = ActiveOptions(allow_smuggling_probes=True)
    findings = _scan_one(
        HTTPSmugglingCheck(),
        _row(url="https://victim.test/api"),
        sender=passthrough, opts=opts,
    )
    assert findings == []


# ============================ GraphQLActiveCheck =============================


def test_graphql_active_skips_non_graphql_urls():

    def responder(req: Request) -> Response:
        raise AssertionError("should not be called for /api/users")

    findings = _scan_one(
        GraphQLActiveCheck(),
        _row(url="https://x.test/api/users"),
        sender=responder,
    )
    assert findings == []


def test_graphql_active_fires_batching_when_array_response():

    def responder(req: Request) -> Response:
        body = req.body or b""
        if body.startswith(b"["):
            # Length-3 array of GraphQL results
            return Response(
                status=200,
                headers=[("Content-Type", "application/json")],
                body=(b'[{"data":{"__typename":"Query"}},'
                       b'{"data":{"__typename":"Query"}},'
                       b'{"data":{"__typename":"Query"}}]'),
                engine="fake",
            )
        return Response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=b'{"data":{"__typename":"Query"}}', engine="fake",
        )

    findings = _scan_one(
        GraphQLActiveCheck(),
        _row(url="https://api.test/graphql"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("batching" in t.lower() for t in titles), titles


def test_graphql_active_fires_field_suggestion_on_did_you_mean():

    def responder(req: Request) -> Response:
        body = req.body or b""
        if b"__schemaa" in body:
            return Response(
                status=400,
                headers=[("Content-Type", "application/json")],
                body=(b'{"errors":[{"message":"Cannot query field '
                       b'\\"__schemaa\\". Did you mean \\"__schema\\"?"}]}'),
                engine="fake",
            )
        # Batching probe — return a single object so batching does not fire.
        return Response(
            status=200, headers=[],
            body=b'{"data":{"__typename":"Query"}}', engine="fake",
        )

    findings = _scan_one(
        GraphQLActiveCheck(),
        _row(url="https://api.test/graphql"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("field-suggestion" in t.lower() for t in titles), titles


def test_graphql_active_quiet_when_endpoint_hardened():

    def responder(req: Request) -> Response:
        return Response(
            status=400,
            headers=[("Content-Type", "application/json")],
            body=b'{"errors":[{"message":"Bad Request"}]}', engine="fake",
        )

    findings = _scan_one(
        GraphQLActiveCheck(),
        _row(url="https://api.test/graphql"),
        sender=responder,
    )
    assert findings == []


# ====================== Sequencer auto-feed (item #16) =======================


@pytest.fixture
def project(tmp_path: Path):
    proj = Project(tmp_path / "seq.rlr")
    yield proj
    proj.close()


def _seed_set_cookie_history(proj, host: str, token_values: list[str],
                                 cookie_name: str = "session_id") -> None:
    for i, val in enumerate(token_values):
        head = (b"HTTP/1.1 200 OK\r\n"
                 + f"Set-Cookie: {cookie_name}={val}; Path=/; HttpOnly\r\n".encode()
                 + b"Content-Type: text/html\r\n\r\n")
        body = b"<html></html>"
        proj.add_history(
            host=host, method="GET", url=f"https://{host}/p{i}",
            status=200, duration_ms=5, engine="httpx",
            raw_req=b"GET / HTTP/1.1\r\n\r\n", raw_resp=head + body,
        )


def test_sequencer_pass_fires_on_low_entropy_counter_tokens(project):
    """Counter-style tokens that increment by one byte per row must be
    rated weak by the Sequencer's statistical analyser."""
    weak_tokens = [f"abc{i:05d}" for i in range(12)]  # only the last 5 chars vary
    _seed_set_cookie_history(project, "weak.test", weak_tokens)

    Scanner().scan_project(project)
    findings = project.list_findings()
    titles = [f["title"] if isinstance(f, dict) else f.title for f in findings]
    assert any("weak session token" in t.lower() for t in titles), titles


def test_sequencer_pass_quiet_below_min_samples(project):
    """With < 8 distinct samples the analyser must not fire — and a
    rule_runs row with the right reason should be recorded."""
    _seed_set_cookie_history(project, "tiny.test",
                              ["a1", "a2", "a3"])  # only 3 samples

    Scanner().scan_project(project)
    findings = project.list_findings()
    titles = [f["title"] if isinstance(f, dict) else f.title for f in findings]
    assert not any("weak session token" in t.lower() for t in titles), titles
    reasons = project.rule_run_reasons(rule_id="passive:weak-session-entropy")
    assert any("only_3_samples" in r["reason"] for r in reasons), reasons


def test_sequencer_pass_quiet_on_high_entropy_tokens(project):
    """Tokens that look like CSPRNG output should not fire."""
    import secrets
    strong_tokens = [secrets.token_urlsafe(32) for _ in range(12)]
    _seed_set_cookie_history(project, "strong.test", strong_tokens)

    Scanner().scan_project(project)
    findings = project.list_findings()
    titles = [f["title"] if isinstance(f, dict) else f.title for f in findings]
    assert not any("weak session token" in t.lower() for t in titles), titles


def test_sequencer_pass_skips_non_session_cookies(project):
    """A 50-sample low-entropy 'pixel_id' cookie must NOT be treated as
    a session token — flagging tracking IDs is noise."""
    boring = [f"px{i:04d}" for i in range(20)]
    _seed_set_cookie_history(project, "tracker.test", boring,
                                cookie_name="pixel_id")

    Scanner().scan_project(project)
    findings = project.list_findings()
    titles = [f["title"] if isinstance(f, dict) else f.title for f in findings]
    assert not any("weak session token" in t.lower() for t in titles), titles
