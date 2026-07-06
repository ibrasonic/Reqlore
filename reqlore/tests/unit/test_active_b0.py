"""B.0 active-scanner reliability tests: budgets, scope, retries, refresh, signatures."""
from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    ReflectedXSSCheck,
    SQLiErrorCheck,
    _detect_sql_engine,
    _host_in_scope,
    _replace_form_value,
)
from reqlore.storage import Project

# ----------------------------- shared helpers --------------------------------


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


def _row(*, url="https://x.test/?a=1&b=2", method="GET",
          req_headers=None, req_body=b"", resp_status=200, resp_body=b"hi"):
    return _Row(
        id=1, host="x.test", url=url, method=method, status=resp_status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(resp_status, [], resp_body),
    )


# ----------------------------- B.0.1 per-target budget -----------------------


def test_per_target_budget_caps_probes_per_param():
    """With 2 params and 2 checks, no single (rule, param) gets more than the cap."""
    seen: list[str] = []

    def responder(req: Request) -> Response:
        seen.append(req.url)
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    scanner = ActiveScanner(
        checks=[ReflectedXSSCheck(), SQLiErrorCheck()],
        sender=responder,
    )
    # Default max_probes_per_target = 4. Each (rule, location, key) gets at most 4.
    # 2 params x 2 rules x 4 = 8 probes max (no SSTI/baseline noise from other checks).
    findings = scanner.run_on_row(_row(url="https://x.test/?a=1&b=2"))
    assert len(seen) <= 2 * 2 * 4
    # Specifically: each (rule, "query", "a") combo fires at most once per call here
    # because SQLi/XSS each only probe each param once \u2014 so we expect exactly
    # 2 params x 2 rules = 4 probes when the budget is plenty.
    assert len(seen) == 4
    assert isinstance(findings, list)


def test_per_target_budget_respects_low_cap():
    counter: list[int] = []

    def responder(req: Request) -> Response:
        counter.append(1)
        return Response(status=200, headers=[], body=b"", engine="fake")

    opts = ActiveOptions(max_probes_per_target=1)
    scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
    scanner.run_on_row(_row(url="https://x.test/?a=1&b=2"), options=opts)
    # 2 params x 1-probe-per-target = 2 probes for the single XSS check.
    assert sum(counter) == 2


# ----------------------------- B.0.5 scope filter ----------------------------


def test_host_in_scope_helper_basic_rules():
    rules = [
        {"kind": "include", "pattern": "*.example.com", "target": "host", "enabled": True},
        {"kind": "exclude", "pattern": "admin.example.com", "target": "host", "enabled": True},
    ]
    assert _host_in_scope("api.example.com", rules)
    assert not _host_in_scope("admin.example.com", rules)   # explicit exclude
    assert not _host_in_scope("other.test", rules)          # not in any include
    assert _host_in_scope("anything", [])                    # empty rules \u2192 in-scope


def test_run_on_project_skips_out_of_scope_rows(tmp_path):
    """An out-of-scope row should be counted in skipped_out_of_scope, not scanned."""
    proj = Project(tmp_path / "scope.rlr")
    try:
        proj.add_scope("include", "good.test", "host")
        proj.add_history(host="good.test", method="GET",
                          url="https://good.test/?q=1", status=200,
                          duration_ms=1, engine="x",
                          raw_req=_req("GET", "https://good.test/?q=1"),
                          raw_resp=_resp(200, body=b"ok"))
        proj.add_history(host="bad.test", method="GET",
                          url="https://bad.test/?q=1", status=200,
                          duration_ms=1, engine="x",
                          raw_req=_req("GET", "https://bad.test/?q=1"),
                          raw_resp=_resp(200, body=b"ok"))

        def responder(req: Request) -> Response:
            return Response(status=200, headers=[], body=b"", engine="fake")

        scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
        result = scanner.run_on_project(proj, options=ActiveOptions())
        assert result.skipped_out_of_scope == 1
        assert result.rows_scanned == 1
    finally:
        proj.close()


# ----------------------------- B.0.4 rate-limit awareness --------------------


def test_retry_after_429_is_respected_and_request_retried():
    calls: list[float] = []
    statuses_to_return = iter([429, 200])

    def responder(req: Request) -> Response:
        calls.append(time.monotonic())
        status = next(statuses_to_return, 200)
        headers = [("Retry-After", "1")] if status == 429 else []
        return Response(status=status, headers=headers, body=b"", engine="fake")

    # Mark every visited row as in-scope (default), use the project runner path
    # to see throttled_count incremented.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        proj = Project(__import__("pathlib").Path(td) / "rl.rlr")
        try:
            proj.add_history(host="x.test", method="GET",
                              url="https://x.test/?a=1", status=200,
                              duration_ms=1, engine="x",
                              raw_req=_req("GET", "https://x.test/?a=1"),
                              raw_resp=_resp(200, body=b"hi"))
            scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
            t0 = time.monotonic()
            result = scanner.run_on_project(
                proj, options=ActiveOptions(retry_after_default_s=0.1),
            )
            elapsed = time.monotonic() - t0
            assert result.throttled_count >= 1
            # Slept ~1 second between the two calls.
            assert (calls[1] - calls[0]) >= 0.9
            assert elapsed >= 0.9
        finally:
            proj.close()


# ----------------------------- B.0.3 replay macro ----------------------------


def test_replay_macro_merges_new_cookie_into_followups(tmp_path):
    """When opts.replay_macro is set, refreshed headers are merged into later probes."""
    proj = Project(tmp_path / "macro.rlr")
    try:
        proj.add_history(host="x.test", method="GET",
                          url="https://x.test/?a=1&b=2", status=200,
                          duration_ms=1, engine="x",
                          raw_req=_req("GET", "https://x.test/?a=1&b=2"),
                          raw_resp=_resp(200, body=b"ok"))

        recorded_cookies: list[str] = []

        def responder(req: Request) -> Response:
            cookie = ""
            for k, v in req.headers:
                if k.lower() == "cookie":
                    cookie = v
            recorded_cookies.append(cookie)
            return Response(status=200, headers=[], body=b"", engine="fake")

        refreshes: list[int] = []

        def macro(project) -> dict[str, str]:
            refreshes.append(1)
            return {"Cookie": f"session=refreshed-{len(refreshes)}"}

        opts = ActiveOptions(
            replay_macro=macro,
            replay_every_n_probes=1,
        )
        scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
        scanner.run_on_project(proj, options=opts)
        # First call: no refresh (counter=0). Subsequent calls: macro merged in.
        assert recorded_cookies[0] == ""
        assert any("refreshed-" in c for c in recorded_cookies[1:])
        assert len(refreshes) >= 1
    finally:
        proj.close()


# ----------------------------- B.0.8 SQLi engine signatures ------------------


@pytest.mark.parametrize("engine,sample_body", [
    ("mysql",    b"You have an error in your SQL syntax; check the manual"),
    ("mariadb",  b"check the manual that corresponds to your MariaDB"),
    ("postgres", b"org.postgresql.util.PSQLException: ERROR"),
    ("mssql",    b"Unclosed quotation mark after the character string"),
    ("oracle",   b"ORA-00933: SQL command not properly ended"),
    ("sqlite",   b"sqlite3.OperationalError: near \"foo\""),
    ("db2",      b"DB2 SQL error: SQLCODE=-204"),
    ("mongo",    b"MongoError: bad query"),
    ("snowflake", b"Snowflake.Data.Client.SnowflakeDbException: bad SQL"),
])
def test_each_sql_engine_signature_is_detected(engine, sample_body):
    hit = _detect_sql_engine(sample_body)
    assert hit is not None
    assert hit[0] == engine


def test_sqli_check_records_engine_in_finding_title():
    def responder(req: Request) -> Response:
        return Response(
            status=500, headers=[],
            body=b"PG::SyntaxError: at or near \"'\"",
            engine="fake",
        )

    scanner = ActiveScanner(checks=[SQLiErrorCheck()], sender=responder)
    findings = scanner.run_on_row(_row(url="https://x.test/?q=42"))
    assert any("postgres" in f.title.lower() for f in findings)


# ----------------------------- B.0.7 form re-encode --------------------------


def test_replace_form_value_preserves_other_chunks():
    # Original body uses %20 for spaces and a percent-encoded ampersand value.
    body = b"name=alice%20smith&data=a%26b&other=42"
    out = _replace_form_value(body, "other", "X")
    # Only the `other` chunk is rewritten; the rest is byte-for-byte preserved.
    assert out == b"name=alice%20smith&data=a%26b&other=X"


def test_replace_form_value_appends_missing_key():
    body = b"x=1"
    out = _replace_form_value(body, "y", "2")
    assert out == b"x=1&y=2"


def test_replace_form_value_url_encodes_new_value():
    body = b"x=1"
    out = _replace_form_value(body, "x", "a b&c")
    # Space + ampersand are percent-encoded; original `x=1` chunk is replaced.
    assert out == b"x=a%20b%26c"
