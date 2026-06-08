"""Phase 3 tests: passive scanner rules + finding dedupe."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from reqlore.scanner import BUILTIN_RULES, Finding, Scanner, run_passive
from reqlore.scanner.passive import RuleContext


@dataclass
class _Row:
    """Minimal stand-in for storage.HistoryRow that satisfies RuleContext."""
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _resp(status: int, headers: list[tuple[str, str]], body: bytes = b"") -> bytes:
    head = f"HTTP/1.1 {status} OK\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _req(method: str, url: str, headers: list[tuple[str, str]] = None,
         body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _row(*, url="https://x.test/", method="GET", status=200,
         req_headers=None, req_body=b"",
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host="x.test", url=url, method=method, status=status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


def test_missing_security_headers_html():
    findings = run_passive(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"<html></html>",
    ))
    titles = {f.title for f in findings}
    assert "Missing response header: Strict-Transport-Security" in titles
    assert "Missing response header: Content-Security-Policy" in titles
    assert "Missing response header: X-Content-Type-Options" in titles


def test_security_headers_quiet_for_non_html_4xx():
    """Non-HTML 4xx errors should not trigger 'missing CSP' noise."""
    findings = run_passive(_row(
        status=404,
        resp_headers=[("Content-Type", "image/png")],
        resp_body=b"\x89PNG",
    ))
    titles = {f.title for f in findings}
    assert "Missing response header: Content-Security-Policy" not in titles


def test_insecure_cookie_flags_each_missing_attribute():
    findings = run_passive(_row(
        resp_headers=[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "sid=abc123; Path=/"),
        ],
    ))
    cookie_findings = [f for f in findings if "Insecure cookie" in f.title]
    assert len(cookie_findings) == 1
    ev = cookie_findings[0].evidence
    assert "sid=" in ev
    # severity should be medium
    assert cookie_findings[0].severity == "medium"


def test_secure_cookie_does_not_alert():
    findings = run_passive(_row(
        resp_headers=[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
        ],
    ))
    assert not any("Insecure cookie" in f.title for f in findings)


def test_server_banner_only_when_version():
    findings_no_ver = run_passive(_row(
        resp_headers=[("Content-Type", "text/html"), ("Server", "nginx")],
    ))
    assert not any(f.title.startswith("Software version") for f in findings_no_ver)

    findings_with_ver = run_passive(_row(
        resp_headers=[("Content-Type", "text/html"), ("Server", "nginx/1.18.0")],
    ))
    assert any(f.title.startswith("Software version") for f in findings_with_ver)


def test_cors_wildcard_with_credentials_is_high():
    findings = run_passive(_row(
        resp_headers=[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    ))
    hits = [f for f in findings if "Dangerous CORS" in f.title]
    assert hits and hits[0].severity == "high"


def test_cors_reflected_origin_with_credentials():
    findings = run_passive(_row(
        req_headers=[("Origin", "https://evil.example")],
        resp_headers=[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "https://evil.example"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    ))
    hits = [f for f in findings if "Reflected Origin" in f.title]
    assert hits and hits[0].severity == "high"


def test_verbose_error_page():
    findings = run_passive(_row(
        status=500,
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"<html>Traceback (most recent call last):\n  File '/srv/app.py'</html>",
    ))
    hits = [f for f in findings if "Verbose error page" in f.title]
    assert hits


def test_directory_listing_alert():
    findings = run_passive(_row(
        url="https://x.test/files/",
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"<html><title>Index of /files</title></html>",
    ))
    assert any("Directory listing" in f.title for f in findings)


def test_sensitive_path_high():
    findings = run_passive(_row(url="https://x.test/.git/config"))
    hits = [f for f in findings if "Sensitive file accessible" in f.title]
    assert hits and hits[0].severity == "high"


def test_jwt_none_alg_in_response_body():
    # alg=none header: {"alg":"none","typ":"JWT"}
    tok = b"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9."
    findings = run_passive(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=b'{"token":"' + tok + b'"}',
    ))
    hits = [f for f in findings if f.title == "JWT with alg=none"]
    assert hits and hits[0].severity == "critical"


def test_basic_auth_over_http():
    findings = run_passive(_row(
        url="http://x.test/api",
        req_headers=[("Authorization", "Basic dXNlcjpwYXNz")],
        resp_headers=[("Content-Type", "text/html")],
    ))
    hits = [f for f in findings if "HTTP Basic Auth over plain HTTP" in f.title]
    assert hits and hits[0].severity == "high"


def test_open_redirect_hint():
    findings = run_passive(_row(
        url="https://x.test/r?u=https://evil.example/path",
        status=302,
        resp_headers=[("Location", "https://evil.example/path")],
    ))
    assert any("Possible open redirect" in f.title for f in findings)


def test_dedupe_key_stable():
    f = Finding(severity="low", title="x", host="h", url="u", evidence="e")
    assert f.dedupe_key == "x|h|u|e"


def test_finding_cvss_band_default():
    f = Finding(severity="high", title="t")
    assert f.cvss_score == 7.5
    f2 = Finding(severity="critical", title="t", cvss=9.9)
    assert f2.cvss_score == 9.9


def test_scanner_extra_rules_run():
    calls: list[str] = []

    def extra(ctx):
        calls.append(ctx.host)
        return []

    s = Scanner(rules=[], extra_rules=[extra])
    s.scan_history_row(_row())
    assert calls == ["x.test"]


def test_scanner_rule_failure_is_isolated():
    def bad(ctx):
        raise RuntimeError("boom")

    s = Scanner(rules=[bad])
    findings = s.scan_history_row(_row())
    assert any("Scanner rule raised" in f.title for f in findings)
