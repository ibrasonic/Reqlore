"""Phase 4 — Active scanner tests using a fake sender."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    GraphQLIntrospectionCheck,
    JWTAlgNoneAcceptanceCheck,
    OpenRedirectCheck,
    PrototypePollutionCheck,
    ReflectedXSSCheck,
    SQLiErrorCheck,
    SSTICheck,
)


@dataclass
class _Row:
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _req(method: str, url: str, headers: list[tuple[str, str]] | None = None,
         body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _resp(status: int, headers: list[tuple[str, str]] | None = None,
          body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


def _row(url="https://x.test/?q=hi", method="GET", status=200,
         req_headers=None, req_body=b"",
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host="x.test", url=url, method=method, status=status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


def _make_sender(responder):
    """Wrap a function `(req) -> Response` into the format the scanner expects."""
    return responder


def test_reflected_xss_detects_unescaped_marker():
    import urllib.parse as up

    def responder(req: Request) -> Response:
        # Real-world server would URL-decode the query value before reflecting it.
        q = up.parse_qs(up.urlparse(req.url).query)
        body = b"<html>" + (q.get("q", [""])[0]).encode() + b"</html>"
        return Response(status=200, headers=[("Content-Type", "text/html")],
                         body=body, engine="fake")

    scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
    findings = scanner.run_on_row(_row())
    assert any("Reflected XSS" in f.title for f in findings)


def test_reflected_xss_negative_when_escaped():
    import urllib.parse as up

    def responder(req: Request) -> Response:
        q = up.parse_qs(up.urlparse(req.url).query)
        val = (q.get("q", [""])[0]).replace("wbr-", "wbr_X_")
        body = b"<html>" + val.encode() + b"</html>"
        return Response(status=200, headers=[("Content-Type", "text/html")],
                         body=body, engine="fake")

    scanner = ActiveScanner(checks=[ReflectedXSSCheck()], sender=responder)
    findings = scanner.run_on_row(_row())
    assert not any("Reflected XSS" in f.title for f in findings)


def test_sqli_error_signature():
    def responder(req: Request) -> Response:
        # Pretend the server explodes on quote injection.
        body = b"<html>You have an error in your SQL syntax near '''</html>"
        return Response(status=500, headers=[], body=body, engine="fake")

    scanner = ActiveScanner(checks=[SQLiErrorCheck()], sender=responder)
    findings = scanner.run_on_row(_row())
    assert any(f.cwe == "CWE-89" for f in findings)


def test_ssti_finds_evaluated_arithmetic():
    def responder(req: Request) -> Response:
        # If the request URL contains "{{7*7}}", reply with "answer: 49"
        body = b"answer: 49" if "%7B%7B7" in req.url or "{{7*7}}" in req.url else b"hi"
        return Response(status=200, headers=[("Content-Type", "text/html")],
                         body=body, engine="fake")

    scanner = ActiveScanner(checks=[SSTICheck()], sender=responder)
    findings = scanner.run_on_row(_row())
    assert any("SSTI" in f.title for f in findings)


def test_open_redirect_active():
    def responder(req: Request) -> Response:
        # Whatever ?next= says, echo into Location.
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query)
        loc = q.get("next", [""])[0]
        return Response(status=302, headers=[("Location", loc)],
                         body=b"", engine="fake")

    scanner = ActiveScanner(checks=[OpenRedirectCheck()], sender=responder)
    findings = scanner.run_on_row(_row(url="https://x.test/r?next=https://orig.example/"))
    assert any("Open redirect" in f.title for f in findings)


def test_jwt_alg_none_accepted():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."  # alg HS256
           "eyJzdWIiOiJhbGljZSJ9.signature")
    row = _row(req_headers=[("Authorization", f"Bearer {tok}")])
    scanner = ActiveScanner(checks=[JWTAlgNoneAcceptanceCheck()], sender=responder)
    findings = scanner.run_on_row(row)
    assert any("alg=none" in f.title for f in findings)


def test_prototype_pollution_marker_reflected():
    def responder(req: Request) -> Response:
        # Pretend the server merges __proto__ and echoes the merged blob.
        return Response(status=200, headers=[("Content-Type", "application/json")],
                         body=req.body, engine="fake")

    row = _row(method="POST", url="https://x.test/api",
                req_headers=[("Content-Type", "application/json")],
                req_body=b'{"name":"a"}')
    scanner = ActiveScanner(checks=[PrototypePollutionCheck()], sender=responder)
    findings = scanner.run_on_row(row)
    assert any("prototype pollution" in f.title.lower() for f in findings)


def test_graphql_introspection_check_triggers_on_graphql_url():
    def responder(req: Request) -> Response:
        body = b'{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
        return Response(status=200, headers=[("Content-Type", "application/json")],
                         body=body, engine="fake")

    row = _row(url="https://x.test/graphql", method="POST",
                req_headers=[("Content-Type", "application/json")])
    scanner = ActiveScanner(checks=[GraphQLIntrospectionCheck()], sender=responder)
    findings = scanner.run_on_row(row)
    assert any("introspection" in f.title.lower() for f in findings)


def test_active_options_filter_checks():
    """Disabling all checks should produce zero findings even on a vulnerable target."""
    def responder(req: Request) -> Response:
        body = req.url.encode()
        return Response(status=200, headers=[], body=body, engine="fake")

    scanner = ActiveScanner(sender=responder)
    findings = scanner.run_on_row(
        _row(), options=ActiveOptions(enabled_checks=["does-not-exist"]),
    )
    assert findings == []
