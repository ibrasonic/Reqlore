"""B.2 active-check tests: header XSS, LFI, NoSQLi, XXE, active CORS."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    BUILTIN_ACTIVE_CHECKS,
    ActiveCORSCheck,
    NoSQLInjectionCheck,
    PathTraversalCheck,
    ReflectedHeaderXSSCheck,
    XXEClassicCheck,
    _cookie_pairs,
    _mutated_cookie,
    _replace_cookie_value,
    _replace_header_value,
)

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
    return scanner.run_on_row(row, options=opts or ActiveOptions())


# ----------------------------- helper unit tests -----------------------------


def test_replace_header_value_swaps_existing_case_insensitive():
    out = _replace_header_value(
        [("Host", "x"), ("User-Agent", "old"), ("X-Foo", "y")],
        "user-agent", "new",
    )
    assert ("User-Agent", "new") in out
    assert ("Host", "x") in out
    assert ("X-Foo", "y") in out
    assert len(out) == 3


def test_replace_header_value_appends_if_missing():
    out = _replace_header_value([("A", "1")], "X-Custom", "v")
    assert out == [("A", "1"), ("X-Custom", "v")]


def test_cookie_pairs_parses_semicolon_list():
    pairs = _cookie_pairs([("Cookie", "a=1; b=2; flagonly; c=3")])
    assert pairs == [("a", "1"), ("b", "2"), ("flagonly", ""), ("c", "3")]


def test_cookie_pairs_returns_empty_when_no_cookie_header():
    assert _cookie_pairs([("X", "y")]) == []


def test_replace_cookie_value_only_swaps_named_value():
    out = _replace_cookie_value("a=1; b=2; c=3", "b", "ZZZ")
    assert "a=1" in out and "b=ZZZ" in out and "c=3" in out


# ----------------------------- ReflectedHeaderXSSCheck -----------------------


def test_reflected_header_xss_fires_when_user_agent_echoed():
    captured: list[Request] = []

    def responder(req: Request) -> Response:
        captured.append(req)
        ua = ""
        for k, v in req.headers:
            if k.lower() == "user-agent":
                ua = v
                break
        return Response(status=200, headers=[],
                         body=f"Hello {ua}".encode(), engine="fake")

    findings = _scan_one(
        ReflectedHeaderXSSCheck(),
        _row(req_headers=[("User-Agent", "Mozilla")]),
        sender=responder,
    )
    titles = [f.title for f in findings]
    # Probe sent; UA reflected -> finding
    assert any("Reflected XSS via request header" in t for t in titles)
    # User-Agent was actually mutated
    assert any(
        any(k.lower() == "user-agent" and "<wbr-" in v for k, v in r.headers)
        for r in captured
    )


def test_reflected_header_xss_quiet_when_not_reflected():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"nothing here", engine="fake")

    findings = _scan_one(
        ReflectedHeaderXSSCheck(),
        _row(req_headers=[("User-Agent", "x")]),
        sender=responder,
    )
    assert findings == []


def test_reflected_header_xss_flags_cookie_value():
    def responder(req: Request) -> Response:
        cookie = ""
        for k, v in req.headers:
            if k.lower() == "cookie":
                cookie = v
                break
        # echo only the sid value
        body = b""
        for piece in cookie.split(";"):
            piece = piece.strip()
            if piece.startswith("sid="):
                body = piece.split("=", 1)[1].encode()
                break
        return Response(status=200, headers=[], body=body, engine="fake")

    findings = _scan_one(
        ReflectedHeaderXSSCheck(),
        _row(req_headers=[("Cookie", "sid=abc; csrf=def")]),
        sender=responder,
    )
    assert any("cookie" in f.title.lower() for f in findings)


def test_reflected_header_xss_quiet_when_no_target_headers_present():
    """With no UA/Referer/X-FF/Cookie at all there's still budget for the 3 headers."""
    sent: list[Request] = []

    def responder(req: Request) -> Response:
        sent.append(req)
        return Response(status=200, headers=[], body=b"clean", engine="fake")

    findings = _scan_one(
        ReflectedHeaderXSSCheck(),
        _row(req_headers=[]),
        sender=responder,
    )
    # Three header probes (UA, Referer, XFF) but no cookie probes.
    assert len(sent) == 3
    assert findings == []


# ----------------------------- PathTraversalCheck ----------------------------


def test_path_traversal_unix_passwd_marker_found():
    def responder(req: Request) -> Response:
        u = req.url.lower()
        if "etc/passwd" in u or "etc%2fpasswd" in u:
            return Response(status=200, headers=[],
                             body=b"root:x:0:0:root:/root:/bin/bash\n",
                             engine="fake")
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    row = _row(url="https://x.test/?file=/var/log/app.log")
    findings = _scan_one(PathTraversalCheck(), row, sender=responder)
    assert findings, "expected an LFI finding"
    assert "unix" in findings[0].title.lower()
    assert findings[0].cwe == "CWE-22"


def test_path_traversal_quiet_when_param_not_path_shaped():
    sent: list[Request] = []

    def responder(req: Request) -> Response:
        sent.append(req)
        return Response(status=200, headers=[],
                         body=b"root:x:0:0:NOISE", engine="fake")

    row = _row(url="https://x.test/?q=hello")
    findings = _scan_one(PathTraversalCheck(), row, sender=responder)
    assert findings == []
    # No probes attempted because the value doesn't look path-shaped.
    assert sent == []


def test_path_traversal_quiet_when_baseline_already_contains_marker():
    """Avoid FP: marker present in the original recorded response."""
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"root:x:0:0:GENUINELY_THERE", engine="fake")

    row = _row(
        url="https://x.test/?file=/var/log/app.log",
        resp_body=b"root:x:0:0:GENUINELY_THERE",
    )
    findings = _scan_one(PathTraversalCheck(), row, sender=responder)
    assert findings == []


def test_path_traversal_windows_ini_marker_found():
    def responder(req: Request) -> Response:
        if "win.ini" in req.url.lower():
            return Response(status=200, headers=[],
                             body=b"; for 16-bit\r\n[fonts]\r\n",
                             engine="fake")
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    row = _row(url="https://x.test/?path=C:\\Users\\foo.txt")
    findings = _scan_one(PathTraversalCheck(), row, sender=responder)
    assert findings
    assert "windows" in findings[0].title.lower()


# ----------------------------- NoSQLInjectionCheck ---------------------------


def test_nosqli_mongo_fires_on_size_growth():
    """Baseline returns small body; $ne probe returns ≥ 2x body length."""
    state = {"call": 0}

    def responder(req: Request) -> Response:
        state["call"] += 1
        # call 1 = baseline; subsequent = $ne probes
        if state["call"] == 1:
            return Response(status=200, headers=[], body=b"x" * 10, engine="fake")
        return Response(status=200, headers=[], body=b"x" * 200, engine="fake")

    row = _row(
        method="POST", url="https://x.test/api/find",
        req_headers=[("Content-Type", "application/json")],
        req_body=b'{"username": "alice"}',
    )
    findings = _scan_one(NoSQLInjectionCheck(), row, sender=responder)
    assert findings
    assert findings[0].cwe == "CWE-943"


def test_nosqli_mongo_fires_on_status_flip():
    """Baseline 401; probe 200 -> auth bypass-shaped flip."""
    state = {"call": 0}

    def responder(req: Request) -> Response:
        state["call"] += 1
        if state["call"] == 1:
            return Response(status=401, headers=[], body=b"unauthorized",
                             engine="fake")
        return Response(status=200, headers=[], body=b"welcome",
                         engine="fake")

    row = _row(
        method="POST", url="https://x.test/api/login",
        req_headers=[("Content-Type", "application/json")],
        req_body=b'{"username": "alice"}',
    )
    findings = _scan_one(NoSQLInjectionCheck(), row, sender=responder)
    assert findings
    assert "status_flip" in (findings[0].evidence or "")


def test_nosqli_mongo_quiet_when_responses_equivalent():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"same", engine="fake")

    row = _row(
        method="POST", url="https://x.test/api/find",
        req_headers=[("Content-Type", "application/json")],
        req_body=b'{"username": "alice"}',
    )
    findings = _scan_one(NoSQLInjectionCheck(), row, sender=responder)
    assert findings == []


def test_nosqli_mongo_skips_non_json_body():
    sent: list[Request] = []

    def responder(req: Request) -> Response:
        sent.append(req)
        return Response(status=200, headers=[], body=b"x" * 999, engine="fake")

    row = _row(
        method="POST", url="https://x.test/api",
        req_headers=[("Content-Type", "text/plain")],
        req_body=b"alice",
    )
    findings = _scan_one(NoSQLInjectionCheck(), row, sender=responder)
    assert findings == []
    assert sent == []


def test_nosqli_mongo_skips_when_no_string_fields():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"x" * 999, engine="fake")

    row = _row(
        method="POST", url="https://x.test/api",
        req_headers=[("Content-Type", "application/json")],
        req_body=b'{"count": 5, "ok": true}',
    )
    findings = _scan_one(NoSQLInjectionCheck(), row, sender=responder)
    assert findings == []


# ----------------------------- XXEClassicCheck -------------------------------


def test_xxe_classic_fires_when_entity_substituted():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<r>web01.local</r>", engine="fake")

    row = _row(
        method="POST", url="https://x.test/import",
        req_headers=[("Content-Type", "application/xml")],
        req_body=b'<?xml version="1.0"?><foo>x</foo>',
    )
    findings = _scan_one(XXEClassicCheck(), row, sender=responder)
    assert findings
    assert findings[0].cwe == "CWE-611"
    assert "web01.local" in (findings[0].evidence or "")


def test_xxe_classic_quiet_when_parser_errors_out():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<r>parse error: undeclared entity</r>",
                         engine="fake")

    row = _row(
        method="POST", url="https://x.test/import",
        req_headers=[("Content-Type", "text/xml")],
        req_body=b'<?xml version="1.0"?><foo/>',
    )
    findings = _scan_one(XXEClassicCheck(), row, sender=responder)
    assert findings == []


def test_xxe_classic_skips_when_not_xml():
    sent: list[Request] = []

    def responder(req: Request) -> Response:
        sent.append(req)
        return Response(status=200, headers=[],
                         body=b"<r>web01.local</r>", engine="fake")

    row = _row(
        method="POST", url="https://x.test/api",
        req_headers=[("Content-Type", "application/json")],
        req_body=b'{"x":1}',
    )
    findings = _scan_one(XXEClassicCheck(), row, sender=responder)
    assert findings == []
    assert sent == []


def test_xxe_classic_quiet_on_non_2xx():
    def responder(req: Request) -> Response:
        return Response(status=500, headers=[],
                         body=b"<r>web01.local</r>", engine="fake")

    row = _row(
        method="POST", url="https://x.test/import",
        req_headers=[("Content-Type", "application/xml")],
        req_body=b'<?xml version="1.0"?><foo/>',
    )
    findings = _scan_one(XXEClassicCheck(), row, sender=responder)
    assert findings == []


def test_xxe_classic_detects_xml_via_body_prolog():
    """Content-Type missing — body prolog `<?xml` should still trigger detection."""
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<r>node-7</r>", engine="fake")

    row = _row(
        method="POST", url="https://x.test/import",
        req_headers=[("Content-Type", "application/octet-stream")],
        req_body=b'<?xml version="1.0"?><foo/>',
    )
    findings = _scan_one(XXEClassicCheck(), row, sender=responder)
    assert findings


# ----------------------------- ActiveCORSCheck -------------------------------


def test_active_cors_flags_reflected_arbitrary_origin_with_creds():
    def responder(req: Request) -> Response:
        origin = ""
        for k, v in req.headers:
            if k.lower() == "origin":
                origin = v
                break
        return Response(
            status=200,
            headers=[
                ("Access-Control-Allow-Origin", origin),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            body=b"", engine="fake",
        )

    findings = _scan_one(ActiveCORSCheck(), _row(), sender=responder)
    assert findings
    f = findings[0]
    assert f.cwe == "CWE-942"
    assert "ACAC: true" in (f.evidence or "")


def test_active_cors_quiet_without_credentials_flag():
    def responder(req: Request) -> Response:
        origin = ""
        for k, v in req.headers:
            if k.lower() == "origin":
                origin = v
                break
        return Response(
            status=200,
            headers=[("Access-Control-Allow-Origin", origin)],  # no ACAC
            body=b"", engine="fake",
        )

    findings = _scan_one(ActiveCORSCheck(), _row(), sender=responder)
    assert findings == []


def test_active_cors_quiet_when_origin_not_reflected():
    def responder(req: Request) -> Response:
        return Response(
            status=200,
            headers=[
                ("Access-Control-Allow-Origin", "https://allowed.example"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            body=b"", engine="fake",
        )

    findings = _scan_one(ActiveCORSCheck(), _row(), sender=responder)
    assert findings == []


def test_active_cors_null_origin_variant_fires():
    """ACAO: null + ACAC: true on the `null` origin probe."""
    def responder(req: Request) -> Response:
        origin = ""
        for k, v in req.headers:
            if k.lower() == "origin":
                origin = v
                break
        if origin == "null":
            return Response(
                status=200,
                headers=[
                    ("Access-Control-Allow-Origin", "null"),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
                body=b"", engine="fake",
            )
        return Response(status=200, headers=[], body=b"", engine="fake")

    findings = _scan_one(ActiveCORSCheck(), _row(), sender=responder)
    assert findings
    assert "null" in findings[0].title.lower()


# ----------------------------- registration ----------------------------------


def test_all_b2_checks_registered_in_builtin():
    names = {c.name for c in BUILTIN_ACTIVE_CHECKS}
    for n in ("xss-reflected-headers", "path-traversal-lfi", "nosqli-mongo",
              "xxe-classic", "cors-misconfig-extended"):
        assert n in names, f"{n} missing from BUILTIN_ACTIVE_CHECKS"


def test_mutated_cookie_only_swaps_named_value_in_cookie_header():
    """Sanity check the helper directly via a one-off context."""
    from reqlore.scanner.active import ActiveContext
    ctx = ActiveContext(
        history_id=1, host="x.test",
        base_url="https://x.test/", full_url="https://x.test/",
        method="GET",
        req_headers=[("Cookie", "sid=A; tok=B")],
        req_body=b"",
    )
    req = _mutated_cookie(ctx, "sid", "ZZZ")
    cookie_hdr = next(v for k, v in req.headers if k.lower() == "cookie")
    assert "sid=ZZZ" in cookie_hdr
    assert "tok=B" in cookie_hdr
