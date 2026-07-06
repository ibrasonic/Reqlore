"""Phase 6 — active-check catalogue tests.

Each new check from :mod:`reqlore.scanner.phase6_checks` gets a
positive test (vulnerable fake responder → finding present) and a
negative test (hardened fake responder → no finding). A small number
of registry / smoke tests also confirm the side-effect import in
:mod:`reqlore.scanner.__init__` wired everything up.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from reqlore.engines import Response
from reqlore.scanner import BUILTIN_ACTIVE_CHECKS, ActiveOptions, ActiveScanner
from reqlore.scanner.phase6_checks import (
    PHASE6_CHECKS,
    CachePoisoningCheck,
    CodeInjectionCheck,
    CRLFInjectionCheck,
    CSVFormulaInjectionCheck,
    ELInjectionCheck,
    GraphQLAliasAbuseCheck,
    HTTPPUTMethodCheck,
    InputTransformationCheck,
    LDAPInjectionCheck,
    MassAssignmentCheck,
    OAuthStateValidationCheck,
    PaddingOracleCheck,
    SMTPHeaderInjectionCheck,
    SSIInjectionCheck,
    UploadPolyglotCheck,
    ViewStateNoMACCheck,
    XFFTrustCheck,
    XPathInjectionCheck,
)

# --- shared row / wire helpers --------------------------------------------

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


def _row(url="https://x.test/?q=hi", method="GET", status=200,
         req_headers=None, req_body=b"",
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host="x.test", url=url, method=method, status=status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


def _run(check, row, *, opts: ActiveOptions | None = None,
         responder=None):
    """Run a single check against a row via a fake sender."""
    if responder is None:
        def responder(req):
            return Response(status=200, headers=[],
                                                  body=b"", engine="fake")
    scanner = ActiveScanner(checks=[check], sender=responder)
    return scanner.run_on_row(row, options=opts or ActiveOptions(
        intensity_levels=frozenset({"light", "medium", "intrusive"}),
    ))


# --- registry / smoke ------------------------------------------------------

def test_registry_appends_phase6_checks_exactly_once():
    names = [c.name for c in BUILTIN_ACTIVE_CHECKS]
    # Every Phase 6 check name appears at least once.
    for c in PHASE6_CHECKS:
        assert c.name in names, f"{c.name} not registered"
    # No duplicates.
    assert len(names) == len(set(names)), "duplicate names in BUILTIN_ACTIVE_CHECKS"


def test_register_phase6_checks_is_idempotent():
    from reqlore.scanner.phase6_checks import register_phase6_checks
    before = list(BUILTIN_ACTIVE_CHECKS)
    register_phase6_checks()
    register_phase6_checks()
    assert len(BUILTIN_ACTIVE_CHECKS) == len(before)


def test_phase6_check_count_is_eighteen():
    assert len(PHASE6_CHECKS) == 18


# --- 1. CRLF injection -----------------------------------------------------

def test_crlf_injection_positive_via_separate_header():
    """Server echoes the injected header onto its own line."""
    def responder(req):
        # Pretend the server splits on CRLF and emits the injected header.
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query, keep_blank_values=True)
        v = (q.get("q", [""])[0])
        headers: list[tuple[str, str]] = []
        if "\r\n" in v:
            after = v.split("\r\n", 1)[1]
            if ": " in after:
                hk, hv = after.split(": ", 1)
                headers.append((hk, hv))
        return Response(status=200, headers=headers, body=b"", engine="fake")
    findings = _run(CRLFInjectionCheck(), _row(), responder=responder)
    assert any("CRLF" in f.title for f in findings)


def test_crlf_injection_negative_when_stripped():
    def responder(req):
        return Response(status=200, headers=[], body=b"", engine="fake")
    findings = _run(CRLFInjectionCheck(), _row(), responder=responder)
    assert not any("CRLF" in f.title for f in findings)


# --- 2. LDAP injection -----------------------------------------------------

def test_ldap_injection_positive():
    def responder(req):
        return Response(status=500, headers=[],
                         body=b"javax.naming.directory.LDAP error: bad search filter",
                         engine="fake")
    findings = _run(LDAPInjectionCheck(), _row(), responder=responder)
    assert any("LDAP" in f.title for f in findings)


def test_ldap_injection_negative():
    def responder(req):
        return Response(status=200, headers=[], body=b"ok", engine="fake")
    findings = _run(LDAPInjectionCheck(), _row(), responder=responder)
    assert findings == []


# --- 3. XPath injection ----------------------------------------------------

def test_xpath_injection_positive():
    def responder(req):
        return Response(status=500, headers=[],
                         body=b"XPathException: Invalid XPath expression",
                         engine="fake")
    findings = _run(XPathInjectionCheck(), _row(), responder=responder)
    assert any("XPath" in f.title for f in findings)


def test_xpath_injection_negative():
    def responder(req):
        return Response(status=200, headers=[], body=b"ok", engine="fake")
    findings = _run(XPathInjectionCheck(), _row(), responder=responder)
    assert findings == []


# --- 4. SMTP header injection ----------------------------------------------

def test_smtp_header_injection_positive():
    def responder(req):
        return Response(status=500, headers=[],
                         body=b"SMTP error 550 5.7.1 recipient address rejected",
                         engine="fake")
    findings = _run(
        SMTPHeaderInjectionCheck(),
        _row(url="https://x.test/?email=a@b.test"),
        responder=responder,
    )
    assert any("SMTP" in f.title for f in findings)


def test_smtp_header_injection_negative_no_email_param():
    """No email-shaped param → no probes sent → no findings."""
    def responder(req):  # would fire if check probed
        return Response(status=500, headers=[],
                         body=b"SMTP error 550 5.7.1 recipient address rejected",
                         engine="fake")
    findings = _run(SMTPHeaderInjectionCheck(),
                     _row(url="https://x.test/?id=42"),
                     responder=responder)
    assert findings == []


# --- 5. SSI injection ------------------------------------------------------

def test_ssi_injection_positive():
    def responder(req):
        # Apache's mod_include consumes the directive and emits (none).
        return Response(status=200, headers=[],
                         body=b"<html>before (none) after</html>",
                         engine="fake")
    findings = _run(SSIInjectionCheck(), _row(), responder=responder)
    assert any("includes injection" in f.title.lower() for f in findings)


def test_ssi_injection_negative_when_echoed_verbatim():
    def responder(req):
        # Server echoes the directive untouched — that's NOT vulnerable.
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query)
        return Response(status=200, headers=[],
                         body=b"<html>" + q.get("q", [""])[0].encode() + b"</html>",
                         engine="fake")
    findings = _run(SSIInjectionCheck(), _row(), responder=responder)
    assert findings == []


# --- 6. Java EL injection --------------------------------------------------

def test_el_injection_positive():
    expected = str(73127 * 9173).encode()
    def responder(req):
        # Pretend the EL engine evaluates ${a*b}.
        return Response(status=200, headers=[],
                         body=b"<html>" + expected + b"</html>",
                         engine="fake")
    findings = _run(ELInjectionCheck(), _row(), responder=responder)
    assert any("Expression Language" in f.title for f in findings)


def test_el_injection_negative():
    def responder(req):
        return Response(status=200, headers=[],
                         body=b"<html>literal</html>",
                         engine="fake")
    findings = _run(ELInjectionCheck(), _row(), responder=responder)
    assert findings == []


# --- 7. Code injection -----------------------------------------------------

def test_code_injection_positive_php():
    product = str(6113 * 7919).encode()
    def responder(req):
        # Server evals; product appears in body.
        return Response(status=200, headers=[],
                         body=b"out=" + product, engine="fake")
    findings = _run(CodeInjectionCheck(), _row(), responder=responder)
    assert any("code injection" in f.title.lower() for f in findings)


def test_code_injection_negative():
    def responder(req):
        return Response(status=200, headers=[], body=b"ok", engine="fake")
    findings = _run(CodeInjectionCheck(), _row(), responder=responder)
    assert findings == []


# --- 8. Padding oracle ------------------------------------------------------

def test_padding_oracle_positive_divergent_status():
    # 32-byte raw = 2 AES blocks → 44-char base64 ending in "==".
    ct = base64.b64encode(b"\x01" * 32).decode()
    url = f"https://x.test/?token={ct}"

    def responder(req):
        # Status diverges based on whether last byte of base64 ciphertext matches.
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query)
        v = q.get("token", [""])[0]
        if v == ct:
            return Response(status=200, headers=[], body=b"ok" * 50, engine="fake")
        return Response(status=500, headers=[], body=b"err", engine="fake")

    findings = _run(PaddingOracleCheck(), _row(url=url), responder=responder)
    assert any("Padding oracle" in f.title for f in findings)


def test_padding_oracle_negative_no_divergence():
    ct = base64.b64encode(b"\x01" * 32).decode()
    url = f"https://x.test/?token={ct}"
    def responder(req):
        return Response(status=200, headers=[], body=b"ok" * 50, engine="fake")
    findings = _run(PaddingOracleCheck(), _row(url=url), responder=responder)
    assert findings == []


# --- 9. CSV formula injection ----------------------------------------------

def test_csv_formula_injection_positive():
    base = _row(
        url="https://x.test/export?name=alice",
        status=200,
        resp_headers=[("Content-Type", "text/csv")],
        resp_body=b"id,name\n1,alice\n",
    )
    def responder(req):
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query)
        nm = q.get("name", [""])[0]
        return Response(status=200,
                         headers=[("Content-Type", "text/csv")],
                         body=f"id,name\n1,{nm}\n".encode(),
                         engine="fake")
    findings = _run(CSVFormulaInjectionCheck(), base, responder=responder)
    assert any("CSV" in f.title for f in findings)


def test_csv_formula_injection_negative_when_quoted():
    base = _row(
        url="https://x.test/export?name=alice",
        status=200,
        resp_headers=[("Content-Type", "text/csv")],
        resp_body=b"id,name\n1,alice\n",
    )
    def responder(req):
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query)
        nm = q.get("name", [""])[0]
        # Properly escaped — prefix dangerous cells with a single quote.
        if nm and nm[0] in "=+-@\t\r":
            nm = "'" + nm
        return Response(status=200,
                         headers=[("Content-Type", "text/csv")],
                         body=f"id,name\n1,\"{nm}\"\n".encode(),
                         engine="fake")
    findings = _run(CSVFormulaInjectionCheck(), base, responder=responder)
    assert findings == []


# --- 10. Mass assignment ---------------------------------------------------

def test_mass_assignment_positive():
    body = json.dumps({"name": "alice"}).encode()
    row = _row(
        url="https://x.test/users",
        method="POST",
        status=200,
        req_headers=[("Content-Type", "application/json")],
        req_body=body,
    )
    def responder(req):
        # Server blindly binds extra fields and echoes the model back.
        parsed = json.loads(req.body)
        return Response(status=200,
                         headers=[("Content-Type", "application/json")],
                         body=json.dumps(parsed).encode(),
                         engine="fake")
    findings = _run(MassAssignmentCheck(), row, responder=responder)
    assert any("Mass assignment" in f.title for f in findings)


def test_mass_assignment_negative_with_allowlist():
    body = json.dumps({"name": "alice"}).encode()
    row = _row(
        url="https://x.test/users",
        method="POST",
        status=200,
        req_headers=[("Content-Type", "application/json")],
        req_body=body,
    )
    def responder(req):
        # Server enforces a strict DTO — only "name" is bound.
        parsed = json.loads(req.body)
        return Response(status=200,
                         headers=[("Content-Type", "application/json")],
                         body=json.dumps({"name": parsed.get("name")}).encode(),
                         engine="fake")
    findings = _run(MassAssignmentCheck(), row, responder=responder)
    assert findings == []


# --- 11. Cache poisoning ---------------------------------------------------

def test_cache_poisoning_positive_via_xfh():
    def responder(req):
        # Reflect X-Forwarded-Host into the body.
        for k, v in req.headers:
            if k.lower() == "x-forwarded-host":
                return Response(status=200,
                                 headers=[("Content-Type", "text/html"),
                                          ("Cache-Control", "public, max-age=600")],
                                 body=f"<base href=https://{v}/>".encode(),
                                 engine="fake")
        return Response(status=200, headers=[], body=b"<html/>", engine="fake")
    findings = _run(CachePoisoningCheck(), _row(), responder=responder)
    assert any("cache poisoning" in f.title.lower() for f in findings)
    assert any(f.confidence == "firm" for f in findings)


def test_cache_poisoning_negative_no_reflection():
    def responder(req):
        return Response(status=200, headers=[("Content-Type", "text/html")],
                         body=b"<html/>", engine="fake")
    findings = _run(CachePoisoningCheck(), _row(), responder=responder)
    assert findings == []


# --- 12. ViewState without MAC ---------------------------------------------

def test_viewstate_no_mac_positive():
    # Synthesise a baseline response with __VIEWSTATE but no __EVENTVALIDATION.
    vs_blob = base64.b64encode(b"\xff\x01abcdefghij").decode()
    body = (
        b'<form><input type="hidden" name="__VIEWSTATE" value="'
        + vs_blob.encode() + b'"/></form>'
    )
    row = _row(resp_body=body)
    # No probes are sent for this observational check; sender is unused.
    findings = _run(ViewStateNoMACCheck(), row)
    assert any("ViewState" in f.title for f in findings)


def test_viewstate_no_mac_negative_with_eventvalidation():
    vs_blob = base64.b64encode(b"\xff\x01abcdefghij").decode()
    body = (
        b'<form>'
        b'<input type="hidden" name="__VIEWSTATE" value="' + vs_blob.encode() + b'"/>'
        b'<input type="hidden" name="__EVENTVALIDATION" value="xxx"/>'
        b'</form>'
    )
    row = _row(resp_body=body)
    findings = _run(ViewStateNoMACCheck(), row)
    assert findings == []


# --- 13. HTTP PUT enabled --------------------------------------------------

def test_http_put_positive():
    def responder(req):
        if req.method == "PUT":
            return Response(status=201, headers=[], body=b"", engine="fake")
        return Response(status=200, headers=[], body=b"", engine="fake")
    findings = _run(HTTPPUTMethodCheck(), _row(), responder=responder)
    assert any("PUT" in f.title for f in findings)


def test_http_put_negative_when_forbidden():
    def responder(req):
        if req.method == "PUT":
            return Response(status=405, headers=[], body=b"", engine="fake")
        return Response(status=200, headers=[], body=b"", engine="fake")
    findings = _run(HTTPPUTMethodCheck(), _row(), responder=responder)
    assert findings == []


# --- 14. XFF trust bypass --------------------------------------------------

def test_xff_trust_positive():
    """Baseline 403 → 200 with X-Forwarded-For."""
    def responder(req):
        for k, v in req.headers:
            if k.lower() in ("x-forwarded-for", "x-real-ip", "x-client-ip",
                              "x-originating-ip", "true-client-ip") and v == "127.0.0.1":
                return Response(status=200, headers=[], body=b"ok",
                                 engine="fake")
        return Response(status=403, headers=[], body=b"forbidden",
                         engine="fake")
    row = _row(status=403, resp_body=b"forbidden")
    findings = _run(XFFTrustCheck(), row, responder=responder)
    assert any("X-Forwarded-For" in f.title or "client-IP" in f.title
               for f in findings)


def test_xff_trust_negative_baseline_200():
    """Baseline is 200 → check skips (no auth gate to bypass)."""
    def responder(req):
        return Response(status=200, headers=[], body=b"ok", engine="fake")
    findings = _run(XFFTrustCheck(), _row(), responder=responder)
    assert findings == []


def test_xff_trust_negative_still_forbidden():
    def responder(req):
        return Response(status=403, headers=[], body=b"forbidden", engine="fake")
    row = _row(status=403, resp_body=b"forbidden")
    findings = _run(XFFTrustCheck(), row, responder=responder)
    assert findings == []


# --- 15. Upload polyglot ---------------------------------------------------

def test_upload_polyglot_tentative_when_filename_echoed():
    body = (
        b"--BND\r\n"
        b'Content-Disposition: form-data; name="file"; filename="x.gif"\r\n'
        b"Content-Type: image/gif\r\n\r\n"
        b"GIF89a;\r\n"
        b"--BND--\r\n"
    )
    row = _row(
        url="https://x.test/upload", method="POST", status=200,
        req_headers=[("Content-Type", "multipart/form-data; boundary=BND")],
        req_body=body,
    )

    def responder(req):
        # Echo the filename in the response body.
        import re
        m = re.search(rb'filename="([^"]+)"', req.body or b"")
        fn = m.group(1) if m else b""
        return Response(status=200,
                         headers=[("Content-Type", "text/html")],
                         body=b"uploaded " + fn, engine="fake")

    findings = _run(UploadPolyglotCheck(), row, responder=responder)
    assert any("Unrestricted file upload" in f.title for f in findings)


def test_upload_polyglot_negative_rejected():
    body = (
        b"--BND\r\n"
        b'Content-Disposition: form-data; name="file"; filename="x.gif"\r\n'
        b"Content-Type: image/gif\r\n\r\n"
        b"GIF89a;\r\n"
        b"--BND--\r\n"
    )
    row = _row(
        url="https://x.test/upload", method="POST", status=200,
        req_headers=[("Content-Type", "multipart/form-data; boundary=BND")],
        req_body=body,
    )
    def responder(req):
        return Response(status=400, headers=[], body=b"rejected", engine="fake")
    findings = _run(UploadPolyglotCheck(), row, responder=responder)
    assert findings == []


# --- 16. OAuth state validation --------------------------------------------

def test_oauth_state_positive():
    url = "https://x.test/oauth/callback?code=abc&state=xyz"
    def responder(req):
        # Server accepts the callback even after state was stripped.
        return Response(status=200, headers=[], body=b"welcome",
                         engine="fake")
    findings = _run(OAuthStateValidationCheck(), _row(url=url),
                     responder=responder)
    assert any("OAuth state" in f.title for f in findings)


def test_oauth_state_negative_when_rejected():
    url = "https://x.test/oauth/callback?code=abc&state=xyz"
    def responder(req):
        return Response(status=400, headers=[], body=b"invalid state",
                         engine="fake")
    findings = _run(OAuthStateValidationCheck(), _row(url=url),
                     responder=responder)
    assert findings == []


def test_oauth_state_negative_off_path():
    """Path doesn't look like OAuth → check skips."""
    url = "https://x.test/api/data?code=abc&state=xyz"
    def responder(req):
        return Response(status=200, headers=[], body=b"ok", engine="fake")
    findings = _run(OAuthStateValidationCheck(), _row(url=url),
                     responder=responder)
    assert findings == []


# --- 17. GraphQL alias abuse -----------------------------------------------

def test_graphql_alias_abuse_positive():
    row = _row(
        url="https://x.test/graphql", method="POST",
        req_headers=[("Content-Type", "application/json")],
        req_body=json.dumps({"query": "{ me { id } }"}).encode(),
    )
    def responder(req):
        parsed = json.loads(req.body)
        q = parsed.get("query", "")
        # Server processes every alias.
        n_aliases = q.count("__typename")
        return Response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=json.dumps({
                "data": {f"a{i}": "Query" for i in range(n_aliases)},
            }).encode(),
            engine="fake",
        )
    findings = _run(GraphQLAliasAbuseCheck(), row, responder=responder)
    assert any("alias" in f.title.lower() for f in findings)


def test_graphql_alias_abuse_negative_cap_enforced():
    row = _row(
        url="https://x.test/graphql", method="POST",
        req_headers=[("Content-Type", "application/json")],
        req_body=json.dumps({"query": "{ me { id } }"}).encode(),
    )
    def responder(req):
        # Server rejects with 400 when more than 10 aliases are present.
        return Response(status=400,
                         headers=[("Content-Type", "application/json")],
                         body=b'{"errors":[{"message":"too many aliases"}]}',
                         engine="fake")
    findings = _run(GraphQLAliasAbuseCheck(), row, responder=responder)
    assert findings == []


# --- 18. Input transformation ----------------------------------------------

def test_input_transformation_positive_url_decode():
    def responder(req):
        # Server URL-decodes the value before reflecting it.
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(req.url).query, keep_blank_values=True)
        v = q.get("q", [""])[0]
        return Response(status=200,
                         headers=[("Content-Type", "text/html")],
                         body=f"<html>{v}</html>".encode(),
                         engine="fake")
    findings = _run(InputTransformationCheck(), _row(), responder=responder)
    assert any("transformation" in f.title.lower() for f in findings)


def test_input_transformation_negative_verbatim():
    def responder(req):
        # Server reflects the raw URL-encoded form verbatim — no transformation.
        url_q = req.url.split("?", 1)[1] if "?" in req.url else ""
        return Response(status=200,
                         headers=[("Content-Type", "text/html")],
                         body=f"<html>{url_q}</html>".encode(),
                         engine="fake")
    findings = _run(InputTransformationCheck(), _row(), responder=responder)
    assert findings == []
