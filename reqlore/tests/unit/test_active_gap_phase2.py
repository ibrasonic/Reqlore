"""Phase 2 (Tier B) tests: ActiveTLSCheck, SubdomainTakeoverCheck,
DefaultCredsSprayCheck.

The TLS check's stdlib I/O is reached via the module-level
``_tls_inspect`` helper, which tests monkey-patch so CI never opens a
real socket.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner import active as active_mod
from reqlore.scanner.active import (
    ActiveTLSCheck,
    DefaultCredsSprayCheck,
    SubdomainTakeoverCheck,
    _is_weak_cipher,
    _parse_cert_expiry,
    _TLSInfo,
)


# --------------------------- shared helpers ---------------------------------


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


def _row(*, url="https://x.test/", host="x.test", method="GET",
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


# ------------------------------- helper units -------------------------------


def test_is_weak_cipher_flags_known_legacy_names():
    assert _is_weak_cipher("ECDHE-RSA-RC4-SHA", 128) is True
    assert _is_weak_cipher("DES-CBC3-SHA", 168) is True
    assert _is_weak_cipher("EXPORT-RC2-CBC-MD5", 40) is True
    assert _is_weak_cipher("NULL-SHA", 0) is True


def test_is_weak_cipher_flags_under_128_bits():
    assert _is_weak_cipher("WEIRD-CUSTOM", 64) is True


def test_is_weak_cipher_passes_modern_aead():
    assert _is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384", 256) is False
    assert _is_weak_cipher("TLS_AES_128_GCM_SHA256", 128) is False


def test_parse_cert_expiry_returns_none_on_garbage():
    assert _parse_cert_expiry("") is None
    assert _parse_cert_expiry("not a date") is None


def test_parse_cert_expiry_returns_seconds_for_real_format():
    # 30 days from now in the format ssl uses
    future = time.gmtime(time.time() + 30 * 86400)
    s = time.strftime("%b %d %H:%M:%S %Y GMT", future)
    secs = _parse_cert_expiry(s)
    assert secs is not None
    assert 28 * 86400 < secs < 32 * 86400


# ---------------------------- ActiveTLSCheck --------------------------------


def test_tls_check_skips_http_urls(monkeypatch):
    called = []

    def fake_inspect(host, port=443, *, timeout=5.0):
        called.append(host)
        return _TLSInfo(protocol="TLSv1.3", cipher_name="X", cipher_bits=256)

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(),
        _row(url="http://x.test/"),  # plain HTTP
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    assert findings == []
    assert called == []


def test_tls_check_fires_high_on_verification_failure(monkeypatch):

    def fake_inspect(host, port=443, *, timeout=5.0):
        return _TLSInfo(error="verify_failed",
                          verify_reason="hostname 'x.test' doesn't match")

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://x.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert "verification failed" in f.title.lower()
    assert "hostname" in f.evidence


def test_tls_check_silent_on_socket_error(monkeypatch):
    """ECONNREFUSED / timeout is not a finding — record silently."""

    def fake_inspect(host, port=443, *, timeout=5.0):
        return _TLSInfo(error="ssl_error:OSError")

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://offline.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    assert findings == []


def test_tls_check_fires_on_legacy_protocol(monkeypatch):

    def fake_inspect(host, port=443, *, timeout=5.0):
        future = time.gmtime(time.time() + 60 * 86400)
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", future)
        return _TLSInfo(
            protocol="TLSv1", cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            cipher_bits=256, not_after=not_after,
        )

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://x.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    titles = [f.title for f in findings]
    assert any("Legacy TLS protocol" in t for t in titles), titles


def test_tls_check_fires_on_weak_cipher(monkeypatch):

    def fake_inspect(host, port=443, *, timeout=5.0):
        future = time.gmtime(time.time() + 60 * 86400)
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", future)
        return _TLSInfo(
            protocol="TLSv1.2", cipher_name="ECDHE-RSA-RC4-SHA",
            cipher_bits=128, not_after=not_after,
        )

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://x.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    titles = [f.title for f in findings]
    assert any("Weak TLS cipher" in t for t in titles), titles


def test_tls_check_fires_high_on_expired_cert(monkeypatch):

    def fake_inspect(host, port=443, *, timeout=5.0):
        past = time.gmtime(time.time() - 30 * 86400)
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", past)
        return _TLSInfo(
            protocol="TLSv1.3", cipher_name="TLS_AES_128_GCM_SHA256",
            cipher_bits=128, not_after=not_after,
        )

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://x.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    titles = [f.title for f in findings]
    assert any("expired" in t.lower() for t in titles), titles
    expired = next(f for f in findings if "expired" in f.title.lower())
    assert expired.severity == "high"


def test_tls_check_quiet_on_modern_config(monkeypatch):

    def fake_inspect(host, port=443, *, timeout=5.0):
        future = time.gmtime(time.time() + 60 * 86400)
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", future)
        return _TLSInfo(
            protocol="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256, not_after=not_after,
        )

    monkeypatch.setattr(active_mod, "_tls_inspect", fake_inspect)

    findings = _scan_one(
        ActiveTLSCheck(), _row(url="https://x.test/"),
        sender=lambda req: Response(status=200, headers=[], body=b"",
                                       engine="fake"),
    )
    assert findings == []


# -------------------------- SubdomainTakeoverCheck --------------------------


def test_takeover_fires_on_github_pages_fingerprint():

    def responder(req: Request) -> Response:
        return Response(
            status=404, headers=[],
            body=(b"<html><body>"
                   b"<h1>There isn't a GitHub Pages site here.</h1>"
                   b"</body></html>"),
            engine="fake",
        )

    findings = _scan_one(
        SubdomainTakeoverCheck(),
        _row(url="https://docs.x.test/", host="docs.x.test"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("GitHub Pages" in t for t in titles), titles


def test_takeover_fires_on_s3_no_such_bucket():

    def responder(req: Request) -> Response:
        return Response(
            status=404, headers=[],
            body=b"<Error><Code>NoSuchBucket</Code></Error>",
            engine="fake",
        )

    findings = _scan_one(
        SubdomainTakeoverCheck(),
        _row(url="https://files.x.test/", host="files.x.test"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("Amazon S3" in t for t in titles), titles


def test_takeover_quiet_on_normal_site():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<html>Welcome to the site.</html>",
                         engine="fake")

    findings = _scan_one(
        SubdomainTakeoverCheck(),
        _row(url="https://app.x.test/", host="app.x.test"),
        sender=responder,
    )
    assert findings == []


def test_takeover_only_fires_once_per_host():

    def responder(req: Request) -> Response:
        # Body matches BOTH GitHub Pages and Heroku markers; we should
        # still get exactly one finding (first match wins).
        return Response(
            status=404, headers=[],
            body=(b"There isn't a GitHub Pages site here\n"
                   b"No such app\n"),
            engine="fake",
        )

    findings = _scan_one(
        SubdomainTakeoverCheck(),
        _row(url="https://multi.x.test/", host="multi.x.test"),
        sender=responder,
    )
    assert len(findings) == 1


# ---------------------------- DefaultCredsSpray -----------------------------


def test_default_creds_off_by_default():
    """Without ``allow_credential_probes`` the check must be a no-op
    even on a 401 Basic-auth challenge."""

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not send when default-creds disabled")

    row = _row(
        url="https://api.x.test/", host="api.x.test",
        resp_status=401,
        resp_headers=[("WWW-Authenticate", "Basic realm=\"x\"")],
        resp_body=b"Unauthorized",
    )
    findings = _scan_one(DefaultCredsSprayCheck(), row, sender=fail_send)
    assert findings == []


def test_default_creds_basic_fires_on_admin_admin():
    seen: list[str] = []

    def responder(req: Request) -> Response:
        for k, v in req.headers:
            if k.lower() == "authorization":
                seen.append(v)
                if v == "Basic YWRtaW46YWRtaW4=":  # admin:admin
                    return Response(status=200, headers=[],
                                     body=b"welcome admin", engine="fake")
        return Response(status=401, headers=[("WWW-Authenticate", "Basic")],
                         body=b"nope", engine="fake")

    row = _row(
        url="https://api.x.test/", host="api.x.test",
        resp_status=401,
        resp_headers=[("WWW-Authenticate", "Basic realm=\"x\"")],
        resp_body=b"Unauthorized",
    )
    opts = ActiveOptions(allow_credential_probes=True)
    findings = _scan_one(DefaultCredsSprayCheck(), row,
                          sender=responder, opts=opts)
    titles = [f.title for f in findings]
    assert any("admin:admin" in t for t in titles), titles
    # Only one finding even though we have 4 cred pairs.
    assert len(findings) == 1


def test_default_creds_basic_quiet_when_all_pairs_rejected():

    def responder(req: Request) -> Response:
        return Response(status=401, headers=[("WWW-Authenticate", "Basic")],
                         body=b"nope", engine="fake")

    row = _row(
        url="https://api.x.test/", host="api.x.test",
        resp_status=401,
        resp_headers=[("WWW-Authenticate", "Basic realm=\"x\"")],
        resp_body=b"Unauthorized",
    )
    opts = ActiveOptions(allow_credential_probes=True)
    findings = _scan_one(DefaultCredsSprayCheck(), row,
                          sender=responder, opts=opts)
    assert findings == []


def test_default_creds_form_skips_when_csrf_token_present():
    """Forms that ship a CSRF / authenticity token must be left alone —
    we'd just send a stale token and produce false negatives."""

    body = (b"<html><body><form action='/login' method='POST'>"
             b"<input type='hidden' name='authenticity_token' value='ABC'>"
             b"<input name='username'>"
             b"<input type='password' name='password'>"
             b"<button>Sign in</button></form></body></html>")

    def fail_send(req: Request) -> Response:
        raise AssertionError("CSRF-protected form must not be sprayed")

    row = _row(
        url="https://app.x.test/login", host="app.x.test",
        resp_status=200, resp_body=body,
    )
    opts = ActiveOptions(allow_credential_probes=True)
    findings = _scan_one(DefaultCredsSprayCheck(), row,
                          sender=fail_send, opts=opts)
    assert findings == []


def test_default_creds_form_fires_on_redirect_after_post():
    body = (b"<html><body><form action='/login' method='POST'>"
             b"<input name='username'>"
             b"<input type='password' name='password'>"
             b"<button>Sign in</button></form></body></html>")

    def responder(req: Request) -> Response:
        if req.method == "POST" and b"username=admin&password=admin" in (
                req.body or b""):
            return Response(status=302,
                             headers=[("Location", "/dashboard")],
                             body=b"", engine="fake")
        return Response(status=200, headers=[],
                         body=b"<html>login again</html>", engine="fake")

    row = _row(
        url="https://app.x.test/login", host="app.x.test",
        resp_status=200, resp_body=body,
    )
    opts = ActiveOptions(allow_credential_probes=True)
    findings = _scan_one(DefaultCredsSprayCheck(), row,
                          sender=responder, opts=opts)
    titles = [f.title for f in findings]
    assert any("admin:admin" in t for t in titles), titles
    assert findings[0].severity == "critical"
