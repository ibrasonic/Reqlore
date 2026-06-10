"""Phase 4 (Tier D) tests: CloudBlobMisconfigCheck, DOMXSSCheck.

The cloud-blob check is plain HTTP and runs against a fake sender.
The DOM XSS check is gated on Playwright being installed; we exercise
the gates first (always green) and skip the rendering test when the
optional dep is missing.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    CloudBlobMisconfigCheck,
    DOMXSSCheck,
    _cloud_blob_service,
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


def _row(*, url, host, method="GET",
          req_headers=None, req_body=b"",
          resp_status=200, resp_headers=None, resp_body=b""):
    return _Row(
        id=1, host=host, url=url, method=method, status=resp_status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(resp_status, resp_headers or [], resp_body),
    )


def _scan_one(check, row, *, sender, opts=None) -> list:
    scanner = ActiveScanner(checks=[check], sender=sender)
    return scanner.run_on_row(row, options=opts or ActiveOptions())


# ----------------------- _cloud_blob_service ---------------------------------


def test_cloud_blob_service_recognises_s3_variants():
    assert _cloud_blob_service("mybucket.s3.amazonaws.com") == "Amazon S3"
    assert (_cloud_blob_service("mybucket.s3.us-east-1.amazonaws.com")
            == "Amazon S3")
    assert (_cloud_blob_service(
        "mybucket.s3-website-us-east-1.amazonaws.com") == "Amazon S3")


def test_cloud_blob_service_recognises_azure():
    assert (_cloud_blob_service("contoso.blob.core.windows.net")
            == "Azure Blob Storage")


def test_cloud_blob_service_returns_none_for_unrelated_hosts():
    assert _cloud_blob_service("example.com") is None
    assert _cloud_blob_service("api.example.com") is None
    assert _cloud_blob_service("") is None


# -------------------------- CloudBlobMisconfigCheck -------------------------


def test_cloud_blob_skips_non_cloud_host():
    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe a non-cloud host")

    row = _row(url="https://example.com/whatever",
                host="example.com")
    assert _scan_one(CloudBlobMisconfigCheck(), row,
                       sender=fail_send) == []


def test_cloud_blob_fires_on_anonymous_s3_listing():
    seen: list[str] = []

    def responder(req: Request) -> Response:
        seen.append(req.url)
        body = (b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                 b"<ListBucketResult xmlns=\"http://s3...\">"
                 b"<Name>mybucket</Name></ListBucketResult>")
        return Response(status=200, headers=[], body=body, engine="fake")

    row = _row(url="https://mybucket.s3.amazonaws.com/secret.txt",
                host="mybucket.s3.amazonaws.com")
    findings = _scan_one(CloudBlobMisconfigCheck(), row, sender=responder)
    assert len(findings) == 1
    assert "Amazon S3" in findings[0].title
    # Probe URL must carry the v2 listing query.
    assert any("list-type=2" in u for u in seen)


def test_cloud_blob_fires_on_anonymous_azure_listing():
    def responder(req: Request) -> Response:
        body = (b"<?xml version=\"1.0\"?>"
                 b"<EnumerationResults ServiceEndpoint=\"https://contoso\">"
                 b"</EnumerationResults>")
        return Response(status=200, headers=[], body=body, engine="fake")

    row = _row(url="https://contoso.blob.core.windows.net/data/x",
                host="contoso.blob.core.windows.net")
    findings = _scan_one(CloudBlobMisconfigCheck(), row, sender=responder)
    assert len(findings) == 1
    assert "Azure" in findings[0].title


def test_cloud_blob_quiet_on_403():
    def responder(req: Request) -> Response:
        return Response(status=403, headers=[], body=b"<Error/>",
                         engine="fake")

    row = _row(url="https://mybucket.s3.amazonaws.com/x",
                host="mybucket.s3.amazonaws.com")
    assert _scan_one(CloudBlobMisconfigCheck(), row,
                       sender=responder) == []


def test_cloud_blob_quiet_on_200_without_listing_envelope():
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"hello there",
                         engine="fake")

    row = _row(url="https://mybucket.s3.amazonaws.com/x",
                host="mybucket.s3.amazonaws.com")
    assert _scan_one(CloudBlobMisconfigCheck(), row,
                       sender=responder) == []


# --------------------------------- DOMXSSCheck ------------------------------


def test_dom_xss_off_by_default():
    def fail_send(req: Request) -> Response:
        raise AssertionError("must not run when allow_dom_xss_probes off")

    row = _row(url="https://x.test/page?q=hello", host="x.test")
    assert _scan_one(DOMXSSCheck(), row, sender=fail_send) == []


def test_dom_xss_skips_non_get_methods():
    def fail_send(req: Request) -> Response:
        raise AssertionError("must not run on non-GET")

    row = _row(url="https://x.test/page?q=hello",
                host="x.test", method="POST")
    opts = ActiveOptions(allow_dom_xss_probes=True)
    assert _scan_one(DOMXSSCheck(), row,
                       sender=fail_send, opts=opts) == []


def test_dom_xss_skips_when_url_has_no_query_params():
    def fail_send(req: Request) -> Response:
        raise AssertionError("must not run without query params")

    row = _row(url="https://x.test/page", host="x.test")
    opts = ActiveOptions(allow_dom_xss_probes=True)
    assert _scan_one(DOMXSSCheck(), row,
                       sender=fail_send, opts=opts) == []


def test_dom_xss_silent_when_playwright_unavailable(monkeypatch):
    """When the optional dep is absent the check must return cleanly,
    not raise ImportError."""
    import reqlore._optdeps as _optdeps
    monkeypatch.setattr(_optdeps, "PLAYWRIGHT_AVAILABLE", False)

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not even start without Playwright")

    row = _row(url="https://x.test/page?q=hello", host="x.test")
    opts = ActiveOptions(allow_dom_xss_probes=True)
    assert _scan_one(DOMXSSCheck(), row,
                       sender=fail_send, opts=opts) == []


def test_dom_xss_fires_when_marker_reaches_innerHTML():
    """Live test: requires Playwright + an installed Chromium.

    The page renders an attacker-controlled query parameter directly
    into innerHTML, which is the classic DOM XSS sink.
    """
    pytest.importorskip("playwright")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")

    # Verify Chromium is actually available before we go further;
    # otherwise the test would fail on infrastructure, not regression.
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as exc:
                pytest.skip(f"chromium not installed: {exc}")
            browser.close()
    except Exception as exc:
        pytest.skip(f"playwright runtime unavailable: {exc}")

    # Stand up a tiny HTTP server on localhost that injects the query
    # parameter into the document body via innerHTML.
    import http.server
    import socketserver
    import threading

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):                                       # noqa: N802
            from urllib.parse import urlsplit, parse_qs
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = (b"<!doctype html><html><body>"
                     b"<div id=\"out\"></div>"
                     b"<script>document.getElementById('out')"
                     b".innerHTML = " + repr(q).encode() + b";</script>"
                     b"</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a, **_kw):                      # noqa: N802
            pass  # silence test runner spam

    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        row = _row(url=f"http://127.0.0.1:{port}/page?q=safe",
                    host="127.0.0.1")
        opts = ActiveOptions(allow_dom_xss_probes=True)
        # The sender is never used by DOMXSSCheck — Playwright drives
        # the request itself — so passing a stub is fine.
        findings = _scan_one(
            DOMXSSCheck(), row,
            sender=lambda req: Response(status=200, headers=[],
                                            body=b"", engine="fake"),
            opts=opts,
        )
    finally:
        srv.shutdown()
        srv.server_close()

    assert len(findings) >= 1
    f = findings[0]
    assert f.severity == "high"
    assert "DOM XSS" in f.title
    assert "innerHTML" in (f.evidence or "")
