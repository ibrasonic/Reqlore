"""Phase 24 — subdomain-takeover hint passive rule."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _TAKEOVER_FINGERPRINTS,
    rule_subdomain_takeover_hint,
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


def _req(method: str, url: str) -> bytes:
    return (f"{method} {url} HTTP/1.1\r\n\r\n").encode("latin-1")


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or [("Content-Type", "text/html")]
    head = f"HTTP/1.1 {status} OK\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _row(url="https://staging.target.test/", host="staging.target.test",
         status=404, resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host=host, url=url, method="GET", status=status,
        req_blob=_req("GET", url),
        resp_blob=_resp(status, resp_headers, resp_body),
    )


def _findings(row):
    return list(run_passive(row, rules=[rule_subdomain_takeover_hint]))


# ---- positives -------------------------------------------------------------


def test_aws_s3_xml_marker_flagged():
    body = (b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<Error><Code>NoSuchBucket</Code>'
            b'<Message>The specified bucket does not exist</Message></Error>')
    f = _findings(_row(
        resp_headers=[("Content-Type", "application/xml")],
        resp_body=body,
    ))
    # Both the XML <Code> marker AND the text marker will hit — that's
    # acceptable; both name the same provider.
    aws = [x for x in f if "AWS S3" in x.title]
    assert len(aws) >= 1


def test_github_pages_flagged_high_severity():
    body = (b"<html><body><h1>404</h1>"
            b"<p>There isn't a GitHub Pages site here.</p></body></html>")
    f = _findings(_row(resp_body=body))
    finding = next((x for x in f if "GitHub Pages" in x.title), None)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.cwe == "CWE-1395"
    # Confidence is tentative — we cannot confirm dangling-DNS from the
    # response alone.
    assert finding.confidence == "tentative"


def test_heroku_no_such_app_flagged():
    body = (b'<!doctype html><meta http-equiv="refresh" '
            b'content="0; url=https://www.herokucdn.com/error-pages/no-such-app.html">')
    f = _findings(_row(resp_body=body))
    assert any("Heroku" in x.title for x in f)


def test_azure_web_app_marker_flagged():
    body = b"<html><body><h1>404 Web Site not found.</h1></body></html>"
    f = _findings(_row(resp_body=body))
    assert any("Azure App Service" in x.title for x in f)


def test_azure_traffic_manager_case_insensitive():
    body = b"<TITLE>AZURE TRAFFIC MANAGER</TITLE>"
    f = _findings(_row(resp_body=body))
    assert any("Azure Traffic Manager" in x.title for x in f)


def test_fastly_unknown_domain_flagged():
    body = b"Fastly error: unknown domain: staging.target.test"
    f = _findings(_row(
        resp_headers=[("Content-Type", "text/plain")],
        resp_body=body,
    ))
    assert any("Fastly" in x.title for x in f)


def test_bitbucket_pages_marker_flagged():
    body = b"<html><body><h1>Repository not found</h1></body></html>"
    f = _findings(_row(resp_body=body))
    assert any("Bitbucket" in x.title for x in f)


def test_surge_sh_marker_flagged():
    body = b"project not found"
    f = _findings(_row(
        resp_headers=[("Content-Type", "text/plain")],
        resp_body=body,
    ))
    assert any("Surge.sh" in x.title for x in f)


def test_tilda_marker_flagged():
    body = b"<p>Please renew your subscription</p>"
    f = _findings(_row(resp_body=body))
    assert any("Tilda" in x.title for x in f)


def test_wpengine_marker_flagged():
    body = b"<h1>The site you were looking for couldn't be found</h1>"
    f = _findings(_row(resp_body=body))
    assert any("WP Engine" in x.title for x in f)


def test_ghost_pro_marker_flagged():
    body = (b"<p>The thing you were looking for is no longer here, "
            b"or never was</p>")
    f = _findings(_row(resp_body=body))
    assert any("Ghost" in x.title for x in f)


def test_pantheon_marker_flagged():
    body = (b"<h1>The gods are wise, but do not know of the site "
            b"which you seek</h1>")
    f = _findings(_row(resp_body=body))
    assert any("Pantheon" in x.title for x in f)


def test_shopify_marker_flagged():
    body = b"<p>Sorry, this shop is currently unavailable.</p>"
    f = _findings(_row(resp_body=body))
    assert any("Shopify" in x.title for x in f)


def test_readme_io_marker_flagged():
    body = b"<h1>Project doesnt exist... yet!</h1>"
    f = _findings(_row(resp_body=body))
    assert any("Readme.io" in x.title for x in f)


def test_teamwork_marker_flagged():
    body = b"<p>Oops - We didn't find your site</p>"
    f = _findings(_row(resp_body=body))
    assert any("Teamwork" in x.title for x in f)


def test_fires_regardless_of_status_code():
    # Heroku's no-such-app page is served with 200 (meta-refresh).
    body = (b'<meta http-equiv="refresh" content="0; '
            b'url=https://www.herokucdn.com/error-pages/no-such-app.html">')
    f = _findings(_row(status=200, resp_body=body))
    assert any("Heroku" in x.title for x in f)


# ---- negatives -------------------------------------------------------------


def test_plain_404_without_marker_not_flagged():
    body = (b"<html><body><h1>404 Not Found</h1>"
            b"<p>The requested URL was not found on this server.</p></body></html>")
    f = _findings(_row(resp_body=body))
    assert f == []


def test_binary_response_skipped():
    body = b"<Code>NoSuchBucket</Code>" + (b"\x00" * 200)
    f = _findings(_row(
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert f == []


def test_empty_body_skipped():
    f = _findings(_row(resp_body=b""))
    assert f == []


# ---- dedupe and registration -----------------------------------------------


def test_dedup_per_response_same_marker():
    body = (b"There isn't a GitHub Pages site here. "
            b"There isn't a GitHub Pages site here.")
    f = _findings(_row(resp_body=body))
    gh = [x for x in f if "GitHub Pages" in x.title]
    assert len(gh) == 1


def test_rule_runs_via_default_run_passive():
    body = b"<p>There isn't a GitHub Pages site here.</p>"
    f = list(run_passive(_row(resp_body=body)))
    assert any("GitHub Pages" in x.title for x in f)


def test_takeover_fingerprint_table_invariants():
    seen_slugs: set[str] = set()
    for entry in _TAKEOVER_FINGERPRINTS:
        assert len(entry) == 4, entry
        slug, regex, provider, remediation_hint = entry
        assert slug not in seen_slugs, f"duplicate slug {slug}"
        seen_slugs.add(slug)
        assert slug == slug.lower()
        # Compiled bytes regex.
        assert hasattr(regex, "search")
        assert regex.pattern.__class__ is bytes
        assert provider
        # Remediation must mention either claiming or removing the DNS
        # record — actionable, not vague.
        assert "claim" in remediation_hint.lower() or "remove" in remediation_hint.lower()
