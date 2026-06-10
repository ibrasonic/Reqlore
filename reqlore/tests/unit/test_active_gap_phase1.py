"""Phase 1 gap-list active checks: ForcedBrowsing, DeserialisationReflect,
WebCacheDeception, OAuthRedirectURI.

Each check is exercised through ``ActiveScanner.run_on_row`` with a fake
sender, the same pattern used by the existing ``test_active_b2`` tests.
"""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    DeserialisationReflectCheck,
    ForcedBrowsingCheck,
    OAuthRedirectURICheck,
    WebCacheDeceptionCheck,
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


# ------------------------- ForcedBrowsingCheck -------------------------------


def test_forced_browsing_fires_on_git_head_with_real_body():
    seen: list[str] = []

    def responder(req: Request) -> Response:
        seen.append(req.url)
        if req.url.endswith("/.git/HEAD"):
            return Response(status=200, headers=[],
                             body=b"ref: refs/heads/main\n", engine="fake")
        return Response(status=404, headers=[], body=b"nope", engine="fake")

    findings = _scan_one(
        ForcedBrowsingCheck(), _row(url="https://x.test/anything"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any(".git/HEAD" in t for t in titles), titles
    assert any(url.endswith("/.git/HEAD") for url in seen)


def test_forced_browsing_ignores_spa_fallback_200():
    """A 200 whose body does not match the artefact fingerprint must NOT
    fire — otherwise SPAs that serve index.html for every path would
    light up every wordlist entry."""

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<!doctype html><html>SPA root</html>",
                         engine="fake")

    findings = _scan_one(
        ForcedBrowsingCheck(), _row(url="https://spa.test/dash"),
        sender=responder,
    )
    assert findings == []


def test_forced_browsing_skips_when_not_200():

    def responder(req: Request) -> Response:
        return Response(status=403, headers=[], body=b"forbidden",
                         engine="fake")

    findings = _scan_one(
        ForcedBrowsingCheck(), _row(url="https://x.test/page"),
        sender=responder,
    )
    assert findings == []


# ---------------------- DeserialisationReflectCheck --------------------------


def test_deserialisation_reflect_fires_on_java_stack_trace():

    def responder(req: Request) -> Response:
        body = (b"500 Internal Server Error\n"
                b"java.io.InvalidClassException: blah\n"
                b"  at java.io.ObjectInputStream.readObject\n")
        return Response(status=500, headers=[], body=body, engine="fake")

    findings = _scan_one(
        DeserialisationReflectCheck(),
        _row(url="https://x.test/api?data=hello"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("java" in t.lower() for t in titles), titles


def test_deserialisation_reflect_quiet_on_plain_response():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"ok",
                         engine="fake")

    findings = _scan_one(
        DeserialisationReflectCheck(),
        _row(url="https://x.test/api?data=hello"),
        sender=responder,
    )
    assert findings == []


def test_deserialisation_reflect_skips_when_no_params():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"java.io.ObjectInputStream",
                         engine="fake")

    findings = _scan_one(
        DeserialisationReflectCheck(),
        _row(url="https://x.test/api"),  # no query params
        sender=responder,
    )
    assert findings == []


# ------------------------- WebCacheDeceptionCheck ----------------------------


def test_cache_deception_fires_when_anonymous_probe_mirrors_auth_body():
    auth_body = (b"<html><body>Hello user@example.com -- "
                  b"<a href='/logout'>logout</a><nav>Dashboard menu items "
                  b"here with lots of words to make the jaccard similarity "
                  b"meaningful and not all 3-grams overlap with garbage."
                  b"</nav></body></html>")

    def responder(req: Request) -> Response:
        # Anonymous probe (no Cookie sent) — return the personal body
        # because the cache mis-keyed.
        return Response(status=200, headers=[], body=auth_body, engine="fake")

    findings = _scan_one(
        WebCacheDeceptionCheck(),
        _row(url="https://x.test/account",
              req_headers=[("Cookie", "session=abc")],
              resp_body=auth_body),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("cache deception" in t.lower() for t in titles), titles


def test_cache_deception_skips_when_no_auth():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"x" * 1000, engine="fake")

    findings = _scan_one(
        WebCacheDeceptionCheck(),
        _row(url="https://x.test/account",
              req_headers=[("Accept", "*/*")],  # no Cookie / Authorization
              resp_body=b"x" * 1000),
        sender=responder,
    )
    assert findings == []


def test_cache_deception_skips_when_probe_differs():
    auth_body = b"PERSONAL: secret data for alice\n" * 50

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"public landing page totally different content",
                         engine="fake")

    findings = _scan_one(
        WebCacheDeceptionCheck(),
        _row(url="https://x.test/account",
              req_headers=[("Cookie", "session=abc")],
              resp_body=auth_body),
        sender=responder,
    )
    assert findings == []


# --------------------------- OAuthRedirectURICheck ---------------------------


def test_oauth_redirect_uri_fires_on_30x_to_swapped_host():
    seen_url = []

    def responder(req: Request) -> Response:
        seen_url.append(req.url)
        # Pull the redirect_uri value out of the URL the scanner sent.
        marker = ""
        if "redirect_uri=" in req.url:
            tail = req.url.split("redirect_uri=", 1)[1]
            from urllib.parse import unquote, urlsplit
            try:
                marker = urlsplit(unquote(tail)).netloc
            except ValueError:
                marker = ""
        return Response(
            status=302,
            headers=[("Location", f"https://{marker}/callback?code=x")],
            body=b"", engine="fake",
        )

    findings = _scan_one(
        OAuthRedirectURICheck(),
        _row(url="https://idp.test/auth?redirect_uri=https://app.test/cb"),
        sender=responder,
    )
    titles = [f.title for f in findings]
    assert any("redirect" in t.lower() for t in titles), titles


def test_oauth_redirect_uri_quiet_when_server_ignores_swap():

    def responder(req: Request) -> Response:
        # Server hard-coded the legitimate callback.
        return Response(
            status=302,
            headers=[("Location", "https://app.test/cb?code=x")],
            body=b"", engine="fake",
        )

    findings = _scan_one(
        OAuthRedirectURICheck(),
        _row(url="https://idp.test/auth?redirect_uri=https://app.test/cb"),
        sender=responder,
    )
    assert findings == []


def test_oauth_redirect_uri_skips_when_no_target_param():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    findings = _scan_one(
        OAuthRedirectURICheck(),
        _row(url="https://idp.test/auth?state=xyz"),
        sender=responder,
    )
    assert findings == []
