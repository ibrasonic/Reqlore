"""B.1 passive rule additions: positive + negative cases for each new rule."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from reqlore.scanner.passive import (
    BUILTIN_RULES,
    RuleContext,
    rule_autocomplete_on_password,
    rule_cache_control_on_private,
    rule_cors_null_origin,
    rule_cors_reflected_origin,
    rule_graphql_batching_hint,
    rule_open_redirect_hint_headers,
    rule_session_fixation,
    rule_weak_tls_hint,
)

# ---------------- shared helpers ----------------


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


def _ctx(*, url="https://x.test/", method="GET", status=200,
          req_headers=None, req_body=b"",
          resp_headers=None, resp_body=b"") -> RuleContext:
    host = url.split("//", 1)[-1].split("/", 1)[0]
    row = _Row(
        id=1, host=host, url=url, method=method, status=status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )
    return RuleContext.from_row(row)


# ---------------- cors-null-origin ----------------


def test_cors_null_origin_flags_literal_null():
    f = list(rule_cors_null_origin(_ctx(
        resp_headers=[("Access-Control-Allow-Origin", "null")],
    )))
    assert f and "null" in f[0].title.lower()


def test_cors_null_origin_ignores_real_origin():
    f = list(rule_cors_null_origin(_ctx(
        resp_headers=[("Access-Control-Allow-Origin", "https://app.test")],
    )))
    assert f == []


# ---------------- cors-reflected-origin ----------------


def test_cors_reflected_origin_flags_reflected_with_credentials():
    f = list(rule_cors_reflected_origin(_ctx(
        req_headers=[("Origin", "https://evil.test")],
        resp_headers=[
            ("Access-Control-Allow-Origin", "https://evil.test"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    )))
    assert f and "reflects" in f[0].title.lower()


def test_cors_reflected_origin_skips_without_credentials():
    f = list(rule_cors_reflected_origin(_ctx(
        req_headers=[("Origin", "https://evil.test")],
        resp_headers=[("Access-Control-Allow-Origin", "https://evil.test")],
    )))
    assert f == []


def test_cors_reflected_origin_skips_different_origin():
    f = list(rule_cors_reflected_origin(_ctx(
        req_headers=[("Origin", "https://evil.test")],
        resp_headers=[
            ("Access-Control-Allow-Origin", "https://app.test"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    )))
    assert f == []


# ---------------- weak-tls-hint ----------------


@pytest.mark.parametrize("path", [
    "/login", "/signin", "/auth", "/oauth/token", "/sso/start", "/account/edit",
])
def test_weak_tls_hint_flags_auth_paths_over_http(path):
    f = list(rule_weak_tls_hint(_ctx(url=f"http://x.test{path}")))
    assert f and "plain HTTP" in f[0].title


def test_weak_tls_hint_skips_https():
    f = list(rule_weak_tls_hint(_ctx(url="https://x.test/login")))
    assert f == []


def test_weak_tls_hint_skips_non_auth_paths():
    f = list(rule_weak_tls_hint(_ctx(url="http://x.test/about")))
    assert f == []


# ---------------- graphql-batching-hint ----------------


def test_graphql_batching_hint_flags_array_post():
    body = b'[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]'
    f = list(rule_graphql_batching_hint(_ctx(
        url="https://x.test/graphql", method="POST", status=200,
        req_headers=[("Content-Type", "application/json")],
        req_body=body,
    )))
    assert f
    assert "3 queries" in f[0].evidence


def test_graphql_batching_hint_skips_single_query():
    body = b'{"query":"{a}"}'
    f = list(rule_graphql_batching_hint(_ctx(
        url="https://x.test/graphql", method="POST", status=200,
        req_body=body,
    )))
    assert f == []


def test_graphql_batching_hint_skips_non_graphql_url():
    f = list(rule_graphql_batching_hint(_ctx(
        url="https://x.test/api", method="POST", status=200,
        req_body=b'[{"x":1},{"y":2}]',
    )))
    assert f == []


def test_graphql_batching_hint_skips_error_status():
    f = list(rule_graphql_batching_hint(_ctx(
        url="https://x.test/graphql", method="POST", status=400,
        req_body=b'[{"q":1},{"q":2}]',
    )))
    assert f == []


# ---------------- session-fixation ----------------


def test_session_fixation_flags_login_reissuing_same_session_cookie():
    f = list(rule_session_fixation(_ctx(
        url="https://x.test/login", method="POST", status=200,
        req_headers=[("Cookie", "PHPSESSID=preauth-abc")],
        resp_headers=[("Set-Cookie", "PHPSESSID=preauth-abc; Path=/")],
    )))
    assert f and "fixation" in f[0].title.lower()


def test_session_fixation_skips_when_request_had_no_session_cookie():
    f = list(rule_session_fixation(_ctx(
        url="https://x.test/login", method="POST", status=200,
        resp_headers=[("Set-Cookie", "PHPSESSID=new; Path=/")],
    )))
    assert f == []


def test_session_fixation_skips_when_non_login_path():
    f = list(rule_session_fixation(_ctx(
        url="https://x.test/profile", method="GET", status=200,
        req_headers=[("Cookie", "PHPSESSID=preauth")],
        resp_headers=[("Set-Cookie", "PHPSESSID=preauth; Path=/")],
    )))
    assert f == []


# ---------------- autocomplete-on-password ----------------


def test_autocomplete_on_password_flags_missing_attribute():
    body = (b"<html><form><input type=\"password\" name=\"pw\"></form></html>")
    f = list(rule_autocomplete_on_password(_ctx(
        resp_headers=[("Content-Type", "text/html; charset=utf-8")],
        resp_body=body,
    )))
    assert f and "autocomplete" in f[0].title.lower()


def test_autocomplete_on_password_skips_with_new_password():
    body = (b"<input type='password' autocomplete='new-password'>")
    f = list(rule_autocomplete_on_password(_ctx(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    )))
    assert f == []


def test_autocomplete_on_password_skips_non_html():
    body = b"<input type=password>"
    f = list(rule_autocomplete_on_password(_ctx(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    )))
    assert f == []


# ---------------- cache-control-on-private ----------------


def test_cache_control_on_private_flags_set_cookie_without_no_store():
    f = list(rule_cache_control_on_private(_ctx(
        resp_headers=[
            ("Set-Cookie", "session=abc; Path=/"),
            ("Cache-Control", "public, max-age=60"),
        ],
    )))
    assert f and "no-store" in f[0].title.lower()


def test_cache_control_on_private_passes_when_no_store_set():
    f = list(rule_cache_control_on_private(_ctx(
        resp_headers=[
            ("Set-Cookie", "session=abc; Path=/"),
            ("Cache-Control", "no-store, no-cache"),
        ],
    )))
    assert f == []


def test_cache_control_on_private_skips_without_set_cookie():
    f = list(rule_cache_control_on_private(_ctx(
        resp_headers=[("Cache-Control", "public, max-age=60")],
    )))
    assert f == []


# ---------------- open-redirect-hint-headers ----------------


def test_open_redirect_hint_headers_flags_host_in_location():
    f = list(rule_open_redirect_hint_headers(_ctx(
        url="https://x.test/r", status=302,
        req_headers=[("Host", "evil.attacker.test")],
        resp_headers=[("Location", "https://evil.attacker.test/next")],
    )))
    assert f and "request header" in f[0].title.lower()


def test_open_redirect_hint_headers_flags_x_forwarded_host():
    f = list(rule_open_redirect_hint_headers(_ctx(
        url="https://x.test/r", status=301,
        req_headers=[("X-Forwarded-Host", "attacker.example")],
        resp_headers=[("Location", "https://attacker.example/welcome")],
    )))
    assert f


def test_open_redirect_hint_headers_skips_2xx_responses():
    f = list(rule_open_redirect_hint_headers(_ctx(
        url="https://x.test/r", status=200,
        req_headers=[("Host", "evil.test")],
        resp_headers=[("Location", "https://evil.test/")],
    )))
    assert f == []


def test_open_redirect_hint_headers_skips_unrelated_location():
    f = list(rule_open_redirect_hint_headers(_ctx(
        url="https://x.test/r", status=302,
        req_headers=[("Host", "evil.test")],
        resp_headers=[("Location", "https://other.test/")],
    )))
    assert f == []


# ---------------- registration ----------------


def test_all_b1_rules_registered_in_builtin():
    """Every new rule must be wired into BUILTIN_RULES so the engine sees it."""
    for rule in (
        rule_cors_null_origin, rule_cors_reflected_origin,
        rule_weak_tls_hint, rule_graphql_batching_hint,
        rule_session_fixation, rule_autocomplete_on_password,
        rule_cache_control_on_private, rule_open_redirect_hint_headers,
    ):
        assert rule in BUILTIN_RULES, f"{rule.__name__} missing from BUILTIN_RULES"
