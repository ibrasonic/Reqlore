"""Param-miner — find hidden query / body / header parameters.

For a given URL the miner takes a wordlist (a built-in 200-word list ships
with the package; users can extend it), generates probe requests where each
candidate parameter is added with a unique sentinel value, sends them through
a caller-supplied ``sender`` (defaults to httpx_engine), and reports any
parameter whose presence visibly changes the response — different status,
different body length beyond a tolerance band, or the sentinel reflected in
the response body.

This is the classic Burp "param miner" workflow. We use simple difference
detection rather than backslash-canary tricks so the algorithm is auditable.

Module is offline-safe: a ``send=`` callable can be injected by tests.
"""
from __future__ import annotations

import secrets
import time
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .engines import Request, Response, httpx_engine


# ---- options & results ----

@dataclass
class MineOptions:
    location: str = "query"          # "query" | "body" | "header"
    method: str = "GET"
    timeout_s: float = 10.0
    follow_redirects: bool = False
    max_words: int = 200             # safety cap
    rate_delay_ms: int = 0
    length_tolerance: int = 16       # bytes of diff considered "noise"
    sentinel_prefix: str = "wlpm_"   # hex token gets appended


@dataclass
class HiddenParam:
    name: str
    location: str
    evidence: str
    baseline_status: int
    probe_status: int
    baseline_len: int
    probe_len: int


@dataclass
class MineResult:
    url: str
    location: str
    tried: int = 0
    found: list[HiddenParam] = field(default_factory=list)
    elapsed_ms: int = 0


# ---- built-in wordlist ----

# Curated short list of params seen in CTFs / bug bounties; readers can extend
# via ``mine(..., words=[...])``.
DEFAULT_WORDS: tuple[str, ...] = (
    "admin", "debug", "test", "dev", "trace", "verbose", "pretty",
    "format", "callback", "jsonp", "redirect", "redirect_uri", "redir",
    "next", "return", "return_url", "returnUrl", "url", "u", "uri",
    "target", "dest", "destination", "continue", "ref", "referer",
    "page", "p", "id", "uid", "user", "username", "name", "email",
    "token", "auth", "key", "api_key", "apikey", "session", "sid",
    "csrf", "_csrf", "xsrf", "captcha", "code", "challenge", "state",
    "lang", "locale", "language", "country", "region", "tz", "timezone",
    "limit", "offset", "page_size", "size", "count", "max", "min",
    "sort", "order", "filter", "q", "query", "search", "search_term",
    "file", "filename", "path", "dir", "folder", "download", "upload",
    "image", "img", "src", "data", "payload", "input", "value",
    "from", "to", "start", "end", "date", "ts", "time", "duration",
    "_method", "method", "action", "op", "operation", "command", "cmd",
    "exec", "run", "call", "service", "module", "plugin", "feature",
    "version", "v", "ver", "build", "release", "channel", "env",
    "host", "domain", "subdomain", "site", "tenant", "account",
    "org", "organization", "team", "group", "role", "permission",
    "scope", "level", "tier", "plan", "package", "type", "kind",
    "category", "tag", "label", "title", "description", "comment",
    "note", "message", "msg", "subject", "body", "content", "text",
    "html", "raw", "json", "xml", "yaml", "csv", "tsv", "format",
    "encoding", "charset", "lang_code", "locale_code",
    "preview", "draft", "publish", "publishing", "status", "state",
    "active", "enabled", "disabled", "visible", "hidden",
    "preview_token", "secret", "secret_key", "private", "public",
    "shared", "share_id", "guest", "anonymous",
    "step", "stage", "phase", "flow", "wizard",
    "src_ip", "client_ip", "x-forwarded-for", "real_ip",
    "user_agent", "ua", "device", "platform", "os",
    "browser", "screen", "width", "height", "dpr",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref_code", "promo", "discount", "coupon",
    "currency", "price", "amount", "total", "qty", "quantity",
    "cart", "order", "order_id", "checkout", "payment", "method_id",
    "shipping", "billing", "address", "city", "zip", "postcode",
)


def _hex_sentinel(prefix: str) -> str:
    return prefix + secrets.token_hex(4)


def _baseline_request(url: str, method: str) -> Request:
    return Request(method=method, url=url, headers=[], body=b"")


def _probe_request(url: str, method: str, location: str,
                   name: str, value: str) -> Request:
    if location == "query":
        pr = up.urlparse(url)
        pairs = up.parse_qsl(pr.query, keep_blank_values=True)
        pairs.append((name, value))
        return Request(method=method,
                       url=up.urlunparse(pr._replace(query=up.urlencode(pairs))),
                       headers=[], body=b"")
    if location == "body":
        body = up.urlencode([(name, value)]).encode("utf-8")
        return Request(method=method, url=url,
                       headers=[("Content-Type", "application/x-www-form-urlencoded")],
                       body=body)
    if location == "header":
        # Use a header name derived from the candidate (X-<Name>: <value>).
        h_name = "X-" + "".join(c if c.isalnum() else "-" for c in name)
        return Request(method=method, url=url, headers=[(h_name, value)], body=b"")
    raise ValueError(f"unknown location {location!r}")


def mine(url: str, *, words: Iterable[str] | None = None,
         options: MineOptions | None = None,
         send: Callable[[Request], Response] | None = None) -> MineResult:
    """Probe for hidden parameters at ``url`` and return a :class:`MineResult`."""
    opts = options or MineOptions()
    candidates = list(words) if words is not None else list(DEFAULT_WORDS)
    candidates = candidates[: opts.max_words]

    def _real_send(req: Request) -> Response:
        return httpx_engine.send(req, timeout=opts.timeout_s,
                                  follow_redirects=opts.follow_redirects)

    sender = send or _real_send

    t0 = time.monotonic()
    base_req = _baseline_request(url, opts.method)
    base_resp = sender(base_req)
    base_len = len(base_resp.body or b"")
    base_status = base_resp.status

    result = MineResult(url=url, location=opts.location)
    for word in candidates:
        result.tried += 1
        sentinel = _hex_sentinel(opts.sentinel_prefix)
        try:
            probe = _probe_request(url, opts.method, opts.location, word, sentinel)
            resp = sender(probe)
        except Exception as exc:  # pragma: no cover -- defensive
            result.found.append(HiddenParam(
                name=word, location=opts.location,
                evidence=f"probe raised: {type(exc).__name__}",
                baseline_status=base_status, probe_status=0,
                baseline_len=base_len, probe_len=0,
            ))
            continue
        probe_body = resp.body or b""
        probe_len = len(probe_body)
        evidence = ""
        if sentinel.encode() in probe_body:
            evidence = "sentinel reflected in response body"
        elif resp.status != base_status:
            evidence = f"status differs: baseline {base_status} vs probe {resp.status}"
        elif abs(probe_len - base_len) > opts.length_tolerance:
            evidence = (f"body length differs by {probe_len - base_len} bytes "
                        f"(tolerance {opts.length_tolerance})")
        if evidence:
            result.found.append(HiddenParam(
                name=word, location=opts.location, evidence=evidence,
                baseline_status=base_status, probe_status=resp.status,
                baseline_len=base_len, probe_len=probe_len,
            ))
        if opts.rate_delay_ms:
            time.sleep(opts.rate_delay_ms / 1000.0)
    result.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return result
