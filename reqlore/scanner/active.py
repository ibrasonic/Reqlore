"""Active scanner — sends mutated requests and looks for evidence.

Unlike :mod:`reqlore.scanner.passive`, active checks **issue HTTP traffic**.
They are off by default; users opt in per scan and per check class.

Design rules:
    * one base class :class:`ActiveCheck`; subclasses implement ``run``
    * a check returns a list of :class:`Finding`; never raises
    * checks share a httpx-based sender (and respect a per-scan rate limit)
    * payloads are minimal "marker" probes — not weaponised exploits
    * results funnel into the same :class:`Finding` model the passive scanner uses

Public surface::

    from reqlore.scanner.active import (
        ActiveCheck, ActiveScanner, BUILTIN_ACTIVE_CHECKS, ActiveOptions,
    )

    scanner = ActiveScanner()
    findings = scanner.run_on_row(row, options=ActiveOptions())
"""
from __future__ import annotations

import base64
import contextlib
import json
import secrets
import ssl
import time
import urllib.parse as up
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..engines import Request, Response, httpx_engine
from .findings import Finding, Severity
from .passive import _split_http  # reuse
from .rules import RuleMeta

# Exceptions the active scanner is allowed to swallow into an info-finding.
# Anything else propagates so real bugs surface.
_SAFE_NETWORK_EXC = (httpx.HTTPError, ssl.SSLError, OSError, ValueError)


# B.0.8 SQLi signatures, keyed by engine so detections record *which*.
_SQL_ERROR_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "mysql": (
        b"You have an error in your SQL syntax",
        b"MySQL server version for the right syntax",
        b"Warning: mysql_",
        b"MySQLSyntaxErrorException",
    ),
    "mariadb": (
        b"check the manual that corresponds to your MariaDB",
    ),
    "postgres": (
        b"PostgreSQL query failed",
        b"PG::SyntaxError",
        b"org.postgresql.util.PSQLException",
        b"pq: syntax error at or near",
    ),
    "mssql": (
        b"Microsoft OLE DB Provider",
        b"Unclosed quotation mark after the character string",
        b"Incorrect syntax near",
        b"System.Data.SqlClient.SqlException",
    ),
    "oracle": (
        b"ORA-00933", b"ORA-00921", b"ORA-01756", b"ORA-00936",
        b"quoted string not properly terminated",
    ),
    "sqlite": (
        b"SQLite3::SQLException",
        b"sqlite3.OperationalError",
        b"unrecognized token",
    ),
    "db2": (
        b"DB2 SQL error", b"SQLCODE=-",
    ),
    "mongo": (
        b"MongoError", b"BSONError",
    ),
    "snowflake": (
        b"Snowflake.Data.Client.SnowflakeDbException",
    ),
}


def _detect_sql_engine(body: bytes) -> tuple[str, bytes] | None:
    """Return (engine, matching_signature) or None."""
    for engine, sigs in _SQL_ERROR_SIGNATURES.items():
        for sig in sigs:
            if sig in body:
                return engine, sig
    return None


# ---- options ----

@dataclass
class ActiveOptions:
    """Per-scan policy. Defaults are conservative."""
    # Back-compat: total cap per (check, row) — left in place but no longer the
    # only gate. Use ``max_probes_per_check`` for the global cap below.
    max_requests_per_check: int = 4
    # B.0.1 finer-grained budgets:
    max_probes_per_target: int = 4   # per (rule_id, location, parameter)
    max_probes_per_check: int = 32   # per (rule_id, row)
    rate_delay_ms: int = 0
    timeout_s: float = 10.0
    follow_redirects: bool = False
    enabled_checks: list[str] | None = None  # None == all built-ins
    oast: object | None = None        # LocalOAST instance for OOB checks
    oast_wait_s: float = 0.6          # how long to poll OAST after a probe
    # B.0.3 CSRF/session refresh hook.
    replay_macro: Callable[[Any], dict[str, str]] | None = None
    replay_every_n_probes: int = 0    # 0 disables refresh
    # B.0.4 Rate-limit awareness.
    retry_after_default_s: float = 5.0
    # Phase 1b — opt-in network-heavy probes. Off by default because they
    # bypass the standard httpx engine (smuggling needs raw socket bytes;
    # the field-suggestion probe sends a deliberately broken query).
    allow_smuggling_probes: bool = False
    # Phase 2 — opt-in credential-spray probe. Off by default because
    # sending login attempts to a real production system is a noisy and
    # potentially account-locking action.
    allow_credential_probes: bool = False
    # Phase 3 — opt-in race-condition probe (parallel state-changing
    # requests). Off by default; can create duplicate resources.
    allow_race_probes: bool = False
    # Phase 3 — second identity for IDOR. Dict of header name -> value
    # to swap/add when re-sending each baseline (e.g. an alternate
    # session cookie). None disables the IDOR check.
    alt_identity: dict[str, str] | None = None
    # Phase 4 — opt-in DOM XSS probe via Playwright. Off by default
    # because it spins up a headless browser per probe, which is
    # slow and pulls in a heavy optional dep.
    allow_dom_xss_probes: bool = False
    # Phase 2 (Burp-parity plan) — coarse intensity filter that runs
    # *in addition to* ``enabled_checks``. When ``enabled_checks`` is
    # set, it wins (explicit selection bypasses intensity). When it is
    # ``None``, each check is gated by its
    # ``RuleMeta.intensity`` membership in this set. ``"intrusive"``
    # is opt-in by default; the route layer additionally requires an
    # explicit confirm form field before constructing an
    # ``ActiveOptions`` with it.
    intensity_levels: frozenset[str] = field(
        default_factory=lambda: frozenset({"light", "medium"})
    )
    # Phase 5 — per-row insertion-point cap. The unified insertion-point
    # engine (``reqlore.scanner.insertion_points``) yields one
    # :class:`InsertionPoint` per mutable position in a request; the
    # cap below prevents pathological corpora (10k JSON keys, 500
    # cookies) from exploding the probe budget. Enforced by
    # :class:`InsertionPointCache` rather than at iteration time so
    # callers can still ``len()`` the full list for dry-run estimates.
    max_insertion_points_per_row: int = 200
    # Phase 9 — global wall-clock cap on a ``run_on_project`` call,
    # in seconds. ``None`` disables the cap (used by the ``deep``
    # preset). Enforced between rows so a long-running row finishes
    # cleanly rather than being torn down mid-probe.
    wall_clock_seconds: float | None = None
    # Phase 10 — authenticated-scan session manager. When set, the
    # send factory injects session cookies + bearer headers into
    # every outgoing probe, harvests rotated cookies from each
    # response, periodically validity-probes the session, and
    # re-runs the login macro on expiry. Typed as ``Any`` to avoid
    # importing :mod:`reqlore.scanner.auth_session` here — that
    # module imports from :mod:`reqlore.engines` which in turn
    # pulls active.py back transitively in some test paths.
    auth_session: Any | None = None
    # Phase 12 — Burp-style audit prioritisation. When ``True`` the
    # ``run_on_project`` loop iterates rows in attack-surface order
    # (rows that introduce the most novel insertion points + the
    # most "interesting" methods / content types / auth requirements
    # go first) instead of raw id-DESC. Off by default so existing
    # tests keep their FIFO assumptions. ``surface_weight`` and
    # ``interest_weight`` blend the two axes (Burp's 80/20 split).
    prioritise: bool = False
    surface_weight: float = 0.8
    interest_weight: float = 0.2
    # Phase 12 — when ``prioritise=True``, recompute scores after
    # each picked row so a row whose surface is consumed by an
    # earlier pick drops in rank. O(n^2) — leave off for large
    # corpora (cap N at ~50 for the incremental mode).
    prioritise_recompute_after_row: bool = False
    # Phase 13 — JavaScript analysis pipeline gate. Normally set by
    # the scan preset (Phase 9); see
    # :mod:`reqlore.scanner.js_pipeline` for the mode semantics.
    # ``"off"`` keeps the historical behaviour (JS analysers must
    # be invoked manually) so every existing call-site is
    # unaffected.
    js_analysis_mode: str = "off"

    def __post_init__(self) -> None:
        # Validate the intensity set so a typo (e.g. ``"intense"``)
        # surfaces immediately instead of silently skipping every
        # check. Cast to frozenset so callers can pass any iterable.
        from .rules import INTENSITIES
        levels = frozenset(self.intensity_levels)
        bad = levels - set(INTENSITIES)
        if bad:
            raise ValueError(
                f"ActiveOptions.intensity_levels contains unknown "
                f"tier(s) {sorted(bad)!r}; valid: {INTENSITIES}"
            )
        if not levels:
            raise ValueError(
                "ActiveOptions.intensity_levels must contain at "
                "least one tier; got empty set"
            )
        object.__setattr__(self, "intensity_levels", levels)
        # Phase 12 — weight validation. We catch the obvious mistakes
        # (negatives, both-zero) here rather than at run_on_project
        # time so a misconfigured options object can't ship a scan
        # that produces an undefined ordering.
        if self.surface_weight < 0 or self.interest_weight < 0:
            raise ValueError(
                "ActiveOptions surface_weight / interest_weight must "
                "be non-negative; got "
                f"surface={self.surface_weight}, "
                f"interest={self.interest_weight}"
            )
        if (self.prioritise
                and self.surface_weight == 0
                and self.interest_weight == 0):
            raise ValueError(
                "ActiveOptions.prioritise=True requires at least one "
                "of surface_weight / interest_weight to be > 0"
            )
        # Phase 13 — validate the JS-analysis mode. Unknown values
        # are rejected loudly here rather than silently no-op'd at
        # scan time, mirroring the intensity-tiers validator above.
        from .js_pipeline import JS_ANALYSIS_MODES
        mode = (self.js_analysis_mode or "").strip().lower()
        if mode not in JS_ANALYSIS_MODES:
            raise ValueError(
                "ActiveOptions.js_analysis_mode must be one of "
                f"{JS_ANALYSIS_MODES!r}; got {self.js_analysis_mode!r}"
            )
        object.__setattr__(self, "js_analysis_mode", mode)


# ---- context: parsed snapshot of a recorded history row ----

@dataclass
class ActiveContext:
    history_id: int
    host: str
    base_url: str            # without query string
    full_url: str            # with query string
    method: str
    req_headers: list[tuple[str, str]] = field(default_factory=list)
    req_body: bytes = b""
    resp_status: int = 0
    resp_headers: list[tuple[str, str]] = field(default_factory=list)
    resp_body: bytes = b""
    # B.0.1+2 per-target budget tracking and per-row probe audit trail.
    probes_per_target: dict[tuple[str, str, str], int] = field(default_factory=dict)
    probes_per_check: dict[str, int] = field(default_factory=dict)
    probes_log: list[tuple] = field(default_factory=list)  # (rule, loc, key, payload, status, ms)
    # B.4 reproduction: the most recently sent probe, serialized to raw bytes
    # so the runner can attach it as `reproduction=...` to record_finding.
    # Tuple shape matches findings_bus.Reproduction:
    #   (request_blob, response_blob, method, url, status, elapsed_ms)
    last_probe_repro: tuple | None = None

    def claim_probe(self, opts: ActiveOptions, rule_id: str,
                     location: str, key: str) -> bool:
        """Reserve a probe slot. Returns True if allowed."""
        per_target = self.probes_per_target.get((rule_id, location, key), 0)
        per_check = self.probes_per_check.get(rule_id, 0)
        if per_target >= opts.max_probes_per_target:
            return False
        if per_check >= opts.max_probes_per_check:
            return False
        self.probes_per_target[(rule_id, location, key)] = per_target + 1
        self.probes_per_check[rule_id] = per_check + 1
        return True

    def probes_for(self, rule_id: str) -> int:
        return self.probes_per_check.get(rule_id, 0)

    @classmethod
    def from_row(cls, row) -> ActiveContext:
        rs, rh, rb = _split_http(row.req_blob)
        ss, sh, sb = _split_http(row.resp_blob)
        base = row.url.split("?", 1)[0]
        return cls(
            history_id=row.id, host=row.host,
            base_url=base, full_url=row.url, method=row.method,
            req_headers=rh, req_body=rb,
            resp_status=row.status, resp_headers=sh, resp_body=sb,
        )

    def query_pairs(self) -> list[tuple[str, str]]:
        parts = self.full_url.split("?", 1)
        if len(parts) < 2:
            return []
        out: list[tuple[str, str]] = []
        for p in parts[1].split("&"):
            if not p:
                continue
            k, _, v = p.partition("=")
            out.append((k, v))
        return out

    def form_pairs(self) -> list[tuple[str, str]]:
        """Best-effort form parsing for application/x-www-form-urlencoded bodies."""
        ct = ""
        for k, v in self.req_headers:
            if k.lower() == "content-type":
                ct = v.lower()
        if "x-www-form-urlencoded" not in ct or not self.req_body:
            return []
        try:
            text = self.req_body.decode("utf-8", errors="replace")
        except Exception:
            return []
        out: list[tuple[str, str]] = []
        for p in text.split("&"):
            if not p:
                continue
            k, _, v = p.partition("=")
            out.append((k, v))
        return out


# ---- check base ----

@dataclass
class ProbeResult:
    request: Request
    response: Response
    elapsed_ms: int


class ActiveCheck:
    """Each subclass implements ``run(ctx, send)`` and returns Findings."""
    name: str = ""
    description: str = ""

    def run(self, ctx: ActiveContext,
             send: Callable[[Request], ProbeResult],
             *, opts: ActiveOptions | None = None) -> Iterable[Finding]:
        raise NotImplementedError


def _scrub_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Remove headers that httpx (or the recorded session) should re-derive."""
    drop = {"host", "content-length", "transfer-encoding", "connection"}
    return [(k, v) for k, v in headers if k.lower() not in drop]


def _replace_query_value(url: str, key: str, new: str) -> str:
    pr = up.urlparse(url)
    pairs = up.parse_qsl(pr.query, keep_blank_values=True)
    out = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, new))
            replaced = True
        else:
            out.append((k, v))
    return up.urlunparse(pr._replace(query=up.urlencode(out, doseq=True)))


def _replace_form_value(body: bytes, key: str, new: str) -> bytes:
    """Replace a form field's value, preserving the original encoding of
    every chunk we did **not** touch.

    Round-tripping through :func:`parse_qsl` + :func:`urlencode` loses fine
    distinctions (`+` vs `%20`, casing of `%2f`, etc.) and can change the body
    of any field that already used a specific encoding — that in turn shifts
    response signatures and produces false-negatives. We operate on the raw
    ``&``-separated chunks and only re-encode the target value.
    """
    if not body:
        return up.urlencode([(key, new)]).encode("utf-8")
    new_bytes = up.quote_from_bytes(new.encode("utf-8"), safe="").encode("ascii")
    key_b = up.quote_from_bytes(key.encode("utf-8"), safe="").encode("ascii")
    chunks = body.split(b"&")
    replaced = False
    out_chunks: list[bytes] = []
    for chunk in chunks:
        if replaced or not chunk:
            out_chunks.append(chunk)
            continue
        kpart, sep, _ = chunk.partition(b"=")
        # Decode the key once to compare; the value stays untouched if no match.
        try:
            decoded_key = up.unquote_to_bytes(kpart).decode("utf-8")
        except UnicodeDecodeError:
            decoded_key = kpart.decode("latin-1", errors="replace")
        if decoded_key == key:
            out_chunks.append(key_b + b"=" + new_bytes if sep else key_b)
            replaced = True
        else:
            out_chunks.append(chunk)
    if not replaced:
        out_chunks.append(key_b + b"=" + new_bytes)
    return b"&".join(out_chunks)


def _mutated(ctx: ActiveContext, key: str, new_val: str,
              location: str) -> Request:
    headers = _scrub_headers(ctx.req_headers)
    if location == "query":
        url = _replace_query_value(ctx.full_url, key, new_val)
        body = ctx.req_body
    elif location == "form":
        url = ctx.full_url
        body = _replace_form_value(ctx.req_body, key, new_val)
    else:
        raise ValueError(f"unknown location {location}")
    return Request(
        method=ctx.method, url=url, headers=headers, body=body,
    )


def _baseline(ctx: ActiveContext) -> Request:
    return Request(
        method=ctx.method, url=ctx.full_url,
        headers=_scrub_headers(ctx.req_headers), body=ctx.req_body,
    )


# B.2 helpers — header / cookie mutation and JSON-field swap.

def _replace_header_value(headers: list[tuple[str, str]], name: str, new: str,
                           ) -> list[tuple[str, str]]:
    """Replace the first occurrence of `name` (case-insensitive); append if absent."""
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in headers:
        if not replaced and k.lower() == name.lower():
            out.append((k, new))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, new))
    return out


def _mutated_header(ctx: ActiveContext, name: str, new_val: str) -> Request:
    headers = _replace_header_value(_scrub_headers(ctx.req_headers), name, new_val)
    return Request(
        method=ctx.method, url=ctx.full_url, headers=headers, body=ctx.req_body,
    )


def _cookie_pairs(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Parse the first `Cookie:` header into (name, value) pairs."""
    for k, v in headers:
        if k.lower() == "cookie":
            out: list[tuple[str, str]] = []
            for piece in v.split(";"):
                piece = piece.strip()
                if not piece:
                    continue
                if "=" in piece:
                    nm, vl = piece.split("=", 1)
                    out.append((nm.strip(), vl.strip()))
                else:
                    out.append((piece, ""))
            return out
    return []


def _replace_cookie_value(cookie_hdr: str, name: str, new: str) -> str:
    """Replace one cookie's value in a `Cookie:` header string."""
    parts = [p.strip() for p in cookie_hdr.split(";") if p.strip()]
    out: list[str] = []
    replaced = False
    for p in parts:
        if not replaced and "=" in p:
            kn, _ = p.split("=", 1)
            if kn.strip() == name:
                out.append(f"{kn.strip()}={new}")
                replaced = True
                continue
        out.append(p)
    return "; ".join(out)


def _mutated_cookie(ctx: ActiveContext, name: str, new_val: str) -> Request:
    headers = _scrub_headers(ctx.req_headers)
    new_headers: list[tuple[str, str]] = []
    for k, v in headers:
        if k.lower() == "cookie":
            new_headers.append((k, _replace_cookie_value(v, name, new_val)))
        else:
            new_headers.append((k, v))
    return Request(
        method=ctx.method, url=ctx.full_url, headers=new_headers, body=ctx.req_body,
    )


# B.4 — serialize a Request / Response back to raw HTTP/1.1 bytes so the
# scanner can store a byte-for-byte reproducer alongside each finding.

def _request_to_raw(req: Request) -> bytes:
    parsed = up.urlparse(req.url)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    lines = [f"{req.method} {path} HTTP/1.1"]
    have_host = any(k.lower() == "host" for k, _ in req.headers)
    if not have_host and parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    for k, v in req.headers:
        lines.append(f"{k}: {v}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")
    return head + (req.body or b"")


def _response_to_raw(resp: Response) -> bytes:
    reason = resp.reason or {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 303: "See Other",
        304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
        500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
    }.get(resp.status, "")
    status_line = f"HTTP/1.1 {resp.status} {reason}".rstrip()
    lines = [status_line]
    for k, v in resp.headers:
        lines.append(f"{k}: {v}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")
    return head + (resp.body or b"")


# ---- Phase 19 helpers — timing statistics + CSRF token discovery ----

def _median(values: list[int]) -> int:
    """Median of a list of integers (millisecond samples). 0 for empty."""
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) // 2


def _mad(values: list[int], centre: int) -> int:
    """Median Absolute Deviation around `centre`. 0 for empty."""
    if not values:
        return 0
    return _median([abs(v - centre) for v in values])


def _is_timing_anomaly(baseline_samples: list[int],
                        probe_samples: list[int],
                        *, mad_mult: float = 3.0,
                        min_delta_ms: int = 50) -> bool:
    """Robust two-sample timing comparison.

    Probe median must exceed baseline median by more than ``mad_mult ×
    MAD(baseline)`` AND by at least ``min_delta_ms``. The floor stops
    zero-variance baselines (MAD = 0) from flagging on noise-level jitter.
    """
    if len(baseline_samples) < 2 or len(probe_samples) < 2:
        return False
    base_med = _median(baseline_samples)
    probe_med = _median(probe_samples)
    delta = probe_med - base_med
    if delta < min_delta_ms:
        return False
    base_mad = _mad(baseline_samples, base_med)
    threshold = max(int(mad_mult * base_mad), min_delta_ms)
    return delta > threshold


# CSRF token discovery — names common to Rails / Django / Laravel /
# Spring / generic frameworks. Case-insensitive match.
_CSRF_PARAM_NAMES: frozenset[str] = frozenset({
    "csrf_token", "_token", "authenticity_token", "csrf",
    "_csrf", "_csrf_token", "xsrf", "xsrf_token",
    "csrfmiddlewaretoken",
})
_CSRF_HEADER_NAMES: frozenset[str] = frozenset({
    "x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token",
})


def _find_csrf_token(ctx: ActiveContext) -> tuple[str, str, str] | None:
    """Return ``(location, key, value)`` of a CSRF token, or ``None``.

    Locations: ``"form"``, ``"query"``, ``"header"``. Cookies are
    intentionally excluded — a cookie-only token is part of the
    double-submit pattern and removing it from the request body does
    not exercise the server-side validation we are probing.
    """
    for key, val in ctx.form_pairs():
        if key.lower() in _CSRF_PARAM_NAMES:
            return ("form", key, val)
    for key, val in ctx.query_pairs():
        if key.lower() in _CSRF_PARAM_NAMES:
            return ("query", key, val)
    for k, v in ctx.req_headers:
        if k.lower() in _CSRF_HEADER_NAMES:
            return ("header", k, v)
    return None


# Username-shaped field names for the account-enumeration heuristic.
_USERNAME_PARAM_NAMES: frozenset[str] = frozenset({
    "username", "user", "email", "login", "userid", "user_id",
    "j_username", "acct", "account",
})


def _find_username_field(ctx: ActiveContext) -> tuple[str, str, str] | None:
    """Return ``(location, key, value)`` of a likely username field, or ``None``."""
    for key, val in ctx.form_pairs():
        if key.lower() in _USERNAME_PARAM_NAMES:
            return ("form", key, val)
    for key, val in ctx.query_pairs():
        if key.lower() in _USERNAME_PARAM_NAMES:
            return ("query", key, val)
    return None


# ---- individual checks ----

class ReflectedXSSCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:xss-reflected",
        intensity="medium",
        title="Reflected XSS probe echoed unescaped",
        default_severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "Replace each query/form value with a marker probe; flag any "
            "response that contains the probe verbatim."
        ),
        remediation=(
            "HTML-encode the value on output, or use a templating engine "
            "that auto-escapes by default."
        ),
        tags=("xss", "injection"),
    )
    name = "xss-reflected"
    description = ("Replace each query / form value with a marker probe and "
                   "check whether the probe appears unescaped in the response.")

    PROBE_TPL = '"\'><wbr-{m}>'

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(4)
                probe = self.PROBE_TPL.format(m=marker)
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                if pr.response.status == 0:
                    continue
                body = pr.response.body
                if probe.encode() in body:
                    yield Finding(
                        severity="high", title="Reflected XSS probe echoed unescaped",
                        description=(
                            f"A marker payload sent in the '{key}' {loc} parameter "
                            "appears verbatim in the response body, which "
                            "indicates the input is not HTML-encoded. An "
                            "attacker could turn this into a stored or "
                            "reflected cross-site-scripting attack."
                        ),
                        remediation=("HTML-encode the value on output, or use a "
                                     "templating engine that auto-escapes."),
                        cwe="CWE-79", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe, evidence=f"{loc} param '{key}' echoed",
                    )


class SQLiErrorCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:sqli-error",
        intensity="medium",
        title="SQL injection error message returned",
        default_severity="high",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        description=(
            "Append a single quote to each parameter and look for vendor "
            "SQL error signatures in the response."
        ),
        remediation=(
            "Use parameterised queries / prepared statements; never "
            "concatenate user input into SQL."
        ),
        tags=("sqli", "injection"),
    )
    name = "sqli-error"
    description = ("Append a single quote to each parameter and look for "
                   "database error signatures in the response.")

    @property
    def ERROR_SIGS(self) -> tuple[bytes, ...]:
        # Kept as a flat view for back-compat with existing tests.
        return tuple(sig for sigs in _SQL_ERROR_SIGNATURES.values() for sig in sigs)

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                probe = (val or "1") + "'"
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                body = pr.response.body[:65_536]
                hit = _detect_sql_engine(body)
                if hit is not None:
                    engine, sig = hit
                    yield Finding(
                        severity="high",
                        title=f"SQL error triggered by quote injection ({engine})",
                        description=(f"Appending a single quote to the '{key}' "
                                     f"{loc} parameter produced a {engine} database "
                                     "error in the response. This is a strong "
                                     "indicator of SQL injection."),
                        remediation=("Use parameterised queries / prepared "
                                     "statements. Never concatenate user "
                                     "input into SQL text."),
                        cwe="CWE-89", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence=f"{engine}: {sig.decode('latin-1', errors='replace')}",
                    )


class OpenRedirectCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:open-redirect",
        intensity="light",
        title="Open redirect via parameter",
        default_severity="medium",
        cwe="CWE-601",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Replace URL-shaped parameters with an attacker-controlled "
            "value and check the response Location header."
        ),
        remediation=(
            "Validate the redirect target against a server-side allowlist."
        ),
        tags=("redirect",),
    )
    name = "open-redirect"
    description = ("Replace URL-shaped parameters with an attacker-controlled "
                   "host and confirm the server issues a 3xx Location to it.")
    PROBE = "https://reqlore-redir.invalid/"

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if not val:
                    continue
                if not (val.startswith("http://") or val.startswith("https://")
                        or val.startswith("/")):
                    continue
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                req = _mutated(ctx, key, self.PROBE, loc)
                pr = send(req)
                if 300 <= pr.response.status < 400:
                    loc_h = pr.response.header("Location") or ""
                    if self.PROBE.rstrip("/") in loc_h:
                        yield Finding(
                            severity="medium", title="Open redirect confirmed",
                            description=(f"The '{key}' {loc} parameter controls the "
                                         "redirect Location. An attacker can "
                                         "send users to any site they choose "
                                         "via a trusted link."
                                         ),
                            remediation=("Validate redirect targets against a "
                                         "server-side allowlist."),
                            cwe="CWE-601", owasp="A01:2021-Broken Access Control",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=self.PROBE,
                            evidence=f"Location: {loc_h}",
                        )


class SSTICheck(ActiveCheck):
    meta = RuleMeta(
        id="active:ssti",
        intensity="medium",
        title="Server-side template injection",
        default_severity="high",
        cwe="CWE-1336",
        owasp="A03:2021-Injection",
        description=(
            "Inject template-engine probes (e.g. {{7*7}}) and look for the "
            "evaluated result in the response."
        ),
        remediation=(
            "Never render user-controlled strings as template source; pass "
            "untrusted values through the template's safe-context API."
        ),
        tags=("ssti", "injection"),
    )
    name = "ssti"
    description = ("Inject template-engine probes (e.g. {{7*7}}) and look for "
                   "the evaluated result in the response.")
    # B.0.10 — per-engine probes so the finding records which engine fired.
    PROBES: tuple[tuple[str, str, str], ...] = (
        ("jinja",   "{{7*7}}",     "49"),
        ("twig",    "{{7*'7'}}",   "7777777"),
        ("smarty",  "{$7*7}",       "49"),
        ("velocity", "#set($x=7*7)$x", "49"),
        ("erb",     "<%= 7*7 %>",  "49"),
        ("mustache", "${7*7}",     "49"),
        ("razor",    "#{7*7}",     "49"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for engine, probe, expected in self.PROBES:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    req = _mutated(ctx, key, probe, loc)
                    pr = send(req)
                    # avoid the case where the literal already existed
                    if (expected.encode() in pr.response.body[:200_000]
                            and expected.encode() not in ctx.resp_body[:200_000]):
                        yield Finding(
                            severity="critical",
                            title=f"SSTI: template expression evaluated ({engine})",
                            description=(
                                f"The '{key}' {loc} parameter was rendered by a "
                                f"{engine} template engine. The probe '{probe}' "
                                f"evaluated to {expected}. Server-side template "
                                "injection typically allows remote code "
                                "execution."
                            ),
                            remediation=("Never render untrusted input as a "
                                         "template. Use safe rendering APIs "
                                         "that treat input as plain text."),
                            cwe="CWE-1336", owasp="A03:2021-Injection",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=probe,
                            evidence=f"{engine} output contains {expected}",
                        )
                        return


class TimeBasedOSCommandCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:os-cmd-time",
        intensity="intrusive",
        title="OS command injection (time-based)",
        default_severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        description=(
            "Send a sleep-style payload and confirm the response is delayed "
            "by approximately the requested duration."
        ),
        remediation=(
            "Never pass user input to OS shell invocations; if shell-out is "
            "required, use argv lists and escape every variable."
        ),
        tags=("rce", "injection"),
    )
    name = "os-cmd-time"
    description = ("Send a sleep-style payload and confirm the response is "
                   "delayed by roughly the requested duration.")
    DELAY_S = 5
    # B.0.9 — cover bash/sh, Windows ping, IFS bypass, sub-shells.
    PROBES: tuple[tuple[str, str], ...] = (
        ("bash-semicolon", f";sleep {DELAY_S};"),
        ("sh-pipe",        f"|sleep {DELAY_S}"),
        ("sh-and",         f"&&sleep {DELAY_S}"),
        ("sub-shell",      f"$(sleep {DELAY_S})"),
        ("backticks",      f"`sleep {DELAY_S}`"),
        ("ifs-bypass",     f";sleep${{IFS}}{DELAY_S};"),
        ("windows-ping",   f"&& ping -n {DELAY_S + 1} 127.0.0.1"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        # Baseline: how long does the unmodified request take?
        baseline = send(_baseline(ctx))
        base_ms = baseline.elapsed_ms
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                kind, suffix = self.PROBES[0]
                probe = (val or "") + suffix
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                # Allow some slack: 0.7 × DELAY × 1000 ms above baseline.
                if pr.elapsed_ms - base_ms > int(self.DELAY_S * 0.7 * 1000):
                    yield Finding(
                        severity="critical",
                        title=f"Time-based OS command injection ({kind})",
                        description=(f"Appending a sleep payload to the '{key}' {loc} "
                                     f"parameter made the response take {pr.elapsed_ms} ms "
                                     f"(baseline {base_ms} ms). This delay strongly "
                                     "suggests the input is being executed as a "
                                     "shell command."),
                        remediation=("Never pass user input to a shell. Use the "
                                     "subprocess argv form with no shell, and "
                                     "validate input against a strict allowlist."),
                        cwe="CWE-78", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence=f"{kind}: baseline {base_ms} ms vs probe {pr.elapsed_ms} ms",
                    )


class JWTAlgNoneAcceptanceCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:jwt-alg-none",
        intensity="light",
        title="Server accepts JWT with alg=none",
        default_severity="critical",
        cwe="CWE-347",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "Re-send a Bearer JWT with alg=none and an emptied signature; "
            "flag any response that does not reject the forgery."
        ),
        remediation=(
            "Reject 'alg=none' on the server and pin the expected algorithm "
            "explicitly during verification."
        ),
        tags=("jwt", "auth", "crypto"),
    )
    name = "jwt-alg-none"
    description = ("If the request carries a Bearer JWT, re-send the same "
                   "request with the token replaced by an alg=none variant "
                   "and check whether the server still accepts it.")

    def run(self, ctx, send):
        auth = None
        for k, v in ctx.req_headers:
            if k.lower() == "authorization":
                auth = v
                break
        if not auth or not auth.lower().startswith("bearer "):
            return
        original = auth.split(" ", 1)[1].strip()
        parts = original.split(".")
        if len(parts) != 3:
            return
        # Build alg=none variant preserving the original payload
        header = {"alg": "none", "typ": "JWT"}
        payload_b = parts[1]
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        forged = f"{new_header}.{payload_b}."
        # Send the original first so we have a comparable baseline.
        baseline = send(_baseline(ctx))
        new_headers = [(k, v) for k, v in _scrub_headers(ctx.req_headers)
                       if k.lower() != "authorization"]
        new_headers.append(("Authorization", f"Bearer {forged}"))
        req = Request(method=ctx.method, url=ctx.full_url,
                      headers=new_headers, body=ctx.req_body)
        pr = send(req)
        if (200 <= pr.response.status < 300
                and 200 <= baseline.response.status < 300):
            yield Finding(
                severity="critical", title="JWT alg=none accepted by server",
                description=("The server returned a successful response for a "
                             "JWT whose alg was set to 'none' (no signature). "
                             "Anyone who knows or guesses a payload can mint "
                             "valid tokens."),
                remediation=("Reject alg=none on the server. Pin the expected "
                             "algorithm explicitly when verifying tokens."),
                cwe="CWE-347", owasp="A07:2021-Identification and Authentication Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=forged,
                evidence=(f"baseline status {baseline.response.status} -> "
                          f"alg=none status {pr.response.status}"),
            )


class PrototypePollutionCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:prototype-pollution",
        intensity="light",
        title="Prototype pollution via JSON body",
        default_severity="high",
        cwe="CWE-1321",
        owasp="A08:2021-Software and Data Integrity Failures",
        description=(
            "Append a polluting property (__proto__/constructor.prototype) "
            "to a JSON body and look for differential response behaviour."
        ),
        remediation=(
            "Reject __proto__ / constructor / prototype keys on the server, "
            "or merge with Object.create(null) and a safe-merge helper."
        ),
        tags=("prototype-pollution", "injection"),
    )
    name = "prototype-pollution"
    description = ("For JSON request bodies, append a polluting property and "
                   "look for the marker in the response (best-effort, "
                   "low-noise heuristic).")

    def run(self, ctx, send):
        ct = ""
        for k, v in ctx.req_headers:
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if "json" not in ct or not ctx.req_body:
            return
        try:
            obj = json.loads(ctx.req_body)
        except (ValueError, json.JSONDecodeError):
            return
        if not isinstance(obj, dict):
            return
        marker = "reqlore_pp_" + secrets.token_hex(3)
        obj.setdefault("__proto__", {"reqlore_test": marker})
        body = json.dumps(obj).encode()
        req = Request(
            method=ctx.method, url=ctx.full_url,
            headers=_scrub_headers(ctx.req_headers), body=body,
        )
        pr = send(req)
        if marker.encode() in pr.response.body[:200_000]:
            yield Finding(
                severity="high", title="Possible prototype pollution",
                description=("A polluting '__proto__' property was sent in the "
                             "JSON body and the marker is reflected in the "
                             "response, suggesting the server merged it into "
                             "an object prototype."),
                remediation=("Sanitise JSON input — reject __proto__, "
                             "constructor, and prototype keys, or merge into "
                             "Object.create(null) targets."),
                cwe="CWE-1321", owasp="A08:2021-Software and Data Integrity Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f'__proto__: {{"reqlore_test": "{marker}"}}',
                evidence="marker reflected after __proto__ injection",
            )


class GraphQLIntrospectionCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:graphql-introspection",
        intensity="light",
        title="GraphQL introspection enabled",
        default_severity="medium",
        cwe="CWE-200",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "Send a __schema introspection query to GraphQL-shaped URLs and "
            "flag endpoints that return a populated schema."
        ),
        remediation=(
            "Disable introspection in production (Apollo: "
            "`introspection: false`), or gate it behind authentication."
        ),
        tags=("graphql", "info-leak"),
    )
    name = "graphql-introspection"
    description = ("For URLs that look like a GraphQL endpoint, send the "
                   "standard introspection query and flag if the schema is "
                   "exposed.")
    INTROSPECTION_QUERY = ('{"query":"query{__schema{types{name}}}"}')

    def run(self, ctx, send):
        url_l = ctx.full_url.lower()
        if "graphql" not in url_l and "/gql" not in url_l:
            return
        headers = _scrub_headers(ctx.req_headers)
        headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
        headers.append(("Content-Type", "application/json"))
        req = Request(
            method="POST", url=ctx.base_url, headers=headers,
            body=self.INTROSPECTION_QUERY.encode(),
        )
        pr = send(req)
        body = pr.response.body[:200_000]
        if b'"__schema"' in body and b'"types"' in body:
            yield Finding(
                severity="medium", title="GraphQL introspection exposed",
                description=("The GraphQL endpoint answered the introspection "
                             "query, leaking the full schema (types, fields, "
                             "arguments). Attackers use this to plan further "
                             "queries and to find hidden mutations."),
                remediation=("Disable introspection in production GraphQL "
                             "servers, or restrict it to authenticated admin "
                             "tokens."),
                cwe="CWE-200", owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=ctx.base_url, request_id=ctx.history_id,
                payload=self.INTROSPECTION_QUERY,
                evidence=f"introspection responded with status {pr.response.status}",
            )


# ============ B.2 additions ============


class ReflectedHeaderXSSCheck(ActiveCheck):
    """B.2.a — reflected XSS via request headers (UA, Referer, X-FF, cookies)."""
    meta = RuleMeta(
        id="active:xss-reflected-headers",
        intensity="medium",
        title="Reflected XSS via request header",
        default_severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "Replace common request headers (User-Agent, Referer, "
            "X-Forwarded-For, or one cookie value at a time) with a marker "
            "probe and flag responses that echo the marker unescaped."
        ),
        remediation=(
            "Treat header values as untrusted; HTML-encode any value before "
            "rendering it in a response."
        ),
        tags=("xss", "injection", "header"),
    )
    name = "xss-reflected-headers"
    description = ("Mutate User-Agent / Referer / X-Forwarded-For / cookie "
                   "values with a marker probe and look for unescaped reflection.")
    PROBE_TPL = '"\'><wbr-{m}>'
    TARGET_HEADERS: tuple[str, ...] = ("User-Agent", "Referer", "X-Forwarded-For")

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        for hdr in self.TARGET_HEADERS:
            if not ctx.claim_probe(opts, rule_id, "header", hdr):
                continue
            marker = secrets.token_hex(4)
            probe = self.PROBE_TPL.format(m=marker)
            req = _mutated_header(ctx, hdr, probe)
            pr = send(req)
            if pr.response.status == 0:
                continue
            if probe.encode() in pr.response.body[:200_000]:
                yield Finding(
                    severity="high",
                    title="Reflected XSS via request header",
                    description=(f"A marker payload sent in the '{hdr}' request "
                                 "header was echoed verbatim in the response "
                                 "body, suggesting headers are reflected without "
                                 "HTML encoding."),
                    remediation=("HTML-encode header-derived values before "
                                 "rendering them in responses."),
                    cwe="CWE-79", owasp="A03:2021-Injection",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=probe,
                    evidence=f"header '{hdr}' echoed",
                )
        # Cookie values, one at a time.
        for name, _ in _cookie_pairs(ctx.req_headers):
            if not ctx.claim_probe(opts, rule_id, "cookie", name):
                continue
            marker = secrets.token_hex(4)
            probe = self.PROBE_TPL.format(m=marker)
            req = _mutated_cookie(ctx, name, probe)
            pr = send(req)
            if pr.response.status == 0:
                continue
            if probe.encode() in pr.response.body[:200_000]:
                yield Finding(
                    severity="high",
                    title="Reflected XSS via cookie value",
                    description=(f"A marker payload placed in the '{name}' cookie "
                                 "value was echoed verbatim in the response "
                                 "body. Cookie-borne XSS often bypasses "
                                 "request-body sanitisation."),
                    remediation=("Encode cookie-derived values before "
                                 "rendering; consider HttpOnly cookies."),
                    cwe="CWE-79", owasp="A03:2021-Injection",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=probe,
                    evidence=f"cookie '{name}' echoed",
                )


class PathTraversalCheck(ActiveCheck):
    """B.2.b — classic Unix / Windows LFI via query / form params."""
    meta = RuleMeta(
        id="active:path-traversal-lfi",
        intensity="medium",
        title="Path traversal / local file inclusion",
        default_severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Replace path-shaped parameters with traversal probes such as "
            "`../../../../etc/passwd` and flag responses that contain "
            "characteristic file content."
        ),
        remediation=(
            "Resolve file paths against a fixed base directory and reject any "
            "path containing `..` or absolute prefixes."
        ),
        tags=("lfi", "traversal"),
    )
    name = "path-traversal-lfi"
    description = ("Send traversal probes for /etc/passwd and Windows win.ini; "
                   "flag responses that contain the canonical file content.")
    PROBES: tuple[tuple[str, str, bytes], ...] = (
        ("unix",      "../../../../etc/passwd",                 b"root:x:0:0:"),
        ("unix-null", "/etc/passwd%00",                         b"root:x:0:0:"),
        ("unix-2x",   "%252e%252e/%252e%252e/etc/passwd",       b"root:x:0:0:"),
        ("windows",   "..\\..\\..\\windows\\win.ini",           b"[fonts]"),
    )
    _PATH_HINT_CHARS = ("/", "\\", ".ini", ".txt", ".log", ".conf", ".xml",
                         ".bak", ".cfg", "passwd", "etc", "windows")

    def _looks_path_shaped(self, val: str) -> bool:
        if not val:
            return False
        v = val.lower()
        return any(h in v for h in self._PATH_HINT_CHARS)

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if not self._looks_path_shaped(val):
                    continue
                for kind, probe, marker in self.PROBES:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    req = _mutated(ctx, key, probe, loc)
                    pr = send(req)
                    body = pr.response.body[:200_000]
                    if marker in body and marker not in ctx.resp_body[:200_000]:
                        yield Finding(
                            severity="high",
                            title=f"Path traversal exposed file ({kind})",
                            description=(f"A traversal probe sent in the '{key}' "
                                         f"{loc} parameter caused the response to "
                                         "include the contents of a sensitive "
                                         "OS file. This is local file inclusion."
                                         ),
                            remediation=("Resolve user-supplied paths against a "
                                         "whitelisted base directory and reject "
                                         "any input containing `..` or "
                                         "drive-letter / absolute prefixes."),
                            cwe="CWE-22",
                            owasp="A01:2021-Broken Access Control",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=probe,
                            evidence=(f"{kind}: marker "
                                       f"{marker.decode('latin-1')} found in body"),
                        )
                        return


class NoSQLInjectionCheck(ActiveCheck):
    """B.2.c — Mongo-style operator-injection in JSON request bodies."""
    meta = RuleMeta(
        id="active:nosqli-mongo",
        intensity="medium",
        title="NoSQL operator injection (MongoDB)",
        default_severity="high",
        cwe="CWE-943",
        owasp="A03:2021-Injection",
        description=(
            "Replace a JSON string field with `{\"$ne\": null}` and look for "
            "a differential response — extra rows or a status flip — that "
            "indicates the operator was honoured server-side."
        ),
        remediation=(
            "Reject MongoDB operator keys ($ne, $gt, $regex, …) in user input, "
            "or coerce values to strings before passing them to the driver."
        ),
        tags=("nosqli", "injection", "mongo"),
    )
    name = "nosqli-mongo"
    description = ("For JSON request bodies with string fields, send a Mongo "
                   "`$ne` operator and compare against the baseline response.")

    def _content_type(self, ctx: ActiveContext) -> str:
        for k, v in ctx.req_headers:
            if k.lower() == "content-type":
                return v.lower()
        return ""

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if "json" not in self._content_type(ctx) or not ctx.req_body:
            return
        try:
            obj = json.loads(ctx.req_body)
        except (ValueError, json.JSONDecodeError):
            return
        if not isinstance(obj, dict):
            return
        string_keys = [k for k, v in obj.items() if isinstance(v, str)]
        if not string_keys:
            return
        baseline_pr = send(_baseline(ctx))
        base_status = baseline_pr.response.status
        base_len = len(baseline_pr.response.body or b"")
        for key in string_keys:
            if not ctx.claim_probe(opts, rule_id, "json", key):
                continue
            mutated = dict(obj)
            mutated[key] = {"$ne": None}
            body = json.dumps(mutated).encode("utf-8")
            req = Request(
                method=ctx.method, url=ctx.full_url,
                headers=_scrub_headers(ctx.req_headers), body=body,
            )
            pr = send(req)
            new_status = pr.response.status
            new_len = len(pr.response.body or b"")
            status_flip = (
                base_status != new_status
                and 200 <= new_status < 300
                and not (200 <= base_status < 300)
            )
            size_growth = (
                200 <= new_status < 300 and base_len > 0 and new_len >= 2 * base_len
            )
            if status_flip or size_growth:
                yield Finding(
                    severity="high",
                    title="Possible NoSQL injection (MongoDB $ne)",
                    description=(f"Replacing the JSON field '{key}' with the "
                                 "Mongo operator `{\"$ne\": null}` produced a "
                                 f"differential response (baseline status={base_status} "
                                 f"len={base_len}; probe status={new_status} len={new_len}). The "
                                 "operator was likely passed to the database "
                                 "driver unfiltered."
                                 ),
                    remediation=("Reject Mongo operator keys ($ne, $gt, $regex, "
                                 "…) in untrusted JSON, or coerce values to "
                                 "strings before passing them to the driver."),
                    cwe="CWE-943", owasp="A03:2021-Injection",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=f'{key}={{"$ne": null}}',
                    evidence=("status_flip" if status_flip else
                               f"size_growth {base_len}->{new_len}"),
                )


class XXEClassicCheck(ActiveCheck):
    """B.2.d — classic XML external entity (file:// disclosure)."""
    meta = RuleMeta(
        id="active:xxe-classic",
        intensity="medium",
        title="XML external entity (file disclosure)",
        default_severity="high",
        cwe="CWE-611",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "Replace XML request bodies with a probe that defines an external "
            "entity referencing `file:///etc/hostname` and flag responses that "
            "echo non-empty entity-substituted content."
        ),
        remediation=(
            "Disable DTD loading and external entity resolution in the XML "
            "parser (libxml2: `LIBXML_NONET | LIBXML_NOENT` off; Java: "
            "`XMLConstants.FEATURE_SECURE_PROCESSING`)."
        ),
        tags=("xxe", "xml"),
    )
    name = "xxe-classic"
    description = ("Replace XML bodies with a file:// external-entity probe and "
                   "flag responses that show entity content was substituted.")
    PROBE = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
        b'<r>&x;</r>'
    )

    def _is_xml(self, ctx: ActiveContext) -> bool:
        for k, v in ctx.req_headers:
            if k.lower() == "content-type" and ("xml" in v.lower()):
                return True
        body = (ctx.req_body or b"")[:64].lstrip()
        return body.startswith(b"<?xml")

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if not self._is_xml(ctx):
            return
        if not ctx.claim_probe(opts, rule_id, "body", "xml"):
            return
        req = Request(
            method=ctx.method, url=ctx.full_url,
            headers=_scrub_headers(ctx.req_headers), body=self.PROBE,
        )
        pr = send(req)
        if not (200 <= pr.response.status < 300):
            return
        body = pr.response.body[:200_000]
        # Look for the entity-substituted shape: <r>SOMETHING</r> with non-empty,
        # non-whitespace content that isn't just an XML error marker.
        import re as _re
        m = _re.search(rb"<r>([^<]{1,200})</r>", body)
        if not m:
            return
        leaked = m.group(1).strip()
        if not leaked:
            return
        lowered = leaked.lower()
        if (b"error" in lowered or b"undeclared" in lowered
                or b"entity" in lowered):
            return
        yield Finding(
            severity="high",
            title="XML external entity disclosed file content",
            description=("An XXE probe with a `SYSTEM \"file:///etc/hostname\"` "
                         "external entity produced a 2xx response whose body "
                         "contained substituted entity content. The XML parser "
                         "resolved the external entity, which typically allows "
                         "arbitrary file disclosure and SSRF."),
            remediation=("Disable external entity / DTD resolution in the XML "
                         "parser. For libxml2 do not pass `LIBXML_NOENT`; for "
                         "Java set `XMLConstants.FEATURE_SECURE_PROCESSING`."),
            cwe="CWE-611",
            owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.full_url,
            request_id=ctx.history_id,
            payload=self.PROBE.decode("latin-1", errors="replace"),
            evidence=("leaked entity: "
                       + leaked[:80].decode("latin-1", errors="replace")),
        )


class ActiveCORSCheck(ActiveCheck):
    """B.2.i — active CORS misconfig: arbitrary or null origin reflected with creds."""
    meta = RuleMeta(
        id="active:cors-misconfig-extended",
        intensity="light",
        title="CORS reflects arbitrary origin with credentials",
        default_severity="high",
        cwe="CWE-942",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "Send an `Origin` header set to an attacker-controlled value "
            "(arbitrary host, `null`, or a target-suffix attack) and flag any "
            "endpoint that reflects it in `Access-Control-Allow-Origin` while "
            "also returning `Access-Control-Allow-Credentials: true`."
        ),
        remediation=(
            "Validate the Origin against a server-side allowlist; never set "
            "`Allow-Credentials: true` together with a wildcard or reflected "
            "origin."
        ),
        tags=("cors", "misconfig"),
    )
    name = "cors-misconfig-extended"
    description = ("Send three attacker-shaped Origin headers and confirm "
                   "the response reflects with Allow-Credentials: true.")

    @staticmethod
    def _probes_for(host: str) -> tuple[tuple[str, str], ...]:
        sibling = f"https://{host}.evil.invalid" if host else "https://target.com.evil.invalid"
        return (
            ("arbitrary", "https://reqlore-cors.invalid"),
            ("null",      "null"),
            ("suffix",    sibling),
        )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for kind, origin in self._probes_for(ctx.host):
            if not ctx.claim_probe(opts, rule_id, "header", f"Origin:{kind}"):
                continue
            req = _mutated_header(ctx, "Origin", origin)
            pr = send(req)
            if pr.response.status == 0:
                continue
            acao = pr.response.header("Access-Control-Allow-Origin") or ""
            acac = (pr.response.header("Access-Control-Allow-Credentials") or "").strip().lower()
            if acao.strip() == origin and acac == "true":
                yield Finding(
                    severity="high",
                    title=f"CORS reflects {kind} origin with credentials",
                    description=("The server echoed the attacker-controlled "
                                 f"Origin '{origin}' in its Access-Control-Allow-Origin "
                                 "header and sent Access-Control-Allow-Credentials: "
                                 "true. An attacker page can issue authenticated "
                                 "cross-origin requests and read the responses."
                                 ),
                    remediation=("Validate the Origin against a strict server-side "
                                 "allowlist; never combine credentials with a "
                                 "wildcard or reflected origin."),
                    cwe="CWE-942",
                    owasp="A05:2021-Security Misconfiguration",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=f"Origin: {origin}",
                    evidence=f"ACAO: {acao} | ACAC: true",
                )
                # one finding per row is enough to flag the misconfig.
                return


# Order matters only for human readability.
BUILTIN_ACTIVE_CHECKS: list[ActiveCheck] = [
    ReflectedXSSCheck(),
    SQLiErrorCheck(),
    OpenRedirectCheck(),
    SSTICheck(),
    TimeBasedOSCommandCheck(),
    JWTAlgNoneAcceptanceCheck(),
    PrototypePollutionCheck(),
    GraphQLIntrospectionCheck(),
    # ---- B.2 additions ----
    ReflectedHeaderXSSCheck(),
    PathTraversalCheck(),
    NoSQLInjectionCheck(),
    XXEClassicCheck(),
    ActiveCORSCheck(),
    # OAST-SSRF only runs when ActiveOptions.oast is provided.
]


class OASTSSRFCheck(ActiveCheck):
    """Inject an OAST callback URL into each parameter and watch for hits.

    Requires ``ActiveOptions.oast`` to be a running :class:`reqlore.oast.LocalOAST`.
    A unique token is generated per row, then for every query / form parameter
    the probe URL is substituted with ``http://127.0.0.1:<port>/<token>/p<i>``.
    After all probes return, the OAST log is polled for any interaction
    matching the token within ``ActiveOptions.oast_wait_s``.
    """
    name = "oast-ssrf"
    description = ("Inject an out-of-band callback URL into parameters; any "
                   "server-side fetch is recorded by the local OAST receiver.")
    meta = RuleMeta(
        id="active:oast-ssrf",
        intensity="intrusive",
        title="Out-of-band callback triggered (likely SSRF)",
        default_severity="high",
        cwe="CWE-918",
        owasp="A10:2021-Server-Side Request Forgery",
        description=(
            "Inject a unique OAST callback URL into each parameter, then "
            "poll the local receiver for any inbound request."
        ),
        remediation=(
            "Refuse outbound requests from user-controlled URLs; if they "
            "must be allowed, restrict by scheme, host allow-list, and "
            "protocol layer."
        ),
        tags=("ssrf", "oast"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        oast = getattr(opts, "oast", None) if opts else None
        if oast is None or not oast.is_running():
            return
        token = oast.new_token()
        callback = oast.url_for(token)

        q_pairs = ctx.query_pairs()
        f_pairs = ctx.form_pairs()
        targets: list[tuple[str, str]] = (
            [("query", k) for k, _ in q_pairs] +
            [("form", k) for k, _ in f_pairs]
        )
        if not targets:
            return

        for i, (loc, key) in enumerate(targets[: opts.max_requests_per_check if opts else 4]):
            probe_url = callback + f"p{i}"
            req = _mutated(ctx, key, probe_url, loc)
            send(req)

        # Poll OAST briefly for this token.
        wait_s = float(getattr(opts, "oast_wait_s", 0.6) or 0.6)
        deadline = time.monotonic() + wait_s
        hits = []
        while time.monotonic() < deadline:
            hits = oast.interactions(token=token)
            if hits:
                break
            time.sleep(0.05)
        if not hits:
            return
        hit = hits[0]
        yield Finding(
            severity="high",
            title="Out-of-band callback triggered (likely SSRF)",
            description=("The server fetched the injected OAST URL. This "
                          "strongly suggests Server-Side Request Forgery or a "
                          "similar out-of-band vector (blind XSS, OOB SQLi)."),
            remediation=("Refuse outbound requests from user-controlled URLs; "
                          "if they must be allowed, restrict by scheme, host "
                          "allow-list, and protocol layer."),
            cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery",
            host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
            payload=callback,
            evidence=f"OAST hit token={token} method={hit.method} path={hit.path}",
        )


BUILTIN_ACTIVE_CHECKS.append(OASTSSRFCheck())


# =============== Phase 1 (Tier A) — gap-list checks ===========================
#
# Each check below closes one item on the SCANNER_GAP_PLAN tier-A list. They
# follow the same contract as everything above: stateless across scans, budget
# every probe via ``ctx.claim_probe``, fire at most one Finding per real
# weakness, and never raise.


class ForcedBrowsingCheck(ActiveCheck):
    """Item 11 — actively probe a small list of high-signal sensitive paths.

    The passive ``rule_sensitive_paths`` only flags paths the operator already
    visited; this check actually sends a GET. The wordlist is intentionally
    short and high-signal: every entry has a near-zero false-positive rate
    when it returns 200, so we don't need a fuzzy body-content classifier.

    A per-row probe budget keeps cost bounded; cross-row duplicates are
    deduped at the Finding layer by ``record_finding``.
    """
    name = "forced-browsing"
    description = ("Probe a small wordlist of sensitive paths (.git/HEAD, "
                   ".env, /backup.zip, /swagger.json, /.DS_Store, /api-docs) "
                   "on the same host and flag any that return 200.")
    meta = RuleMeta(
        id="active:forced-browsing",
        intensity="medium",
        title="Sensitive path exposed",
        default_severity="high",
        cwe="CWE-538",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "Actively GET a curated list of paths that should never be "
            "world-readable. Each hit is high-signal: a 200 on /.git/HEAD "
            "leaks the entire repository, /.env leaks credentials, "
            "/swagger.json leaks the full API surface."
        ),
        remediation=(
            "Remove the file from the deployed tree, or block the path at "
            "the front-end (`location ~ /\\.git { deny all; }`). For "
            "/swagger.json and /api-docs, gate them behind authentication."
        ),
        tags=("forced-browsing", "info-leak"),
    )
    WORDLIST: tuple[tuple[str, Severity, str], ...] = (
        # (path, severity, why)
        ("/.git/HEAD",      "high",   "Git repository exposed"),
        ("/.env",           "high",   "Environment file exposed"),
        ("/.DS_Store",      "medium", "macOS Finder metadata exposed"),
        ("/backup.zip",     "high",   "Backup archive exposed"),
        ("/swagger.json",   "medium", "OpenAPI spec exposed"),
        ("/api-docs",       "medium", "API documentation exposed"),
    )
    # Body markers that confirm the response is the real artefact, not a
    # SPA fallback 200 that serves index.html for every path.
    _CONFIRM_MARKERS: dict[str, tuple[bytes, ...]] = {
        "/.git/HEAD":    (b"ref: refs/", b"ref:refs/"),
        "/.env":         (b"=",),  # any key=value line
        "/.DS_Store":    (b"Bud1",),  # DS_Store magic
        "/backup.zip":   (b"PK\x03\x04",),  # ZIP magic
        "/swagger.json": (b"\"swagger\"", b"\"openapi\""),
        "/api-docs":     (b"swagger", b"openapi", b"<title>"),
    }

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        parsed = up.urlsplit(ctx.full_url)
        if not parsed.scheme or not parsed.netloc:
            return
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, severity, why in self.WORDLIST:
            if not ctx.claim_probe(opts, rule_id, "path", path):
                continue
            probe_url = origin + path
            req = Request(method="GET", url=probe_url, headers=[], body=b"")
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                continue
            if pr.response.status != 200:
                continue
            body = pr.response.body[:200_000]
            markers = self._CONFIRM_MARKERS.get(path, ())
            if markers and not any(m in body for m in markers):
                # 200 but the body doesn't look like the artefact — likely
                # a SPA fallback. Skip to avoid false positives.
                continue
            yield Finding(
                severity=severity,
                title=f"Sensitive path exposed: {path}",
                description=(
                    f"{why}. Anonymous GET to {probe_url} returned 200 with "
                    "a body that matches the expected fingerprint."
                ),
                remediation=(
                    "Remove the file from the deployed artefact, or block "
                    f"`{path}` at the front-end / WAF."
                ),
                cwe="CWE-538", owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=probe_url, request_id=ctx.history_id,
                payload=f"GET {path}",
                evidence=f"status=200, body[:32]={body[:32]!r}",
            )


class DeserialisationReflectCheck(ActiveCheck):
    """Item 7 — feed known serialised-object magic bytes into params and look
    for the back-end's deserialiser stack trace in the response.

    Sending Base64-encoded magic for Java (rO0AB…), .NET (AAEAAAD…), PHP
    (O:…), or Python pickle (gASV…) into a parameter that is later
    deserialised tends to surface a *very* specific error string. We do not
    attempt RCE; the marker for "the back-end actually tried to deserialise"
    is the exception class name. False-positive risk is low because those
    class names virtually never appear in normal application output.
    """
    name = "deserialisation-reflect"
    description = ("Inject Java/.NET/PHP/Python serialised-object magic "
                   "bytes into each parameter and flag responses that "
                   "leak a deserialiser stack trace.")
    meta = RuleMeta(
        id="active:deserialisation-reflect",
        intensity="medium",
        title="Insecure deserialisation hint",
        default_severity="high",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        description=(
            "Send the canonical magic prefix for Java ObjectInputStream, "
            ".NET BinaryFormatter, PHP `unserialize`, and Python pickle "
            "in each query/form parameter; flag any response that reveals "
            "the matching deserialiser stack trace or class name."
        ),
        remediation=(
            "Stop deserialising untrusted input; if you must, use a safe "
            "format (JSON with schema validation) or sign the payload "
            "(HMAC) and verify before deserialising."
        ),
        tags=("deserialisation", "injection"),
    )
    # (label, payload, marker_signatures)
    PAYLOADS: tuple[tuple[str, str, tuple[bytes, ...]], ...] = (
        ("java-objectinputstream", "rO0ABXQABHRlc3Q=", (
            b"java.io.ObjectInputStream",
            b"java.io.InvalidClassException",
            b"java.io.NotSerializableException",
            b"java.io.StreamCorruptedException",
        )),
        ("dotnet-binaryformatter", "AAEAAAD/////AQAAAAAAAAAMAgAAAFNTeXN0ZW0=", (
            b"System.Runtime.Serialization",
            b"BinaryFormatter",
            b"SerializationException",
        )),
        ("php-unserialize", 'O:8:"stdClass":0:{}', (
            b"unserialize()",
            b"__PHP_Incomplete_Class",
            b"PHP Warning:  unserialize",
        )),
        ("python-pickle", "gASVCgAAAAAAAACMBnRlc3QxlC4=", (
            b"pickle.UnpicklingError",
            b"_pickle.UnpicklingError",
            b"_pickle.PickleError",
        )),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        targets: list[tuple[str, str]] = (
            [("query", k) for k, _ in ctx.query_pairs()] +
            [("form", k) for k, _ in ctx.form_pairs()]
        )
        if not targets:
            return

        for loc, key in targets:
            for label, payload, sigs in self.PAYLOADS:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    return  # per-row budget exhausted
                req = _mutated(ctx, key, payload, loc)
                try:
                    pr = send(req)
                except _SAFE_NETWORK_EXC:
                    continue
                body = pr.response.body[:200_000]
                hit = next((s for s in sigs if s in body), None)
                if not hit:
                    continue
                yield Finding(
                    severity="high",
                    title=f"Insecure deserialisation hint ({label})",
                    description=(
                        f"Sending the {label} magic bytes in '{loc}' "
                        f"parameter '{key}' caused the response to include "
                        "a deserialiser stack trace, which strongly "
                        "suggests the parameter is fed to an unsafe "
                        "deserialisation routine."
                    ),
                    remediation=(
                        "Stop deserialising untrusted input; use a safe "
                        "format or sign+verify the payload before "
                        "deserialising."
                    ),
                    cwe="CWE-502",
                    owasp="A08:2021-Software and Data Integrity Failures",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=payload[:120],
                    evidence=f"{loc}.{key}: stack-trace marker {hit!r}",
                )
                # One finding per (loc, key) is enough; stop probing other
                # payload families for this parameter.
                break


class WebCacheDeceptionCheck(ActiveCheck):
    """Item 19 — classic Omer Gil cache-deception: append a static-looking
    suffix to an authenticated path and see if the cache serves the
    authenticated body to an *anonymous* request.

    Only runs when the recorded request carried a ``Cookie`` or
    ``Authorization`` header (otherwise there's nothing personal in the
    response). The detection signal is "an unauthenticated GET to
    /account/x.css returned a 200 whose body is highly similar to the
    authenticated /account body" — i.e. the upstream cache mis-keyed.
    """
    name = "web-cache-deception"
    description = ("Append a static-looking suffix (/x.css) to authenticated "
                   "paths and check whether an anonymous request gets the "
                   "personal body back from the cache.")
    meta = RuleMeta(
        id="active:web-cache-deception",
        intensity="medium",
        title="Web cache deception",
        default_severity="high",
        cwe="CWE-525",
        owasp="A04:2021-Insecure Design",
        description=(
            "Append a static-extension suffix to the recorded URL, GET it "
            "without auth, and compare the response body to the original. "
            "A high-similarity 200 from the unauthenticated probe means "
            "the upstream cache mis-keyed and is serving personal data."
        ),
        remediation=(
            "Configure the cache to key on the full path *and* a "
            "Vary/Cache-Control hint, never cache responses that carry "
            "Set-Cookie, and reject path traversal that produces "
            "ambiguous extensions at the origin."
        ),
        tags=("cache", "info-leak"),
    )
    SUFFIXES: tuple[str, ...] = ("/x.css", "/x.js", "/x.jpg")

    def _had_auth(self, ctx) -> bool:
        for k, v in ctx.req_headers:
            kl = k.lower()
            if kl == "cookie" and v.strip():
                return True
            if kl == "authorization" and v.strip():
                return True
        return False

    def _similarity(self, a: bytes, b: bytes) -> float:
        """Token Jaccard on byte 3-grams. Cheap and good enough for
        'is this the same page or a different one?'."""
        if not a or not b:
            return 0.0
        a = a[:50_000]
        b = b[:50_000]
        ga = {a[i:i + 3] for i in range(0, len(a) - 2)}
        gb = {b[i:i + 3] for i in range(0, len(b) - 2)}
        if not ga or not gb:
            return 0.0
        inter = len(ga & gb)
        union = len(ga | gb)
        return inter / union if union else 0.0

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        if ctx.method.upper() != "GET":
            return
        if ctx.resp_status != 200 or not ctx.resp_body:
            return
        if not self._had_auth(ctx):
            return

        parsed = up.urlsplit(ctx.full_url)
        # Pages that already look like static assets are uninteresting.
        if parsed.path and "." in parsed.path.rsplit("/", 1)[-1]:
            return

        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        for suffix in self.SUFFIXES:
            if not ctx.claim_probe(opts, rule_id, "suffix", suffix):
                continue
            probe_path = path.rstrip("/") + suffix
            probe_url = origin + probe_path
            if parsed.query:
                probe_url += "?" + parsed.query
            req = Request(method="GET", url=probe_url, headers=[], body=b"")
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                continue
            if pr.response.status != 200:
                continue
            sim = self._similarity(ctx.resp_body, pr.response.body)
            if sim < 0.6:
                continue
            yield Finding(
                severity="high",
                title="Web cache deception",
                description=(
                    f"Unauthenticated GET to {probe_url} returned a 200 "
                    f"whose body is {int(sim * 100)}% similar to the "
                    "authenticated response. The upstream cache appears "
                    "to be serving personal data under a static-looking "
                    "URL, so any later anonymous visitor will get it too."
                ),
                remediation=(
                    "Reject extension-confused paths at the origin (the "
                    "request reached the app even with a /x.css suffix). "
                    "Configure the cache to refuse caching responses that "
                    "carry a Set-Cookie or vary on Authorization."
                ),
                cwe="CWE-525", owasp="A04:2021-Insecure Design",
                host=ctx.host, url=probe_url, request_id=ctx.history_id,
                payload=f"GET {probe_path}",
                evidence=f"jaccard={sim:.2f} vs authenticated body",
            )
            return  # one finding per page is enough


class OAuthRedirectURICheck(ActiveCheck):
    """Item 20 — OAuth ``redirect_uri`` open-redirect.

    Many OAuth-ish flows accept a ``redirect_uri`` (or ``return_to`` /
    ``next`` / ``url``) parameter and trust the registered host list to
    catch tampering. If the server forgets to check, or matches with a
    weak prefix test, swapping the host sends the user — with their
    freshly-minted token — to an attacker.

    We swap the host for a scan-unique ``*.example.invalid`` marker and
    flag a 30x whose ``Location`` honours the swap, or a 200 whose body
    embeds the swapped URL in a fresh anchor / form / meta refresh.
    """
    name = "oauth-redirect-uri"
    description = ("For URLs carrying a redirect_uri-style parameter, swap "
                   "the host for an attacker marker and flag responses that "
                   "redirect to it.")
    meta = RuleMeta(
        id="active:oauth-redirect-uri",
        intensity="light",
        title="Open redirect via OAuth redirect_uri",
        default_severity="medium",
        cwe="CWE-601",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Detect open redirects in OAuth-shaped parameters by "
            "host-swapping the value and watching for the swapped host to "
            "show up in the Location header or response body."
        ),
        remediation=(
            "Validate redirect_uri against an exact-match allow-list of "
            "registered URIs (scheme + host + path), not a prefix or "
            "substring match. Reject mismatches with HTTP 400."
        ),
        tags=("open-redirect", "oauth"),
    )
    TARGET_PARAMS: tuple[str, ...] = (
        "redirect_uri", "redirect", "return_to", "returnto",
        "return_url", "next", "url", "continue", "callback",
    )

    def _is_uri_value(self, val: str) -> bool:
        if not val:
            return False
        v = val.strip()
        return bool(v.startswith(("http://", "https://", "//")))

    def _swap_host(self, val: str, attacker: str) -> str | None:
        try:
            decoded = up.unquote(val)
        except Exception:
            return None
        try:
            pr = up.urlsplit(decoded)
        except ValueError:
            return None
        if not pr.netloc:
            return None
        new = pr._replace(netloc=attacker)
        return up.urlunsplit(new)

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        pairs = ctx.query_pairs() + ctx.form_pairs()
        if not pairs:
            return

        attacker = f"r{secrets.token_hex(3)}.example.invalid"

        seen: set[tuple[str, str]] = set()
        for key, val in pairs:
            if key.lower() not in self.TARGET_PARAMS:
                continue
            if not self._is_uri_value(val):
                continue
            if (key, val) in seen:
                continue
            seen.add((key, val))

            swapped = self._swap_host(val, attacker)
            if not swapped:
                continue
            # Best-effort: which location holds this param? Form if it was
            # in the body, else query. ``_mutated`` doesn't care about a
            # second location, so probe both if needed.
            in_query = any(k == key for k, _ in ctx.query_pairs())
            location = "query" if in_query else "form"
            if not ctx.claim_probe(opts, rule_id, location, key):
                continue

            req = _mutated(ctx, key, swapped, location)
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                continue
            status = pr.response.status
            loc_hdr = pr.response.header("Location") or ""
            body = pr.response.body[:200_000]

            redirect_hit = (300 <= status < 400 and attacker in loc_hdr)
            body_hit = (status == 200 and attacker.encode() in body)
            if not (redirect_hit or body_hit):
                continue

            yield Finding(
                severity="medium",
                title="Open redirect via OAuth redirect_uri",
                description=(
                    f"Swapping the host of '{key}' to {attacker!r} caused "
                    f"the server to {'redirect' if redirect_hit else 'echo a link'} "
                    "to the attacker-controlled host. If this parameter is "
                    "part of an OAuth flow, an attacker who tricks a user "
                    "into clicking the crafted URL can steal the resulting "
                    "authorisation code or token."
                ),
                remediation=(
                    "Validate the redirect target against an exact-match "
                    "allow-list of registered URIs and reject anything "
                    "else with HTTP 400."
                ),
                cwe="CWE-601", owasp="A01:2021-Broken Access Control",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"{key}={swapped}",
                evidence=(
                    f"status={status}, "
                    f"{'Location=' + loc_hdr if redirect_hit else 'body contains marker'}"
                ),
            )


BUILTIN_ACTIVE_CHECKS.append(ForcedBrowsingCheck())
BUILTIN_ACTIVE_CHECKS.append(DeserialisationReflectCheck())
BUILTIN_ACTIVE_CHECKS.append(WebCacheDeceptionCheck())
BUILTIN_ACTIVE_CHECKS.append(OAuthRedirectURICheck())


# =============== Phase 1b — items #8 and #18 ==================================


class HTTPSmugglingCheck(ActiveCheck):
    """Item 8 — wrap :mod:`reqlore.smuggling` into a check.

    The smuggling payloads are byte-exact raw HTTP bytes that the standard
    httpx engine would normalise away, so this check uses
    :mod:`reqlore.engines.raw_engine` directly. That sidesteps the active
    scanner's injected ``send`` (and its rate / throttle bookkeeping); we
    compensate by gating behind an opt-in flag and a per-host claim_probe
    budget so a single scan can only fire ~3 raw-socket probes per host.

    The check is **off by default** (``ActiveOptions.allow_smuggling_probes``)
    because raw-socket egress and the timing heuristic are both noisy in
    real-world environments.
    """
    name = "http-smuggling"
    description = ("Timing-based HTTP request smuggling probe (CL.TE / "
                   "TE.CL / TE.TE) using the raw-socket engine. Off by "
                   "default; enable via the run-page Custom preset.")
    meta = RuleMeta(
        id="active:http-smuggling",
        intensity="intrusive",
        title="Likely HTTP request smuggling",
        default_severity="critical",
        cwe="CWE-444",
        owasp="A10:2021-Server-Side Request Forgery",
        description=(
            "Send a baseline GET and a CL.TE / TE.CL / TE.TE payload to "
            "the recorded host via the raw-socket engine; flag a probe "
            "whose latency exceeds the baseline by more than the "
            "configured threshold."
        ),
        remediation=(
            "Normalise request framing at the front-end (reject ambiguous "
            "Transfer-Encoding/Content-Length combinations, prefer HTTP/2 "
            "end-to-end) and patch the affected proxy/server software."
        ),
        tags=("smuggling", "ssrf"),
    )
    TECHNIQUES: tuple[str, ...] = ("cl.te", "te.cl", "te.te")
    PAUSE_THRESHOLD_MS = 1500

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        if not getattr(opts, "allow_smuggling_probes", False):
            return
        from .. import smuggling as smug
        from ..engines import raw_engine
        rule_id = self.meta.id

        # Only one probe family per host per scan — the timing heuristic
        # is the same regardless of which technique fires, and three back-
        # to-back raw probes is enough load already.
        if not ctx.claim_probe(opts, rule_id, "host", ctx.host):
            return

        timeout_s = float(opts.timeout_s)

        def _raw_send(req: Request) -> Response:
            return raw_engine.send(req, timeout=timeout_s)

        for technique in self.TECHNIQUES:
            try:
                test = smug.detect(
                    ctx.base_url, technique, sender=_raw_send,
                    pause_ms_threshold=self.PAUSE_THRESHOLD_MS,
                )
            except _SAFE_NETWORK_EXC:
                continue
            if not test.likely_vulnerable:
                continue
            yield Finding(
                severity="critical",
                title=f"Likely HTTP request smuggling ({technique.upper()})",
                description=(
                    "A raw-socket timing probe took significantly longer "
                    "than the baseline, which strongly suggests the "
                    "upstream front-end and back-end disagree on request "
                    "framing — the classic indicator of HTTP request "
                    "smuggling. Confirm manually before disclosure."
                ),
                remediation=(
                    "Normalise request framing at the front-end (reject "
                    "ambiguous Transfer-Encoding/Content-Length "
                    "combinations, prefer HTTP/2 end-to-end) and patch "
                    "the affected proxy/server software."
                ),
                cwe="CWE-444", owasp="A10:2021-Server-Side Request Forgery",
                host=ctx.host, url=ctx.base_url, request_id=ctx.history_id,
                payload=f"{technique.upper()} timing probe",
                evidence=test.reason,
            )
            # One critical-severity finding per host is plenty.
            return


class GraphQLActiveCheck(ActiveCheck):
    """Item 18 — GraphQL beyond introspection: batching + field suggestions.

    Two probes against any URL that looks like a GraphQL endpoint:

    1. **Query batching abuse** — POST a JSON array of N copies of the same
       trivial query. A response that comes back as a *length-N JSON array*
       proves the server honours batched requests, which is exploitable for
       brute-force amplification (rate-limiters typically count requests,
       not queries) and DoS.
    2. **Field-suggestion leak** — POST a query with a deliberately
       misspelt root field (``__schemaa``). A response containing a "Did
       you mean" hint or echoing valid root field names leaks schema
       information even when introspection is disabled.

    Both probes are JSON-only; we leave the existing
    :class:`GraphQLIntrospectionCheck` untouched.
    """
    name = "graphql-active"
    description = ("Send batched-query and typo-field probes to GraphQL "
                   "endpoints; flag servers that honour batching or leak "
                   "field-suggestion hints even with introspection off.")
    meta = RuleMeta(
        id="active:graphql-active",
        intensity="medium",
        title="GraphQL hardening gap",
        default_severity="medium",
        cwe="CWE-200",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "POST a query batch and a typo'd field name to the GraphQL "
            "endpoint; flag responses that confirm batching is enabled "
            "or that leak a 'Did you mean' field-name suggestion."
        ),
        remediation=(
            "Disable query batching unless required (Apollo: "
            "`allowBatchedHttpRequests: false`); turn off field-name "
            "suggestions in production (e.g. Apollo's "
            "`NoSchemaIntrospectionCustomRule` and `NoUnknownFieldsHint`)."
        ),
        tags=("graphql", "info-leak"),
    )
    BATCH_QUERY = (
        '[{"query":"{__typename}"},{"query":"{__typename}"},'
        '{"query":"{__typename}"}]'
    )
    TYPO_QUERY = '{"query":"{ __schemaa { types { name } } }"}'
    SUGGESTION_MARKERS: tuple[bytes, ...] = (
        b"Did you mean",
        b"did you mean",
        b'"__schema"',  # echoing a real root field counts as suggestion
    )

    def _looks_like_graphql(self, url: str) -> bool:
        u = url.lower()
        return "graphql" in u or "/gql" in u

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if not self._looks_like_graphql(ctx.full_url):
            return

        json_headers = [(k, v) for k, v in _scrub_headers(ctx.req_headers)
                         if k.lower() != "content-type"]
        json_headers.append(("Content-Type", "application/json"))

        # ---- batching probe -------------------------------------------------
        if ctx.claim_probe(opts, rule_id, "json", "batch"):
            req = Request(method="POST", url=ctx.base_url,
                          headers=list(json_headers),
                          body=self.BATCH_QUERY.encode())
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                pr = None
            if pr is not None and 200 <= pr.response.status < 300:
                body = pr.response.body[:200_000].lstrip()
                if body.startswith(b"["):
                    # Confirm it's a length-3 array of GraphQL responses.
                    try:
                        decoded = json.loads(body.decode(
                            "utf-8", errors="replace"))
                    except (ValueError, UnicodeDecodeError):
                        decoded = None
                    if (isinstance(decoded, list) and len(decoded) >= 2
                            and all(isinstance(x, dict) for x in decoded)):
                        yield Finding(
                            severity="medium",
                            title="GraphQL query batching enabled",
                            description=(
                                "The endpoint accepted a JSON array of "
                                "queries and returned an array of "
                                "results. Batching lets an attacker bypass "
                                "per-request rate limits by packing N "
                                "lookups (or N login attempts) into a "
                                "single HTTP request."
                            ),
                            remediation=(
                                "Disable query batching unless explicitly "
                                "required by clients; if it must stay on, "
                                "rate-limit by *operation count* rather "
                                "than by HTTP request."
                            ),
                            cwe="CWE-770",
                            owasp="A04:2021-Insecure Design",
                            host=ctx.host, url=ctx.base_url,
                            request_id=ctx.history_id,
                            payload=self.BATCH_QUERY,
                            evidence=(f"batched response is a JSON array "
                                       f"of length {len(decoded)}"),
                        )

        # ---- field-suggestion probe ----------------------------------------
        if ctx.claim_probe(opts, rule_id, "json", "suggest"):
            req = Request(method="POST", url=ctx.base_url,
                          headers=list(json_headers),
                          body=self.TYPO_QUERY.encode())
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                return
            body = pr.response.body[:200_000]
            hit = next((m for m in self.SUGGESTION_MARKERS if m in body), None)
            if hit:
                yield Finding(
                    severity="low",
                    title="GraphQL field-suggestion hints leaked",
                    description=(
                        "Sending a query with a deliberately misspelt "
                        "root field caused the GraphQL server to echo a "
                        "suggestion that points at a real schema field "
                        "name. Field-name suggestions effectively leak "
                        "the schema even when introspection is disabled."
                    ),
                    remediation=(
                        "Disable field-name suggestions in production "
                        "(e.g. Apollo's `NoUnknownFieldsHint` rule, or "
                        "graphql-js `validate` with the standard rules "
                        "minus `FieldsOnCorrectTypeRule`)."
                    ),
                    cwe="CWE-200",
                    owasp="A05:2021-Security Misconfiguration",
                    host=ctx.host, url=ctx.base_url,
                    request_id=ctx.history_id,
                    payload=self.TYPO_QUERY,
                    evidence=f"response body includes marker {hit!r}",
                )


BUILTIN_ACTIVE_CHECKS.append(HTTPSmugglingCheck())
BUILTIN_ACTIVE_CHECKS.append(GraphQLActiveCheck())


# =============== Phase 2 (Tier B) — stdlib net I/O =============================
#
# Items #14, #13, #15. Each uses the network differently from the other
# checks: TLS opens a raw SSL socket, takeover only inspects response
# bodies, default-creds spray is opt-in like smuggling. Tests
# monkey-patch the I/O helpers so CI stays offline.


@dataclass
class _TLSInfo:
    cipher_name: str = ""
    cipher_bits: int = 0
    protocol: str = ""           # e.g. "TLSv1.2"
    not_after: str = ""          # raw "MMM DD HH:MM:SS YYYY GMT" string
    error: str = ""              # populated when the handshake failed
    verify_reason: str = ""      # SSLCertVerificationError.reason


def _tls_inspect(host: str, port: int = 443, *,
                  timeout: float = 5.0) -> _TLSInfo:
    """Open a TLS connection and return inspection metadata.

    On a successful handshake the cert was verified by the system trust
    store; populates ``cipher_name``, ``cipher_bits``, ``protocol``, and
    ``not_after``. On failure populates ``error`` (and ``verify_reason``
    if it was a verification error). Tests monkey-patch this helper.
    """
    import socket
    info = _TLSInfo()
    try:
        ctx = ssl.create_default_context()
        with (socket.create_connection((host, port), timeout=timeout) as sock,
              ctx.wrap_socket(sock, server_hostname=host) as ssock):
            cipher = ssock.cipher() or ("", "", 0)
            info.cipher_name = cipher[0] or ""
            info.cipher_bits = int(cipher[2] or 0)
            info.protocol = ssock.version() or ""
            cert = ssock.getpeercert() or {}
            info.not_after = str(cert.get("notAfter") or "")
        return info
    except ssl.SSLCertVerificationError as exc:
        info.error = "verify_failed"
        info.verify_reason = str(getattr(exc, "reason", "") or exc)
        return info
    except (ssl.SSLError, OSError) as exc:
        info.error = f"ssl_error:{exc.__class__.__name__}"
        return info


# Cipher names whose presence indicates legacy/insecure crypto, even when
# the bit-count is nominally OK.
_WEAK_CIPHER_TOKENS = (
    "RC4", "3DES", "DES-", "EXPORT", "NULL", "ANON", "MD5", "IDEA",
)
_WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _is_weak_protocol(name: str) -> bool:
    """True for protocols below TLS 1.2. Exact-match (and tolerates
    OpenSSL's occasional ``TLSv1.0`` spelling for TLS 1.0)."""
    if not name:
        return False
    if name in _WEAK_PROTOCOLS:
        return True
    return name == "TLSv1.0"


def _is_weak_cipher(name: str, bits: int) -> bool:
    if not name:
        return False
    upper = name.upper()
    if any(tok in upper for tok in _WEAK_CIPHER_TOKENS):
        return True
    return bool(bits) and bits < 128


def _parse_cert_expiry(not_after: str) -> int | None:
    """Return seconds-until-expiry, or None if unparseable."""
    if not not_after:
        return None
    try:
        # ssl module returns "MMM DD HH:MM:SS YYYY GMT"
        return int(ssl.cert_time_to_seconds(not_after) - time.time())
    except (ValueError, OSError, TypeError):
        return None


class ActiveTLSCheck(ActiveCheck):
    """Item 14 — open a real TLS handshake against the recorded host:443
    and flag expired certs, weak protocols, weak ciphers, or hostname
    mismatch."""
    name = "tls-active"
    description = ("Open a TLS handshake against the recorded host and "
                   "flag expired certs, weak protocols, weak ciphers, or "
                   "hostname mismatch.")
    meta = RuleMeta(
        id="active:tls-active",
        intensity="medium",
        title="TLS configuration weakness",
        default_severity="medium",
        cwe="CWE-326",
        owasp="A02:2021-Cryptographic Failures",
        description=(
            "Live TLS handshake against the recorded host's HTTPS port. "
            "Reports certificate verification failures (hostname "
            "mismatch, expired, self-signed, untrusted CA), legacy "
            "protocol versions (< TLS 1.2), and ciphers below 128 bits "
            "or on the documented weak list."
        ),
        remediation=(
            "Renew or replace the certificate, configure the server to "
            "negotiate TLS 1.2+ only, and disable RC4 / 3DES / EXPORT "
            "/ NULL / anonymous cipher suites."
        ),
        tags=("tls", "crypto"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        parsed = up.urlsplit(ctx.full_url)
        if parsed.scheme.lower() != "https":
            return
        host = parsed.hostname or ctx.host
        if not host:
            return
        port = parsed.port or 443

        # One TLS handshake per (host, port) per scan.
        if not ctx.claim_probe(opts, rule_id, "host", f"{host}:{port}"):
            return

        info = _tls_inspect(host, port, timeout=float(opts.timeout_s))

        # ---- handshake outcome ------------------------------------------
        if info.error:
            if info.error == "verify_failed":
                reason = info.verify_reason or "certificate verification failed"
                yield Finding(
                    severity="high",
                    title="TLS certificate verification failed",
                    description=(
                        f"Connecting to {host}:{port} with the system "
                        f"trust store raised: {reason}. Common causes "
                        "include hostname mismatch, expired cert, "
                        "self-signed cert, or an untrusted CA. Browsers "
                        "will warn or refuse to connect."
                    ),
                    remediation=(
                        "Issue a certificate for the correct hostname "
                        "from a trusted CA and renew before expiry."
                    ),
                    cwe="CWE-295",
                    owasp="A02:2021-Cryptographic Failures",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=f"tls handshake -> {host}:{port}",
                    evidence=reason,
                )
            # Plain SSL/socket errors (timeout, connection refused) are
            # not findings — record_no_finding via the scanner's normal
            # rule_run telemetry.
            return

        # ---- protocol --------------------------------------------------
        if _is_weak_protocol(info.protocol):
            yield Finding(
                severity="medium",
                title=f"Legacy TLS protocol negotiated ({info.protocol})",
                description=(
                    f"The server at {host}:{port} accepts {info.protocol}. "
                    "Anything below TLS 1.2 is considered broken: "
                    "BEAST, POODLE, and Lucky13 all target TLS 1.0/1.1 "
                    "and SSLv3."
                ),
                remediation=(
                    "Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 at the "
                    "server; require TLS 1.2 or later."
                ),
                cwe="CWE-326", owasp="A02:2021-Cryptographic Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"tls handshake -> {host}:{port}",
                evidence=f"protocol={info.protocol}",
            )

        # ---- cipher ----------------------------------------------------
        if _is_weak_cipher(info.cipher_name, info.cipher_bits):
            yield Finding(
                severity="medium",
                title=f"Weak TLS cipher negotiated ({info.cipher_name})",
                description=(
                    f"The server at {host}:{port} negotiated "
                    f"{info.cipher_name} ({info.cipher_bits} bits). "
                    "RC4, 3DES, DES, EXPORT, NULL, ANON, MD5, IDEA, and "
                    "ciphers below 128 bits are all considered broken."
                ),
                remediation=(
                    "Restrict the server cipher list to modern AEAD "
                    "suites (e.g. AES-GCM, ChaCha20-Poly1305) and "
                    "disable the legacy ones."
                ),
                cwe="CWE-326", owasp="A02:2021-Cryptographic Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"tls handshake -> {host}:{port}",
                evidence=(
                    f"cipher={info.cipher_name}, bits={info.cipher_bits}"
                ),
            )

        # ---- expiry ----------------------------------------------------
        seconds_left = _parse_cert_expiry(info.not_after)
        if seconds_left is not None and seconds_left <= 0:
            yield Finding(
                severity="high",
                title="TLS certificate expired",
                description=(
                    f"The certificate for {host}:{port} expired on "
                    f"{info.not_after}. Browsers will refuse to "
                    "connect; clients pinning the cert will hard-fail."
                ),
                remediation=(
                    "Renew the certificate immediately and automate "
                    "renewal (e.g. ACME / Let's Encrypt) so it does "
                    "not happen again."
                ),
                cwe="CWE-298", owasp="A02:2021-Cryptographic Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"tls handshake -> {host}:{port}",
                evidence=f"notAfter={info.not_after}",
            )
        elif seconds_left is not None and seconds_left <= 7 * 86400:
            days = max(0, seconds_left // 86400)
            yield Finding(
                severity="low",
                title="TLS certificate expiring soon",
                description=(
                    f"The certificate for {host}:{port} expires on "
                    f"{info.not_after} (~{days} day(s) from now). "
                    "Renew before expiry or browsers will start to "
                    "refuse the connection."
                ),
                remediation=(
                    "Renew the certificate and automate renewal."
                ),
                cwe="CWE-298", owasp="A02:2021-Cryptographic Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"tls handshake -> {host}:{port}",
                evidence=f"notAfter={info.not_after}",
            )


# Each entry: (service_label, fingerprint_bytes, severity).
_TAKEOVER_FINGERPRINTS: tuple[tuple[str, bytes, Severity], ...] = (
    ("GitHub Pages", b"There isn't a GitHub Pages site here", "high"),
    ("Heroku",       b"No such app",                          "high"),
    ("Heroku",       b"herokucdn.com/error-pages/no-such-app", "high"),
    ("Amazon S3",    b"<Code>NoSuchBucket</Code>",            "high"),
    ("Amazon S3",    b"The specified bucket does not exist",  "high"),
    ("Azure App",    b"404 Web Site not found",               "high"),
    ("Azure Cloud",  b"Web App - Unavailable",                "medium"),
    ("Surge.sh",     b"project not found",                    "medium"),
    ("Fastly",       b"Fastly error: unknown domain",         "high"),
    ("Cargo",        b"<title>404 - Page not found</title>"
                     b"\n<p>The page you were looking for does not exist", "low"),
)


class SubdomainTakeoverCheck(ActiveCheck):
    """Item 13 — fetch the recorded URL fresh and look for known
    "dangling service" fingerprints in the response body. A match
    suggests the DNS still points at e.g. GitHub Pages but the backing
    project has been deleted, so an attacker can re-register and host
    arbitrary content under your domain.

    No external DNS lookup: the recorded host is already pointing
    *somewhere*; we just check whether that somewhere is the "this
    project doesn't exist" page of a known platform.
    """
    name = "subdomain-takeover"
    description = ("Fetch the recorded URL and check the response body "
                   "against a built-in fingerprint table of dangling "
                   "GitHub Pages / Heroku / S3 / Azure / Fastly hosts.")
    meta = RuleMeta(
        id="active:subdomain-takeover",
        intensity="medium",
        title="Subdomain takeover candidate",
        default_severity="high",
        cwe="CWE-350",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "GET the recorded base URL and look for the canonical "
            "'project not found' fingerprint of GitHub Pages, Heroku, "
            "Amazon S3, Azure App Service, Fastly, Surge.sh, etc. A "
            "match indicates the DNS still points at the platform but "
            "the backing project has been deleted, allowing an attacker "
            "to re-register and serve arbitrary content."
        ),
        remediation=(
            "Remove the dangling DNS record, or re-claim the resource "
            "on the platform under the same name. Audit other CNAME "
            "records pointing at the same providers."
        ),
        tags=("dns", "takeover"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        if not ctx.host:
            return
        if not ctx.claim_probe(opts, rule_id, "host", ctx.host):
            return

        req = Request(method="GET", url=ctx.base_url, headers=[], body=b"")
        try:
            pr = send(req)
        except _SAFE_NETWORK_EXC:
            return
        body = pr.response.body[:200_000]
        for service, marker, severity in _TAKEOVER_FINGERPRINTS:
            if marker in body:
                yield Finding(
                    severity=severity,
                    title=f"Subdomain takeover candidate ({service})",
                    description=(
                        f"GET {ctx.base_url} returned a page whose body "
                        f"matches the canonical {service} 'project not "
                        "found' fingerprint. The DNS for this host "
                        "still points at the platform, but the backing "
                        "project appears to have been deleted — anyone "
                        "able to register the same project name there "
                        "can then serve arbitrary content under your "
                        "subdomain."
                    ),
                    remediation=(
                        "Remove the dangling DNS record or re-claim "
                        f"the {service} project under the same name. "
                        "Audit other CNAME records pointing at "
                        f"{service}."
                    ),
                    cwe="CWE-350",
                    owasp="A05:2021-Security Misconfiguration",
                    host=ctx.host, url=ctx.base_url,
                    request_id=ctx.history_id,
                    payload=f"GET {ctx.base_url}",
                    evidence=f"body contains {marker[:80]!r}",
                )
                return  # one finding per host is enough


_DEFAULT_CRED_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("guest", "guest"),
)
# Very loose markers that the response body looks like a "logged in"
# state rather than the login page being re-rendered.
_LOGIN_SUCCESS_MARKERS = (b"logout", b"sign out", b"signout",
                            b"my account", b"dashboard")
# If any of these appear we assume we're still on the login page.
_LOGIN_FAIL_MARKERS = (b"invalid credentials", b"incorrect password",
                        b"login failed", b"try again",
                        b"<input type=\"password\"", b"<input type='password'")


class DefaultCredsSprayCheck(ActiveCheck):
    """Item 15 — opt-in, very-low-volume credential spray.

    Two trigger paths, both gated behind ``allow_credential_probes``:

    1. **HTTP Basic challenge** — the recorded response was a 401 with
       ``WWW-Authenticate: Basic ...``. Send the same URL with each of
       four well-known credential pairs in the ``Authorization`` header
       and flag any non-401 response.
    2. **HTML password form** — the recorded response body contains a
       single ``<input type="password">`` and at least one
       username-shaped sibling input. POST the four credential pairs
       to the form action and flag responses that look "logged in"
       (Location: redirect, or body markers like 'logout' / 'dashboard'
       without 'invalid' / 'try again').

    Hard cap is ``len(_DEFAULT_CRED_PAIRS)`` = 4 attempts per host per
    scan; ``ctx.claim_probe`` enforces that (and the per-rule budget).
    """
    name = "default-creds"
    description = ("Try four well-known credential pairs against an HTTP "
                   "Basic challenge or a simple password form. Off by "
                   "default; enable via the run-page Custom preset.")
    meta = RuleMeta(
        id="active:default-creds",
        intensity="light",
        title="Default credentials accepted",
        default_severity="critical",
        cwe="CWE-521",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "Send four well-known credential pairs (admin/admin, "
            "admin/password, root/root, guest/guest) to a discovered "
            "Basic-auth challenge or a simple password form, and flag "
            "any pair that authenticates."
        ),
        remediation=(
            "Force a password change on first login; reject known "
            "default credentials at the application layer; require "
            "MFA for administrative roles."
        ),
        tags=("auth", "credentials"),
    )

    def _basic_challenge(self, ctx) -> bool:
        if ctx.resp_status != 401:
            return False
        for k, v in ctx.resp_headers:
            if k.lower() == "www-authenticate" and v.lower().startswith("basic"):
                return True
        return False

    def _find_password_form(self, ctx) -> dict | None:
        """Very small HTML scrape for a single password form.

        Returns a dict with keys ``action``, ``method``, ``user_field``,
        ``password_field``, ``extras`` (list of (name, value) for any
        hidden inputs we should round-trip), or None.

        The parser is deliberately conservative; any hint of CSRF / token
        state aborts because we'd just be sending stale tokens.
        """
        body = ctx.resp_body or b""
        if b"<input" not in body or b"password" not in body.lower():
            return None
        try:
            import re
            text = body[:200_000].decode("utf-8", errors="replace")
        except Exception:
            return None
        # Find the first <form ... </form> that contains a type=password.
        form_re = re.compile(r"<form\b[^>]*>(.*?)</form>",
                              re.IGNORECASE | re.DOTALL)
        for m in form_re.finditer(text):
            form_html = m.group(0)
            inner = m.group(1)
            if "type=\"password\"" not in form_html.lower() and \
               "type='password'" not in form_html.lower() and \
               "type=password" not in form_html.lower():
                continue
            # Bail on anything that looks like CSRF protection.
            if re.search(r"name\s*=\s*[\"']?(csrf|_token|"
                          r"authenticity_token|xsrf)",
                          form_html, re.IGNORECASE):
                return None
            # Pull action, method.
            action_m = re.search(r"action\s*=\s*[\"']([^\"'>]+)[\"']",
                                  form_html, re.IGNORECASE)
            method_m = re.search(r"method\s*=\s*[\"']([^\"'>]+)[\"']",
                                  form_html, re.IGNORECASE)
            action = action_m.group(1) if action_m else ""
            method = (method_m.group(1) if method_m else "POST").upper()
            inputs = re.findall(
                r"<input\b([^>]*)/?>", inner, re.IGNORECASE)
            password_name = ""
            user_name = ""
            extras: list[tuple[str, str]] = []
            for attrs in inputs:
                a = attrs.lower()
                name_m = re.search(r"name\s*=\s*[\"']?([^\"' >]+)",
                                    attrs, re.IGNORECASE)
                if not name_m:
                    continue
                name = name_m.group(1)
                value_m = re.search(r"value\s*=\s*[\"']([^\"']*)[\"']",
                                     attrs, re.IGNORECASE)
                value = value_m.group(1) if value_m else ""
                if "type=\"password\"" in a or "type='password'" in a \
                   or "type=password" in a:
                    password_name = name
                    continue
                lname = name.lower()
                if not user_name and any(
                        k in lname for k in ("user", "email",
                                              "login", "username")):
                    user_name = name
                else:
                    extras.append((name, value))
            if not password_name or not user_name:
                continue
            return {
                "action": action,
                "method": method,
                "user_field": user_name,
                "password_field": password_name,
                "extras": extras,
            }
        return None

    def _resolve_action(self, ctx, action: str) -> str:
        if not action:
            return ctx.full_url
        try:
            return up.urljoin(ctx.full_url, action)
        except Exception:
            return ctx.full_url

    def _looks_logged_in(self, status: int, body: bytes) -> bool:
        if 300 <= status < 400:
            return True
        if status >= 400:
            return False
        body = body[:50_000].lower()
        if any(m in body for m in _LOGIN_FAIL_MARKERS):
            return False
        return any(m in body for m in _LOGIN_SUCCESS_MARKERS)

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        if not getattr(opts, "allow_credential_probes", False):
            return
        rule_id = self.meta.id

        # ---- Basic auth path -------------------------------------------
        if self._basic_challenge(ctx):
            for username, password in _DEFAULT_CRED_PAIRS:
                if not ctx.claim_probe(opts, rule_id, "basic",
                                         f"{username}:{password}"):
                    return
                token = base64.b64encode(
                    f"{username}:{password}".encode()).decode("ascii")
                headers = [(k, v) for k, v in _scrub_headers(ctx.req_headers)
                            if k.lower() != "authorization"]
                headers.append(("Authorization", f"Basic {token}"))
                req = Request(method=ctx.method, url=ctx.full_url,
                              headers=headers, body=ctx.req_body)
                try:
                    pr = send(req)
                except _SAFE_NETWORK_EXC:
                    continue
                if pr.response.status != 401:
                    yield Finding(
                        severity="critical",
                        title=f"Default Basic-auth credentials accepted "
                              f"({username}:{password})",
                        description=(
                            f"The server returned status "
                            f"{pr.response.status} when presented with "
                            f"the well-known credential pair "
                            f"'{username}:{password}'. Default creds in "
                            "production are a routine source of full-"
                            "system compromise."
                        ),
                        remediation=(
                            "Force a password change on first login; "
                            "reject known default credentials at the "
                            "application layer; require MFA for "
                            "administrative roles."
                        ),
                        cwe="CWE-521",
                        owasp="A07:2021-Identification and Authentication Failures",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=f"Authorization: Basic <{username}:{password}>",
                        evidence=f"status={pr.response.status} (was 401)",
                    )
                    return  # one critical finding per host is plenty
            return  # exhausted basic pairs without success

        # ---- Form path -------------------------------------------------
        form = self._find_password_form(ctx)
        if not form:
            return
        action_url = self._resolve_action(ctx, form["action"])
        for username, password in _DEFAULT_CRED_PAIRS:
            if not ctx.claim_probe(opts, rule_id, "form",
                                     f"{username}:{password}"):
                return
            payload_pairs = list(form["extras"])
            payload_pairs.append((form["user_field"], username))
            payload_pairs.append((form["password_field"], password))
            body = up.urlencode(payload_pairs).encode("utf-8")
            headers = [(k, v) for k, v in _scrub_headers(ctx.req_headers)
                        if k.lower() != "content-type"]
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
            method = form["method"] if form["method"] in ("GET", "POST") \
                else "POST"
            if method == "GET":
                # Encode in the query string instead.
                glue = "&" if "?" in action_url else "?"
                req = Request(method="GET",
                              url=action_url + glue + body.decode(),
                              headers=headers, body=b"")
            else:
                req = Request(method="POST", url=action_url,
                              headers=headers, body=body)
            try:
                pr = send(req)
            except _SAFE_NETWORK_EXC:
                continue
            if not self._looks_logged_in(pr.response.status,
                                          pr.response.body or b""):
                continue
            yield Finding(
                severity="critical",
                title=f"Default form credentials accepted ({username}:{password})",
                description=(
                    f"POSTing the well-known pair '{username}:{password}' "
                    f"to the form at {action_url} returned a response "
                    "that looks logged-in (3xx redirect, or a body "
                    "containing 'logout' / 'dashboard' without "
                    "'invalid credentials' / 'try again'). Default "
                    "credentials in production are a routine source of "
                    "full-system compromise."
                ),
                remediation=(
                    "Force a password change on first login; reject "
                    "known default credentials at the application "
                    "layer; require MFA for administrative roles."
                ),
                cwe="CWE-521",
                owasp="A07:2021-Identification and Authentication Failures",
                host=ctx.host, url=action_url,
                request_id=ctx.history_id,
                payload=f"{form['user_field']}={username}&{form['password_field']}={password}",
                evidence=f"status={pr.response.status}, looks_logged_in=True",
            )
            return  # one finding per host


BUILTIN_ACTIVE_CHECKS.append(ActiveTLSCheck())
BUILTIN_ACTIVE_CHECKS.append(SubdomainTakeoverCheck())
BUILTIN_ACTIVE_CHECKS.append(DefaultCredsSprayCheck())


# =============== Phase 3 (Tier C) — architectural changes =====================
#
# Items #2, #10, #9. Each one needs more than a single round-trip:
# stored XSS does inject + re-fetch, IDOR sends each request twice
# under two identities, and the race check fans the same request out
# in parallel.


def _byte_3gram_jaccard(a: bytes, b: bytes) -> float:
    """Token Jaccard on byte 3-grams over the first 50 KB.

    Same trick as ``WebCacheDeceptionCheck._similarity`` — cheap and
    good enough for 'is this the same page or a different one?'.
    """
    if not a or not b:
        return 0.0
    a = a[:50_000]
    b = b[:50_000]
    ga = {a[i:i + 3] for i in range(0, len(a) - 2)}
    gb = {b[i:i + 3] for i in range(0, len(b) - 2)}
    if not ga or not gb:
        return 0.0
    inter = len(ga & gb)
    union = len(ga | gb)
    return inter / union if union else 0.0


class StoredXSSCheck(ActiveCheck):
    """#2 — stored XSS (2-step probe).

    For every query / form parameter on a state-changing request,
    inject a marker via the recorded method, then re-fetch the same
    URL as a clean GET (no marker in the request) and flag if the
    marker still appears in the body. The two probes share a single
    ``claim_probe`` slot per parameter — budget-wise they count as
    one logical probe.
    """

    meta = RuleMeta(
        id="active:xss-stored",
        intensity="intrusive",
        title="Stored XSS marker reflected on re-fetch",
        default_severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "Inject a marker into a state-changing request, then re-fetch "
            "the resource with no marker in the URL or body. If the marker "
            "appears in the re-fetch the input is being persisted and "
            "rendered without HTML-encoding."
        ),
        remediation=(
            "HTML-encode persisted user input on output, or store and "
            "render via a templating engine that auto-escapes."
        ),
        tags=("xss", "stored", "injection"),
    )
    name = "xss-stored"
    description = ("Inject a marker via the recorded request, then "
                   "re-fetch the same URL and flag if the marker is "
                   "still rendered.")

    PROBE_TPL = '"\'><wbr-stored-{m}>'

    # Methods we treat as 'this could store something server-side'.
    _STATEFUL_METHODS = ("POST", "PUT", "PATCH")

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        if ctx.method.upper() not in self._STATEFUL_METHODS:
            return

        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(6)
                probe = self.PROBE_TPL.format(m=marker)

                inject = _mutated(ctx, key, probe, loc)
                inj_pr = send(inject)
                if inj_pr.response.status == 0:
                    continue
                # If the inject already echoed it back this is a
                # *reflected* XSS — leave that to ReflectedXSSCheck.

                # Step 2: re-fetch the base URL with no marker.
                fetch_url = ctx.base_url
                fetch_headers = _scrub_headers(ctx.req_headers)
                refetch = Request(
                    method="GET", url=fetch_url,
                    headers=fetch_headers, body=b"",
                )
                rf_pr = send(refetch)
                if rf_pr.response.status == 0:
                    continue
                if probe.encode() in rf_pr.response.body:
                    yield Finding(
                        severity="high",
                        title="Stored XSS marker reflected on re-fetch",
                        description=(
                            f"A marker payload sent in the '{key}' {loc} "
                            f"parameter of a {ctx.method.upper()} request was still "
                            "present in the body returned by a clean "
                            "GET of the same URL afterwards. The input "
                            "is being persisted and rendered without "
                            "HTML-encoding."
                        ),
                        remediation=(
                            "HTML-encode persisted user input on output, "
                            "or use an auto-escaping templating engine."
                        ),
                        cwe="CWE-79", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence=(f"{loc} param '{key}' echoed by clean "
                                   f"GET {fetch_url}"),
                    )


class IDORAltIdentityCheck(ActiveCheck):
    """#10 — IDOR via second identity.

    Re-send the recorded request with the headers in
    ``ActiveOptions.alt_identity`` swapped/added. If the alternate
    identity also gets a 200 whose body is highly similar to the
    baseline, the resource is not enforcing per-user authorisation.
    Defaults to off (``alt_identity = None``).
    """

    meta = RuleMeta(
        id="active:idor-alt-identity",
        intensity="intrusive",
        title="Insecure direct object reference (alt identity)",
        default_severity="high",
        cwe="CWE-639",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Repeat the recorded request under a different identity "
            "(supplied via ActiveOptions.alt_identity). If both responses "
            "are 200 and the bodies are highly similar, the resource is "
            "not scoped to the requesting user."
        ),
        remediation=(
            "Enforce per-user authorisation on every read/write of an "
            "object identified by a guessable parameter; reject "
            "cross-user references at the controller layer."
        ),
        tags=("authz", "idor"),
    )
    name = "idor-alt-identity"
    description = ("Send each recorded request again with an alternate "
                   "identity; flag matching 200 responses with similar bodies.")

    SIMILARITY_THRESHOLD = 0.9

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        if not opts.alt_identity:
            return
        if ctx.resp_status != 200 or not ctx.resp_body:
            return

        rule_id = self.meta.id
        # One probe per (rule, row); key on the URL so we don't repeat
        # for the same logical resource if the row is replayed.
        if not ctx.claim_probe(opts, rule_id, "row", ctx.full_url):
            return

        # Swap/add the alt-identity headers on the recorded request.
        headers = _scrub_headers(ctx.req_headers)
        for k, v in opts.alt_identity.items():
            headers = _replace_header_value(headers, k, v)

        req = Request(method=ctx.method, url=ctx.full_url,
                       headers=headers, body=ctx.req_body)
        try:
            pr = send(req)
        except _SAFE_NETWORK_EXC:
            return

        if pr.response.status != 200 or not pr.response.body:
            return

        sim = _byte_3gram_jaccard(ctx.resp_body, pr.response.body)
        if sim < self.SIMILARITY_THRESHOLD:
            return

        # Surface the alt-identity header names (not values) in evidence
        # so the report doesn't leak whatever cookie the user supplied.
        alt_keys = ", ".join(sorted(opts.alt_identity.keys()))
        yield Finding(
            severity="high",
            title="Insecure direct object reference (alt identity)",
            description=(
                "The recorded request returned 200 under the original "
                "identity. Resending it with the alt-identity headers "
                f"({alt_keys}) also returned 200, and the bodies are "
                f"{int(sim * 100)}% similar "
                f"(>= {int(self.SIMILARITY_THRESHOLD * 100)}%). "
                "The resource is not enforcing per-user authorisation."
            ),
            remediation=(
                "Enforce per-user authorisation on every access to an "
                "object identified by a guessable parameter; reject "
                "cross-user references at the controller layer."
            ),
            cwe="CWE-639", owasp="A01:2021-Broken Access Control",
            host=ctx.host, url=ctx.full_url,
            request_id=ctx.history_id,
            payload=f"alt-identity headers: {alt_keys}",
            evidence=f"jaccard={sim:.2f}, both responses 200",
        )


class RaceConditionCheck(ActiveCheck):
    """#9 — race condition / TOCTOU on state-changing endpoints.

    Re-issues the recorded request N times in parallel and flags when
    the parallel run produces strictly more sub-400 responses than the
    baseline single send. Off by default
    (``ActiveOptions.allow_race_probes``); only inspects state-changing
    methods (POST / PUT / PATCH / DELETE).

    The original gap-list called for the HTTP/2 last-byte sync trick,
    which needs raw socket control we don't have through the normal
    sender. This is the best-effort HTTP/1.1 equivalent: a thread-pool
    fan-out. False-negatives are possible against tightly-locked
    endpoints, but a true race usually shows up well above N=2 anyway.
    """

    meta = RuleMeta(
        id="active:race-condition",
        intensity="intrusive",
        title="Race condition: parallel duplicates accepted",
        default_severity="high",
        cwe="CWE-362",
        owasp="A04:2021-Insecure Design",
        description=(
            "Re-issue the recorded state-changing request in parallel. "
            "If two or more parallel responses succeed where the baseline "
            "single request only allowed one, the endpoint is not "
            "serialising concurrent access."
        ),
        remediation=(
            "Serialise state-changing operations with a database lock, "
            "unique constraint, or idempotency key; reject duplicate "
            "submissions inside the same window."
        ),
        tags=("race", "logic"),
    )
    name = "race-condition"
    description = ("Send N parallel copies of state-changing requests; "
                   "flag when more sub-400 responses come back than a "
                   "single baseline send produced.")

    _STATEFUL_METHODS = ("POST", "PUT", "PATCH", "DELETE")
    _PARALLEL = 8

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        if not opts.allow_race_probes:
            return
        if ctx.method.upper() not in self._STATEFUL_METHODS:
            return
        if ctx.resp_status >= 400:
            return  # baseline failed; nothing to race against

        rule_id = self.meta.id
        if not ctx.claim_probe(opts, rule_id, "row", ctx.full_url):
            return

        req = _baseline(ctx)

        from concurrent.futures import ThreadPoolExecutor

        def _send_one(_i: int) -> int:
            try:
                pr = send(req)
                return int(pr.response.status or 0)
            except _SAFE_NETWORK_EXC:
                return 0

        statuses: list[int] = []
        with ThreadPoolExecutor(max_workers=self._PARALLEL) as pool:
            statuses = list(pool.map(_send_one, range(self._PARALLEL)))

        successes = [s for s in statuses if 0 < s < 400]
        if len(successes) < 2:
            return

        # Distinguish "duplicate created" (multiple 2xx) from "all
        # responded the same idempotent way" (e.g. all 304).
        creates = [s for s in successes if s in (200, 201, 202, 204)]
        if len(creates) < 2:
            return

        yield Finding(
            severity="high",
            title="Race condition: parallel duplicates accepted",
            description=(
                f"{self._PARALLEL} parallel copies of the recorded "
                f"{ctx.method.upper()} request produced "
                f"{len(successes)} sub-400 responses ({creates}). The endpoint accepted "
                "concurrent state changes that the single-request baseline "
                f"(status {ctx.resp_status}) only allowed one of."
            ),
            remediation=(
                "Serialise state-changing operations with a unique "
                "database constraint, row-level lock, or idempotency "
                "key; reject duplicate submissions inside the same "
                "window."
            ),
            cwe="CWE-362", owasp="A04:2021-Insecure Design",
            host=ctx.host, url=ctx.full_url,
            request_id=ctx.history_id,
            payload=f"parallel x{self._PARALLEL}",
            evidence=f"statuses={statuses}",
        )


BUILTIN_ACTIVE_CHECKS.append(StoredXSSCheck())
BUILTIN_ACTIVE_CHECKS.append(IDORAltIdentityCheck())
BUILTIN_ACTIVE_CHECKS.append(RaceConditionCheck())


# =============== Phase 4 (Tier D) — heavy / optional deps =====================
#
# Items #3, #17. Both are gated so the default install stays lean:
# DOM XSS needs Playwright + a browser; the cloud-blob check is plain
# HTTP but only meaningful for S3 / Azure hostnames.


# Hostname patterns that look like an unbranded cloud-blob endpoint.
# Tuple of (regex, service) — regex matches against the hostname only.
_CLOUD_BLOB_HOSTS: tuple[tuple[str, str], ...] = (
    (r"^[a-z0-9.-]+\.s3\.amazonaws\.com$", "Amazon S3"),
    (r"^[a-z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com$", "Amazon S3"),
    (r"^[a-z0-9.-]+\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$", "Amazon S3"),
    (r"^[a-z0-9-]+\.blob\.core\.windows\.net$", "Azure Blob Storage"),
)


def _cloud_blob_service(host: str) -> str | None:
    import re as _re
    h = (host or "").lower()
    for pattern, service in _CLOUD_BLOB_HOSTS:
        if _re.match(pattern, h):
            return service
    return None


# Body markers that confirm an anonymous bucket / container listing.
# Both clouds use XML; we match the wrapping element name only so the
# check is resilient to whitespace and attribute differences.
_CLOUD_LISTING_MARKERS: tuple[bytes, ...] = (
    b"<ListBucketResult",          # S3 (v1 + v2)
    b"<EnumerationResults",        # Azure Blob list
)


class CloudBlobMisconfigCheck(ActiveCheck):
    """#17 — S3 / Azure Blob anonymous listing.

    Only runs when the recorded host looks like an unbranded cloud
    blob endpoint. Issues one unauthenticated GET to the bucket /
    container root with the cloud's listing query (``?list-type=2``
    for S3, ``?restype=container&comp=list`` for Azure) and flags
    when the response body is a listing XML envelope.

    No SDK; just plain HTTP via the standard sender.
    """

    meta = RuleMeta(
        id="active:cloud-blob-misconfig",
        intensity="light",
        title="Cloud blob storage allows anonymous listing",
        default_severity="high",
        cwe="CWE-200",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "An anonymous GET to the cloud blob endpoint returned a "
            "listing XML envelope (S3 ListBucketResult or Azure "
            "EnumerationResults). The bucket / container exposes its "
            "object names without authentication, which often precedes "
            "data exfiltration."
        ),
        remediation=(
            "Disable anonymous list permission on the bucket / "
            "container; require signed URLs or IAM credentials. For "
            "S3 set BlockPublicAcls + IgnorePublicAcls; for Azure set "
            "the container access level to Private."
        ),
        tags=("cloud", "misconfig", "infoleak"),
    )
    name = "cloud-blob-misconfig"
    description = ("GET the bucket/container root with the cloud's "
                   "listing query and flag when it returns an "
                   "unauthenticated object listing.")

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        service = _cloud_blob_service(ctx.host)
        if not service:
            return

        # One probe per host so a row burst on the same bucket doesn't
        # multiply requests.
        if not ctx.claim_probe(opts, rule_id, "host", ctx.host):
            return

        parsed = up.urlsplit(ctx.full_url)
        scheme = parsed.scheme or "https"
        if service == "Amazon S3":
            probe_url = f"{scheme}://{ctx.host}/?list-type=2"
        else:  # Azure
            probe_url = (f"{scheme}://{ctx.host}/?restype=container"
                          f"&comp=list")

        req = Request(method="GET", url=probe_url,
                       headers=[("Accept", "*/*")], body=b"")
        try:
            pr = send(req)
        except _SAFE_NETWORK_EXC:
            return

        if pr.response.status != 200 or not pr.response.body:
            return

        body = pr.response.body[:50_000]
        if not any(marker in body for marker in _CLOUD_LISTING_MARKERS):
            return

        yield Finding(
            severity="high",
            title=f"{service} container/bucket allows anonymous listing",
            description=(
                f"An unauthenticated GET to {probe_url} returned a {service} "
                "listing envelope. The container exposes its object "
                "names without authentication, which often precedes "
                "credential or PII exfiltration."
            ),
            remediation=(
                "Disable anonymous list permission on the bucket / "
                "container; require signed URLs or IAM credentials."
            ),
            cwe="CWE-200",
            owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=probe_url,
            request_id=ctx.history_id,
            payload=probe_url,
            evidence=f"response body contains {service} listing envelope",
        )


# DOM-sink JS snippet executed in the rendered page to look for the
# probe marker landing in dangerous browser APIs. Returns a list of
# sink names that contain the marker.
_DOM_SINK_PROBE_JS = """
(marker) => {
    const sinks = [];
    try {
        if (document.documentElement && document.documentElement.outerHTML
                && document.documentElement.outerHTML.indexOf(marker) !== -1) {
            sinks.push("innerHTML");
        }
        if (document.location && (document.location.href || "")
                .indexOf(marker) !== -1) {
            sinks.push("location.href");
        }
        const inlineScripts = document.querySelectorAll("script:not([src])");
        for (const s of inlineScripts) {
            if ((s.textContent || "").indexOf(marker) !== -1) {
                sinks.push("inline-script");
                break;
            }
        }
        const anchors = document.querySelectorAll("a[href]");
        for (const a of anchors) {
            if ((a.getAttribute("href") || "")
                    .startsWith("javascript:" + marker)
                || (a.getAttribute("href") || "")
                    .indexOf("javascript:" + marker) === 0) {
                sinks.push("anchor-javascript-href");
                break;
            }
        }
    } catch (e) { /* swallow — probe must not crash the page */ }
    return sinks;
}
"""


class DOMXSSCheck(ActiveCheck):
    """#3 — DOM-based XSS via headless Playwright.

    For each query parameter, swap the value for a unique marker,
    render the resulting URL in a headless Chromium and ask the page
    whether the marker landed in a dangerous DOM sink (innerHTML,
    location.href, inline-script body, ``javascript:`` href).

    Skipped silently when Playwright is not installed (the
    ``[browser]`` extra ships it). Opt-in via
    ``ActiveOptions.allow_dom_xss_probes`` because a headless browser
    per probe is expensive.
    """

    meta = RuleMeta(
        id="active:xss-dom",
        intensity="intrusive",
        title="DOM XSS sink reached by URL-controlled marker",
        default_severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "A unique marker placed in a URL query parameter was "
            "rendered into a dangerous DOM sink (innerHTML, "
            "location.href, inline script, or javascript: href). "
            "An attacker controlling that parameter can execute "
            "arbitrary script in the victim's browser."
        ),
        remediation=(
            "Encode URL-derived data before inserting it into the "
            "DOM; prefer textContent over innerHTML; treat any "
            "javascript: URL coming from user input as hostile."
        ),
        tags=("xss", "dom", "browser"),
    )
    name = "xss-dom"
    description = ("Render the URL in a headless browser with a "
                   "marker injected into each query parameter; flag "
                   "when the marker lands in a DOM sink.")

    NAV_TIMEOUT_MS = 8_000

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        if not opts.allow_dom_xss_probes:
            return

        try:
            from .._optdeps import PLAYWRIGHT_AVAILABLE
        except ImportError:
            PLAYWRIGHT_AVAILABLE = False
        if not PLAYWRIGHT_AVAILABLE:
            return
        if ctx.method.upper() != "GET":
            return

        pairs = ctx.query_pairs()
        if not pairs:
            return

        rule_id = self.meta.id

        # Single Playwright session for the whole row — spinning a new
        # browser per parameter is brutally slow.
        from playwright.sync_api import sync_playwright  # local import

        try:
            pw_ctx = sync_playwright().start()
        except _SAFE_NETWORK_EXC:
            return
        try:
            try:
                browser = pw_ctx.chromium.launch(headless=True)
            except _SAFE_NETWORK_EXC:
                return
            try:
                for key, _ in pairs:
                    if not ctx.claim_probe(opts, rule_id, "query", key):
                        continue
                    marker = "RQLDOM" + secrets.token_hex(5)
                    probe_url = _replace_query_value(
                        ctx.full_url, key, marker,
                    )
                    page = browser.new_page()
                    try:
                        try:
                            page.goto(probe_url,
                                       timeout=self.NAV_TIMEOUT_MS,
                                       wait_until="load")
                        except _SAFE_NETWORK_EXC:
                            continue
                        except Exception:                       # noqa: BLE001,S112  # Playwright raises arbitrary browser/JS errors on navigation; skip this probe URL and continue with remaining params
                            continue
                        try:
                            sinks = page.evaluate(
                                _DOM_SINK_PROBE_JS, marker,
                            )
                        except _SAFE_NETWORK_EXC:
                            continue
                        except Exception:                       # noqa: BLE001,S112  # Playwright evaluate raises arbitrary JS errors; skip this probe and continue with remaining params
                            continue
                        if not sinks:
                            continue
                        sink_list = ", ".join(sorted(set(sinks)))
                        yield Finding(
                            severity="high",
                            title=("DOM XSS sink reached by "
                                    f"URL-controlled '{key}'"),
                            description=(
                                f"A unique marker placed in the '{key}' "
                                f"query parameter of {ctx.full_url} landed in the "
                                "following DOM sink(s) after the page "
                                f"rendered: {sink_list}. An attacker controlling "
                                "this parameter can execute arbitrary "
                                "script in the victim's browser."
                            ),
                            remediation=(
                                "Encode URL-derived data before "
                                "inserting it into the DOM; prefer "
                                "textContent over innerHTML; reject "
                                "javascript: URLs from user input."
                            ),
                            cwe="CWE-79",
                            owasp="A03:2021-Injection",
                            host=ctx.host, url=probe_url,
                            request_id=ctx.history_id,
                            payload=marker,
                            evidence=f"DOM sinks reached: {sink_list}",
                        )
                    finally:
                        with contextlib.suppress(*_SAFE_NETWORK_EXC):
                            page.close()
            finally:
                with contextlib.suppress(*_SAFE_NETWORK_EXC):
                    browser.close()
        finally:
            with contextlib.suppress(*_SAFE_NETWORK_EXC):
                pw_ctx.stop()


BUILTIN_ACTIVE_CHECKS.append(CloudBlobMisconfigCheck())
BUILTIN_ACTIVE_CHECKS.append(DOMXSSCheck())


# ---- Phase 19 — auth-flow + CSRF active checks ----

class AccountEnumTimingCheck(ActiveCheck):
    """Detect timing-based account enumeration on login-shaped endpoints.

    Heuristic: when the baseline request carries a username-shaped field
    (``username`` / ``user`` / ``email`` / ``login`` / ...), send N
    "user-exists" probes (replaying the baseline username) and N
    "user-absent" probes (a random non-existent variant) and compare
    medians. A robust median-of-N + MAD threshold (see
    :func:`_is_timing_anomaly`) keeps false positives low on noisy
    networks.

    Opt-in: only runs when ``ActiveOptions.enabled_checks`` includes
    ``"auth-enum-timing"`` or ``intensity_levels`` includes
    ``"intrusive"``.
    """
    meta = RuleMeta(
        id="active:auth-enum-timing",
        intensity="intrusive",
        title="Account enumeration via response-time delta",
        default_severity="medium",
        cwe="CWE-204",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "Compare response times for known-existing vs likely-absent "
            "usernames on a login-shaped endpoint. A consistent delta "
            "leaks valid account names to unauthenticated attackers."
        ),
        remediation=(
            "Ensure the login endpoint takes the same time regardless of "
            "whether the supplied account exists; in particular, always "
            "compute the password hash (or a dummy hash) and emit the "
            "same generic error message."
        ),
        tags=("auth", "enumeration", "timing"),
    )
    name = "auth-enum-timing"
    description = (
        "Time login probes for an existing vs absent username and flag a "
        "robust median delta as account enumeration."
    )
    SAMPLES_PER_SIDE = 7
    MIN_DELTA_MS = 50

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        target = _find_username_field(ctx)
        if target is None:
            return
        location, key, val = target

        # Only state-changing verbs; GET-based login forms are rare and
        # the baseline timing is dominated by a redirect we cannot
        # control here.
        if ctx.method.upper() not in {"POST", "PUT"}:
            return

        # One logical check per (row, target).
        if not ctx.claim_probe(opts, rule_id, location, key):
            return

        absent_marker = f"{val or 'reqlore'}_nx9k2x_zzz"
        exists_req = _mutated(ctx, key, val or "", location)
        absent_req = _mutated(ctx, key, absent_marker, location)

        base_samples: list[int] = []
        probe_samples: list[int] = []
        for _ in range(self.SAMPLES_PER_SIDE):
            try:
                pr_e = send(exists_req)
                base_samples.append(int(pr_e.elapsed_ms))
            except Exception:  # noqa: BLE001 — never block a scan
                return
            try:
                pr_a = send(absent_req)
                probe_samples.append(int(pr_a.elapsed_ms))
            except Exception:  # noqa: BLE001
                return

        # Bidirectional: an "absent slower" delta is the classic Django
        # / Rails default-hash pattern; "exists slower" is the bcrypt
        # path. Flag whichever side is consistently slower.
        if _is_timing_anomaly(base_samples, probe_samples,
                              min_delta_ms=self.MIN_DELTA_MS):
            slower = "absent"
            fast_med, slow_med = (_median(base_samples),
                                  _median(probe_samples))
        elif _is_timing_anomaly(probe_samples, base_samples,
                                min_delta_ms=self.MIN_DELTA_MS):
            slower = "existing"
            fast_med, slow_med = (_median(probe_samples),
                                  _median(base_samples))
        else:
            return

        yield Finding(
            severity="medium",
            title="Account enumeration via response-time delta",
            description=(
                f"The login endpoint at {ctx.full_url} responds noticeably slower for "
                f"{slower} usernames than the other case (median {slow_med} ms "
                f"vs {fast_med} ms across {self.SAMPLES_PER_SIDE} samples each side). An attacker "
                "can use this timing oracle to enumerate valid accounts "
                "without ever needing a valid password."
            ),
            remediation=(
                "Make the login path constant-time with respect to whether "
                "the supplied account exists. Always run the password hash "
                "(or a dummy hash on the absent path) and return the same "
                "generic error message."
            ),
            cwe="CWE-204",
            owasp="A07:2021-Identification and Authentication Failures",
            host=ctx.host, url=ctx.full_url,
            request_id=ctx.history_id,
            payload=f"{key}={absent_marker} vs {key}={val}",
            evidence=(
                f"{location} param '{key}': baseline median "
                f"{_median(base_samples)} ms, absent median "
                f"{_median(probe_samples)} ms over "
                f"{self.SAMPLES_PER_SIDE} samples each"
            ),
            confidence="tentative",
        )


class CSRFTokenValidationCheck(ActiveCheck):
    """Probe whether the server actually validates the CSRF token.

    For each state-changing request that carries a recognisable CSRF
    token (``csrf_token`` / ``_token`` / ``authenticity_token`` /
    ``X-CSRF-Token`` / ...) the check issues two probes:

    1. Token removed entirely.
    2. Token replaced with a syntactically plausible but invalid value.

    Either probe returning a 2xx response means the server did not
    enforce the token. The check skips silently when the original
    response was already non-2xx (we cannot tell anti-CSRF from any
    other rejection) or when the method is not state-changing.
    """
    meta = RuleMeta(
        id="active:csrf-token-not-validated",
        intensity="intrusive",
        title="CSRF token not validated by server",
        default_severity="high",
        cwe="CWE-352",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Re-send the recorded state-changing request with the CSRF "
            "token removed and again with a mangled value. A 2xx response "
            "in either case indicates the server accepts the request "
            "without a valid token."
        ),
        remediation=(
            "Reject every state-changing request whose CSRF token is "
            "missing, malformed, or does not match the session-bound "
            "expected value. Use the framework's built-in CSRF middleware "
            "rather than rolling a custom check."
        ),
        tags=("csrf", "access-control"),
    )
    name = "csrf-token-not-validated"
    description = (
        "Send state-changing requests with the CSRF token removed and "
        "mangled; flag a 2xx response."
    )
    MANGLED_VALUE = "reqlore_invalid_csrf_zzz"

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        if ctx.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        if not (200 <= ctx.resp_status < 300):
            return

        found = _find_csrf_token(ctx)
        if found is None:
            return
        location, key, original = found
        if not original:
            return

        if not ctx.claim_probe(opts, rule_id, location, key):
            return

        # Probe 1 — token mangled (kept the same shape, wrong value).
        if location == "header":
            mangled_req = _mutated_header(ctx, key, self.MANGLED_VALUE)
        else:
            mangled_req = _mutated(ctx, key, self.MANGLED_VALUE, location)
        try:
            pr_mangled = send(mangled_req)
        except Exception:  # noqa: BLE001
            return
        mangled_ok = 200 <= pr_mangled.response.status < 300

        # Probe 2 — token removed entirely.
        if location == "header":
            # Drop the header by filtering it out of the scrubbed list.
            headers = [(k, v) for k, v in _scrub_headers(ctx.req_headers)
                       if k.lower() != key.lower()]
            removed_req = Request(method=ctx.method, url=ctx.full_url,
                                  headers=headers, body=ctx.req_body)
        elif location == "form":
            removed_req = _mutated(ctx, key, "", "form")
        else:
            removed_req = _mutated(ctx, key, "", "query")
        try:
            pr_removed = send(removed_req)
        except Exception:  # noqa: BLE001
            return
        removed_ok = 200 <= pr_removed.response.status < 300

        if not (mangled_ok or removed_ok):
            return

        which = []
        if removed_ok:
            which.append(f"removed (status {pr_removed.response.status})")
        if mangled_ok:
            which.append(f"mangled (status {pr_mangled.response.status})")
        yield Finding(
            severity="high",
            title="CSRF token not validated by server",
            description=(
                "The {l} CSRF token '{k}' on {u} is not validated: the "
                "server accepted the request when the token was {w}. An "
                "attacker can therefore forge this request from a victim's "
                "browser without needing the real token value."
            ).format(l=location, k=key, u=ctx.full_url,
                     w=" and ".join(which)),
            remediation=(
                "Reject state-changing requests whose CSRF token is "
                "missing or does not match the session-bound expected "
                "value. Use the framework's built-in anti-CSRF middleware."
            ),
            cwe="CWE-352",
            owasp="A01:2021-Broken Access Control",
            host=ctx.host, url=ctx.full_url,
            request_id=ctx.history_id,
            payload=f"{location}:{key} removed/mangled",
            evidence=(
                f"baseline status {ctx.resp_status}; "
                f"removed -> {pr_removed.response.status}; "
                f"mangled -> {pr_mangled.response.status}"
            ),
            confidence="firm",
        )


BUILTIN_ACTIVE_CHECKS.append(AccountEnumTimingCheck())
BUILTIN_ACTIVE_CHECKS.append(CSRFTokenValidationCheck())


# ---- Phase 26 -- auth-flow active checks built on MacroStep.step_type ----


def _macro_from_opts(opts: ActiveOptions):
    """Return the auth macro attached to opts, or None.

    Pulled out so both Phase 26 checks share the gate logic and so a
    unit test can drive it without standing up the full scanner.
    """
    auth = getattr(opts, "auth_session", None)
    if auth is None:
        return None
    macro = getattr(auth, "macro", None)
    if macro is None or not getattr(macro, "steps", None):
        return None
    return macro


def _raw_sender_from(send):
    """Return the unwrapped raw sender attached to ``send`` if any.

    The active scanner stashes its ``_raw_send`` closure on the
    auth-wrapped ``_send`` (see ``_send_factory``); falling back to
    ``send`` itself keeps unit tests that pass a bare callable
    working unchanged.
    """
    raw = getattr(send, "raw", None)
    return raw if callable(raw) else send


def _macro_step_adapter(raw_send):
    """Wrap a ``(Request) -> ProbeResult-or-Response`` callable so the
    macro runner sees a ``(Request) -> Response`` callable."""
    def adapter(req):
        try:
            result = raw_send(req)
        except Exception:  # noqa: BLE001 -- never block a scan
            return Response(status=0, headers=[], body=b"",
                            engine="reqlore-macro-replay",
                            error="send-failed")
        # If a ProbeResult-shaped object came back (real scanner),
        # unwrap to the Response. A bare Response (test fakes /
        # raw_send factory) passes through unchanged.
        resp = getattr(result, "response", None)
        return resp if resp is not None else result
    return adapter


class MFABypassCheck(ActiveCheck):
    """Detect whether MFA can be bypassed by skipping the MFA macro step.

    Re-runs the configured auth macro with every step tagged
    ``step_type="mfa"`` removed, then inspects whether a subsequent
    verification step still returns 2xx. When it does, the MFA step
    is decorative -- the server hands out a full authenticated
    session after just the password step, which an attacker who
    captures the victim's credentials can replay without ever
    completing the second factor.

    Gates:
        * ``ActiveOptions.auth_session`` is configured.
        * The macro has at least one step with ``step_type="mfa"``.
        * The macro has at least one step AFTER the last MFA step
          (the "verification" step whose status decides the verdict).
        * The check has not already run against this ``auth_session``
          instance (one-shot per scan, sentinel attribute).
    """
    meta = RuleMeta(
        id="active:mfa-bypass",
        intensity="intrusive",
        title="MFA bypass: server issues authenticated session "
              "without the MFA step",
        default_severity="high",
        cwe="CWE-308",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "Re-runs the configured auth macro with every step "
            "tagged step_type=\"mfa\" removed and observes whether "
            "the verification step still succeeds (2xx). When it "
            "does, an attacker who captures the password alone can "
            "obtain an authenticated session without ever completing "
            "the second factor."
        ),
        remediation=(
            "Treat MFA as an atomic part of authentication: do not "
            "issue an authenticated session cookie until both the "
            "password and the MFA factor have been verified. Reject "
            "any subsequent authenticated request whose session was "
            "issued mid-flow."
        ),
        tags=("auth", "mfa", "session"),
    )
    name = "mfa-bypass"
    description = (
        "Re-run the auth macro without its MFA-tagged steps and "
        "verify whether a later step still authenticates."
    )

    _SENTINEL = "_reqlore_mfa_bypass_checked"

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        macro = _macro_from_opts(opts)
        if macro is None:
            return

        steps = list(macro.steps)
        mfa_indices = [i for i, s in enumerate(steps)
                       if getattr(s, "step_type", "") == "mfa"]
        if not mfa_indices:
            return
        # Need at least one step AFTER the last MFA step to serve as
        # the verification probe; otherwise we cannot tell bypass from
        # "the macro stops at MFA".
        if mfa_indices[-1] >= len(steps) - 1:
            return

        # One-shot per AuthSession: across many rows in the same scan
        # the answer is identical, so only the first row pays the
        # cost. Sentinel is best-effort -- read-only auth objects
        # simply re-fire each row, which is correct but noisier.
        auth = opts.auth_session
        if getattr(auth, self._SENTINEL, False):
            return
        with contextlib.suppress(Exception):
            setattr(auth, self._SENTINEL, True)

        if not ctx.claim_probe(opts, rule_id, "macro", "mfa"):
            return

        from ..macros import Macro as _Macro
        from ..macros import run as _run_macro

        no_mfa_steps = [s for s in steps
                        if getattr(s, "step_type", "") != "mfa"]
        partial_macro = _Macro(
            name=getattr(macro, "name", ""),
            base_headers=dict(getattr(macro, "base_headers", {}) or {}),
            variables=dict(getattr(macro, "variables", {}) or {}),
            steps=no_mfa_steps,
        )

        adapter = _macro_step_adapter(_raw_sender_from(send))
        try:
            run_result = _run_macro(partial_macro, sender=adapter)
        except Exception:  # noqa: BLE001
            return

        if not run_result.steps:
            return
        verify = run_result.steps[-1]
        if verify.error:
            return
        if not (200 <= verify.status < 300):
            return

        verify_step = no_mfa_steps[-1]
        verify_url = verify.request_url or getattr(verify_step, "url", "") \
            or ctx.full_url
        yield Finding(
            severity="high",
            title="MFA bypass: server issues authenticated session "
                  "without the MFA step",
            description=(
                "After re-running the configured auth macro with the "
                f"{len(mfa_indices)} step(s) tagged step_type=\"mfa\" removed, the "
                f"verification step '{verify.step}' returned {verify.status} from {verify_url}. "
                "The server therefore hands out a full authenticated "
                "session after just the password step -- an attacker "
                "who captures the password alone can replay the same "
                "partial flow and pivot straight to the protected "
                "endpoints."
            ),
            remediation=(
                "Treat MFA as atomic: do not issue an authenticated "
                "session cookie until both the password and the MFA "
                "factor have been verified. Reject subsequent "
                "authenticated requests whose session was issued "
                "mid-flow."
            ),
            cwe="CWE-308",
            owasp="A07:2021-Identification and Authentication Failures",
            host=ctx.host, url=verify_url,
            request_id=ctx.history_id,
            payload=(
                f"removed {len(mfa_indices)} step(s) with "
                f"step_type=mfa from auth macro"
            ),
            evidence=(
                f"verification step '{verify.step}' returned "
                f"{verify.status} (no error) after running the "
                f"macro without its MFA step(s)"
            ),
            confidence="firm",
        )


class SessionFixationActiveCheck(ActiveCheck):
    """Detect whether the server rotates the session cookie on login.

    Re-runs the macro's login step (the step tagged ``step_type=
    "login"``) with an attacker-chosen value pre-set on the captured
    session-cookie name(s), then inspects the resulting Set-Cookie
    header(s):

        * If the post-login Set-Cookie carries our injected value,
          the server echoed it -- confirmed fixation.
        * If no Set-Cookie at all was issued, the server kept the
          pre-set value as the active session -- also fixation.
        * If a fresh server-generated value came back, the server
          rotates the session on login -- safe.

    The captured-cookie names are inferred from the login step's
    ``capture`` spec (any capture with
    ``{"source": "header", "name": "Set-Cookie"}``), so the check
    needs no extra configuration when the macro already follows
    the normal convention.
    """
    meta = RuleMeta(
        id="active:session-fixation",
        intensity="intrusive",
        title="Session fixation: server does not rotate session "
              "cookie on login",
        default_severity="high",
        cwe="CWE-384",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "Pre-set a session cookie before invoking the login step "
            "of the configured auth macro and observe whether the "
            "server issues a fresh session identifier. If the "
            "post-login cookie matches the attacker-supplied value "
            "(or is absent), the server is vulnerable to session "
            "fixation."
        ),
        remediation=(
            "Issue a fresh session identifier on every successful "
            "login. Most frameworks expose this as "
            "session.regenerate_id() / request.session.cycle_key() / "
            "session.regenerate() -- combine with the Secure, "
            "HttpOnly, and SameSite cookie flags."
        ),
        tags=("auth", "session", "fixation"),
    )
    name = "session-fixation"
    description = (
        "Pre-set a session cookie before the login step and check "
        "whether the server rotates it."
    )

    FIXATION_VALUE = "reqlore_fixated_session_zzz"
    _SENTINEL = "_reqlore_session_fixation_checked"

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        macro = _macro_from_opts(opts)
        if macro is None:
            return

        steps = list(macro.steps)
        login_idx = next(
            (i for i, s in enumerate(steps)
             if getattr(s, "step_type", "") == "login"),
            -1,
        )
        if login_idx < 0:
            return
        login_step = steps[login_idx]

        cookie_names: list[str] = []
        for var, spec in (getattr(login_step, "capture", {}) or {}).items():
            if not isinstance(spec, dict):
                continue
            src = (spec.get("source") or "").lower()
            name = (spec.get("name") or "").lower()
            if src == "header" and name == "set-cookie":
                cookie_names.append(var)
        if not cookie_names:
            return

        auth = opts.auth_session
        if getattr(auth, self._SENTINEL, False):
            return
        with contextlib.suppress(Exception):
            setattr(auth, self._SENTINEL, True)

        if not ctx.claim_probe(opts, rule_id, "macro", "login"):
            return

        from ..macros import Macro as _Macro
        from ..macros import MacroStep as _MacroStep
        from ..macros import run as _run_macro

        injected_cookie = "; ".join(
            f"{n}={self.FIXATION_VALUE}" for n in cookie_names
        )
        fixated_steps: list = []
        for i, s in enumerate(steps):
            if i != login_idx:
                fixated_steps.append(s)
                continue
            headers = dict(getattr(s, "headers", {}) or {})
            existing = ""
            existing_key = None
            for k, v in list(headers.items()):
                if k.lower() == "cookie":
                    existing_key = k
                    existing = v or ""
                    break
            if existing_key is not None:
                headers.pop(existing_key, None)
            headers["Cookie"] = (
                f"{existing}; {injected_cookie}" if existing else injected_cookie
            )
            fixated_steps.append(_MacroStep(
                name=s.name, method=s.method, url=s.url,
                headers=headers, body=s.body,
                capture=dict(getattr(s, "capture", {}) or {}),
                timeout_s=getattr(s, "timeout_s", 10.0),
                follow_redirects=getattr(s, "follow_redirects", True),
                step_type=getattr(s, "step_type", ""),
            ))

        fixated_macro = _Macro(
            name=getattr(macro, "name", ""),
            base_headers=dict(getattr(macro, "base_headers", {}) or {}),
            variables=dict(getattr(macro, "variables", {}) or {}),
            steps=fixated_steps,
        )

        adapter = _macro_step_adapter(_raw_sender_from(send))
        try:
            run_result = _run_macro(fixated_macro, sender=adapter)
        except Exception:  # noqa: BLE001
            return

        login_result = next(
            (sr for sr in run_result.steps if sr.step == login_step.name),
            None,
        )
        if login_result is None:
            return
        if login_result.error:
            return
        # Only act on a successful login -- a 4xx/5xx tells us the
        # server rejected our pre-set cookie outright, which is the
        # safe behaviour.
        if not (200 <= login_result.status < 400):
            return

        captured = login_result.captured or {}
        fixation_outcomes: list[tuple[str, str]] = []
        for var in cookie_names:
            value = (captured.get(var) or "").strip()
            if not value:
                fixation_outcomes.append((var, "not-rotated"))
            elif self.FIXATION_VALUE in value:
                fixation_outcomes.append((var, "echoed"))
            # else: server returned a fresh cookie -- safe.

        if not fixation_outcomes:
            return

        modes = ", ".join(f"{n} ({mode})" for n, mode in fixation_outcomes)
        yield Finding(
            severity="high",
            title="Session fixation: server does not rotate session "
                  "cookie on login",
            description=(
                "After pre-setting the cookie(s) [{names}] to a known "
                "attacker value, the login step on {u} did not rotate "
                "the session identifier: {modes}. An attacker who can "
                "fix a victim's session cookie (via XSS, a sibling "
                "subdomain, or a meta-refresh) can therefore log into "
                "the victim's authenticated session by sharing the "
                "fixed value."
            ).format(
                names=", ".join(cookie_names),
                u=login_step.url,
                modes=modes,
            ),
            remediation=(
                "Issue a fresh session identifier on every successful "
                "login. Most frameworks expose this as "
                "session.regenerate_id() / request.session.cycle_key() "
                "/ session.regenerate(). Combine with the Secure, "
                "HttpOnly, and SameSite cookie flags."
            ),
            cwe="CWE-384",
            owasp="A07:2021-Identification and Authentication Failures",
            host=ctx.host, url=login_step.url,
            request_id=ctx.history_id,
            payload=(
                f"pre-set Cookie: {injected_cookie} "
                f"on step '{login_step.name}'"
            ),
            evidence=(
                f"login step returned status {login_result.status}; "
                f"captured outcomes: {modes}"
            ),
            confidence="firm",
        )


BUILTIN_ACTIVE_CHECKS.append(MFABypassCheck())
BUILTIN_ACTIVE_CHECKS.append(SessionFixationActiveCheck())


# ---- runner ----

@dataclass
class ActiveScanResult:
    rows_scanned: int = 0
    probes_sent: int = 0
    findings_added: int = 0
    # B.0.4 — number of probes that hit a 429.
    throttled_count: int = 0
    # B.0.5 — number of history rows skipped because they were out of scope.
    skipped_out_of_scope: int = 0
    # Phase 2 — number of (row, check) pairs the intensity filter blocked.
    # Surfaced in the run summary so the operator can see whether a more
    # aggressive tier would have changed the result.
    skipped_by_intensity: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    })
    # Phase 2 — breakdown of *findings* by the intensity tier of the check
    # that fired them. Useful for the report: "12 findings came from light
    # probes, 3 from medium, 0 from intrusive."
    by_intensity: dict[str, int] = field(default_factory=lambda: {
        "light": 0, "medium": 0, "intrusive": 0,
    })
    elapsed_ms: int = 0
    # Phase 9 — populated when ``ActiveOptions.wall_clock_seconds``
    # was set and the cap was reached mid-run. ``rows_skipped_deadline``
    # is the count of in-scope rows we never started because the
    # deadline had already elapsed.
    aborted_due_to_deadline: bool = False
    deadline_seconds: float | None = None
    rows_skipped_deadline: int = 0
    # Phase 10 — mirrored from ``ActiveOptions.auth_session.stats``
    # at the end of the run so the result is a self-contained
    # serialisable summary (the AuthSession instance itself contains
    # an in-memory cookie jar that must not be reported).
    auth_macro_runs: int = 0
    auth_macro_failures: int = 0
    session_recoveries: int = 0
    validity_probes: int = 0
    csrf_token_refetches: int = 0
    csrf_token_swaps: int = 0
    # Phase 12 — audit prioritisation. ``prioritised`` is True when
    # the run iterated rows in scored order instead of id-DESC.
    # ``top_score`` / ``top_history_id`` capture the row that was
    # audited first so the operator can confirm the scoring picked
    # the row they expected. Zero / 0 / 0 when prioritisation was
    # off.
    prioritised: bool = False
    top_score: float = 0.0
    top_history_id: int = 0
    # Phase 13 — JavaScript analysis pipeline counters. All zero
    # when ``js_analysis_mode='off'``. ``js_pages_analysed`` counts
    # distinct responses the pipeline actually inspected (after the
    # content-type gate); ``js_static_findings`` and
    # ``js_dynamic_hits`` count the raw stage outputs;
    # ``js_cross_confirmed`` counts findings the dynamic stage
    # promoted from ``firm`` → ``certain``.
    js_pages_analysed: int = 0
    js_static_findings: int = 0
    js_dynamic_hits: int = 0
    js_cross_confirmed: int = 0


def _host_in_scope(host: str, scope_rules: list[dict]) -> bool:
    """Backwards-compat shim. The canonical implementation lives in
    ``reqlore.scanner.scope_utils.host_in_scope`` so the passive
    scanner, active scanner, and live worker all apply identical
    semantics. Kept here as a thin alias because plugins / tests may
    have imported the private name.
    """
    from .scope_utils import host_in_scope as _shared
    return _shared(host, scope_rules)


class ActiveScanner:
    """Run the active checks against recorded history rows."""

    def __init__(self, checks: list[ActiveCheck] | None = None,
                 sender: Callable[[Request], Response] | None = None):
        self.checks = list(checks if checks is not None else BUILTIN_ACTIVE_CHECKS)
        self._sender = sender  # tests inject a fake sender

    def _send_factory(self, opts: ActiveOptions, counter: list[int],
                       result: ActiveScanResult | None = None,
                       project: object | None = None,
                       ctx: ActiveContext | None = None):
        def _raw_send(req: Request) -> Response:
            # Lowest-level outgoing call. Used both by the probe path
            # below and by the Phase 10 ``AuthSession`` (which needs
            # to fire CSRF-token re-fetches and validity probes
            # without recursing back through the per-probe gates).
            if self._sender is not None:
                return self._sender(req)
            return httpx_engine.send(
                req, timeout=opts.timeout_s,
                follow_redirects=opts.follow_redirects,
            )

        def _send(req: Request) -> ProbeResult:
            # Phase 10 — inject session cookies + bearer headers from
            # the auth manager, and (if configured) refresh any CSRF
            # token in the body. We pass ``_raw_send`` rather than
            # ``_send`` so CSRF / validity-probe fetches do not
            # recursively apply auth or count against the probe
            # budget.
            if opts.auth_session is not None:
                with contextlib.suppress(*_SAFE_NETWORK_EXC):
                    req = opts.auth_session.apply_to_request(
                        req, sender=_raw_send,
                    )
            # B.0.3 — if a refresh macro is configured, periodically re-run it
            # and merge the returned headers/cookies into the next request.
            if (opts.replay_macro is not None and project is not None
                    and opts.replay_every_n_probes > 0
                    and counter[0] > 0
                    and counter[0] % opts.replay_every_n_probes == 0):
                try:
                    extras = opts.replay_macro(project) or {}
                except _SAFE_NETWORK_EXC:
                    extras = {}
                if extras:
                    have = {k.lower() for k, _ in req.headers}
                    merged = list(req.headers)
                    for k, v in extras.items():
                        if k.lower() in have:
                            merged = [(hk, v) if hk.lower() == k.lower() else (hk, hv)
                                       for hk, hv in merged]
                        else:
                            merged.append((k, v))
                    req = Request(method=req.method, url=req.url,
                                  headers=merged, body=req.body)

            t0 = time.monotonic()
            resp = _raw_send(req)
            elapsed = int((time.monotonic() - t0) * 1000)
            counter[0] += 1

            # B.0.4 — honour 429 + Retry-After, then re-send once.
            if resp.status == 429:
                if result is not None:
                    result.throttled_count += 1
                ra_raw = resp.header("Retry-After") if hasattr(resp, "header") else None
                try:
                    wait_s = float(ra_raw) if ra_raw else opts.retry_after_default_s
                except (TypeError, ValueError):
                    wait_s = opts.retry_after_default_s
                wait_s = max(0.0, min(wait_s, 60.0))
                if wait_s:
                    time.sleep(wait_s)
                t1 = time.monotonic()
                resp = _raw_send(req)
                elapsed = int((time.monotonic() - t1) * 1000)
                counter[0] += 1

            # Phase 10 — let the auth manager opportunistically harvest
            # rotated cookies and (if its threshold is reached) fire a
            # validity probe + macro recovery before the next probe.
            if opts.auth_session is not None:
                try:
                    opts.auth_session.notify_response(req, resp)
                    opts.auth_session.maybe_revalidate(sender=_raw_send)
                except _SAFE_NETWORK_EXC:
                    pass

            if ctx is not None:
                ctx.probes_log.append(
                    ("", req.url, req.method, len(req.body or b""),
                     resp.status, elapsed)
                )
                # B.4 — capture a byte-for-byte reproducer for the most recent
                # probe. The runner attaches this tuple to the next finding
                # the check yields. We synthesise canonical HTTP/1.1 bytes
                # because some engines (h2/h3, curl-cffi) don't expose them.
                ctx.last_probe_repro = (
                    _request_to_raw(req),
                    _response_to_raw(resp),
                    req.method, req.url, resp.status, elapsed,
                )
            if opts.rate_delay_ms:
                time.sleep(opts.rate_delay_ms / 1000.0)
            return ProbeResult(req, resp, elapsed)
        # Phase 26 -- expose the unwrapped sender so auth-flow checks
        # (MFA bypass, session fixation) can re-run the configured auth
        # macro without the AuthSession wrapper re-injecting the
        # already-primed session cookies on every step.
        _send.raw = _raw_send  # type: ignore[attr-defined]
        return _send

    def run_on_row(self, row, *, options: ActiveOptions | None = None
                    ) -> list[Finding]:
        opts = options or ActiveOptions()
        ctx = ActiveContext.from_row(row)
        counter = [0]
        send = self._send_factory(opts, counter, ctx=ctx)
        findings: list[Finding] = []
        from .rules import intensity_for
        for check in self.checks:
            # Two-stage filter: explicit ``enabled_checks`` wins over
            # the coarse intensity gate so a test that names a single
            # intrusive check by name still runs that check, even
            # though the default ``intensity_levels`` excludes
            # intrusive. When ``enabled_checks`` is ``None`` we fall
            # through to the intensity filter.
            if opts.enabled_checks:
                if check.name not in opts.enabled_checks:
                    continue
            elif intensity_for(check) not in opts.intensity_levels:
                continue
            try:
                # OAST-aware checks accept the options kwarg; older checks do not.
                import inspect
                sig = inspect.signature(check.run)
                if "opts" in sig.parameters:
                    findings.extend(check.run(ctx, send, opts=opts))
                else:
                    findings.extend(check.run(ctx, send))
            except _SAFE_NETWORK_EXC as exc:
                findings.append(Finding(
                    severity="info",
                    title=f"Active check raised: {check.name}",
                    description=f"{type(exc).__name__}: {exc}",
                    host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                    evidence=repr(exc)[:200],
                ))
        return findings

    def run_on_project(self, project, *, options: ActiveOptions | None = None,
                        host: str | None = None,
                        limit: int = 50) -> ActiveScanResult:
        """Run active checks across the most recent `limit` history rows.
        Active scans send traffic — keep `limit` small."""
        from ..findings_bus import record_finding
        from .rules import apply_meta_defaults, id_for, intensity_for, meta_for
        opts = options or ActiveOptions()
        t0 = time.monotonic()
        result = ActiveScanResult()
        # Phase 9 — record the configured cap on the result so the
        # report renderer can show what limit was in force, even if
        # we finish under it.
        deadline_at: float | None = None
        if opts.wall_clock_seconds is not None and opts.wall_clock_seconds > 0:
            deadline_at = t0 + float(opts.wall_clock_seconds)
            result.deadline_seconds = float(opts.wall_clock_seconds)
        # B.0.5 — apply project scope rules.
        try:
            scope_rules = list(project.list_scope())
        except AttributeError:
            scope_rules = []
        # Phase 10 — prime the auth session once before any probes
        # fire. Failures here are non-fatal: we still let the run
        # proceed unauthenticated and surface the failure via the
        # macro_failures stat.
        if opts.auth_session is not None and not getattr(
                opts.auth_session, "primed", False):
            with contextlib.suppress(*_SAFE_NETWORK_EXC):
                opts.auth_session.prime(sender=self._sender)
        rows = project.list_history(limit=limit, host=host)
        # Phase 12 — optional audit prioritisation. When enabled we
        # re-order the row list using the same insertion-point
        # enumeration the per-row probe loop will run anyway, so the
        # cost is amortised. The scoring is deterministic and pure,
        # but parser failures can still happen on hostile blobs —
        # any exception leaves the row order untouched and emits a
        # diagnostic flag so the operator can see the prioritiser
        # bailed.
        if opts.prioritise:
            try:
                from .prioritise import (
                    ScoringWeights as _Weights,
                )
                from .prioritise import (
                    prioritise_queue as _prioritise,
                )
                ranked = _prioritise(
                    rows,
                    weights=_Weights(
                        surface=opts.surface_weight,
                        interest=opts.interest_weight,
                    ),
                    recompute_after_row=(
                        opts.prioritise_recompute_after_row
                    ),
                )
                rows = [r for r, _ in ranked]
                result.prioritised = True
                if ranked:
                    _, top = ranked[0]
                    result.top_score = float(top.score)
                    result.top_history_id = int(top.history_id)
            except Exception:  # noqa: BLE001,S110 — never block a scan; prioritiser is best-effort ranking, leave rows in id-DESC order if scoring fails
                # Leave rows in their original id-DESC order if
                # scoring blew up. ``prioritised`` stays False so
                # the operator can tell the prioritiser was
                # requested but skipped.
                pass
        for row in rows:
            # Phase 9 — wall-clock guard. Checked between rows so a
            # row that started before the deadline gets to finish
            # cleanly rather than being torn down mid-probe.
            if deadline_at is not None and time.monotonic() >= deadline_at:
                if _host_in_scope(row.host, scope_rules):
                    result.rows_skipped_deadline += 1
                result.aborted_due_to_deadline = True
                continue
            if not _host_in_scope(row.host, scope_rules):
                result.skipped_out_of_scope += 1
                continue
            result.rows_scanned += 1
            ctx = ActiveContext.from_row(row)
            counter = [0]
            send = self._send_factory(opts, counter, result=result,
                                       project=project, ctx=ctx)
            for check in self.checks:
                # Two-stage filter: explicit ``enabled_checks`` wins;
                # otherwise gate by intensity. Skipped-by-intensity is
                # counted so the run summary shows how much coverage
                # the chosen tier set is leaving on the table.
                tier = intensity_for(check)
                if opts.enabled_checks:
                    if check.name not in opts.enabled_checks:
                        continue
                elif tier not in opts.intensity_levels:
                    result.skipped_by_intensity += 1
                    continue
                rid = id_for(check, prefix="active")
                meta = meta_for(check)
                check_findings: list[Finding] = []
                try:
                    import inspect
                    sig = inspect.signature(check.run)
                    if "opts" in sig.parameters:
                        check_findings.extend(check.run(ctx, send, opts=opts))
                    else:
                        check_findings.extend(check.run(ctx, send))
                except _SAFE_NETWORK_EXC as exc:
                    check_findings.append(Finding(
                        severity="info",
                        title=f"Active check raised: {check.name}",
                        description=f"{type(exc).__name__}: {exc}",
                        host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                        evidence=repr(exc)[:200],
                    ))
                if not check_findings:
                    project.record_rule_run(
                        rule_id=rid, host=ctx.host, url=ctx.full_url,
                        fired=False, reason="no_match",
                    )
                    continue
                for f in check_findings:
                    apply_meta_defaults(f, meta)
                    # B.0.2 — stamp probes_attempted into evidence so reports
                    # show how aggressive the rule had to be to fire.
                    attempted = ctx.probes_for(rid)
                    evidence = f.evidence or ""
                    if attempted and "probes_attempted=" not in evidence:
                        sep = " | " if evidence else ""
                        evidence = f"{evidence}{sep}probes_attempted={attempted}"
                    # B.4 — attach the last-probe reproducer so the reporter /
                    # CLI can render a curl one-liner that re-fires the probe.
                    repro = ctx.last_probe_repro
                    fid = record_finding(
                        project, source="scanner", rule_id=rid,
                        severity=f.severity, title=f.title,
                        description=f.description, remediation=f.remediation,
                        references=f.references,
                        cwe=f.cwe, owasp=f.owasp,
                        host=f.host, url=f.url,
                        request_id=f.request_id, response_id=f.response_id,
                        evidence=evidence, payload=f.payload,
                        reproduction=repro,
                        # Phase 3 — forward the rule's self-declared
                        # confidence. Bus may still demote on WAF /
                        # error-page fingerprint match.
                        confidence=getattr(f, "confidence", "firm"),
                    )
                    if fid is not None:
                        result.findings_added += 1
                        result.by_severity[f.severity] = (
                            result.by_severity.get(f.severity, 0) + 1
                        )
                        result.by_intensity[tier] = (
                            result.by_intensity.get(tier, 0) + 1
                        )
            result.probes_sent = result.probes_sent + counter[0]
            # Phase 13 — JavaScript analysis pipeline. Runs once per
            # row, after the per-check loop has finished. Defensive:
            # any pipeline failure is swallowed so a buggy esprima /
            # Playwright path can never block a scan. The hook is a
            # no-op when ``opts.js_analysis_mode == 'off'``.
            if opts.js_analysis_mode != "off":
                try:
                    from .js_pipeline import run_js_pipeline
                    js_result = run_js_pipeline(
                        response_body=ctx.resp_body,
                        response_headers=ctx.resp_headers,
                        host=ctx.host,
                        url=ctx.full_url,
                        mode=opts.js_analysis_mode,
                    )
                    if js_result.pages_analysed:
                        result.js_pages_analysed += (
                            js_result.pages_analysed
                        )
                        result.js_dynamic_hits += len(
                            js_result.dynamic_hits
                        )
                        result.js_cross_confirmed += (
                            js_result.cross_confirmed_count
                        )
                        # Surface every static finding via the
                        # findings bus so suppressions /
                        # fingerprinting / dedupe all apply.
                        for jf in js_result.static_findings:
                            jf_host = jf.host or ctx.host
                            jf_url = jf.url or ctx.full_url
                            fid = record_finding(
                                project,
                                source="scanner",
                                rule_id="js-static:dom-xss",
                                severity=jf.severity,
                                title=jf.title,
                                description=jf.description,
                                remediation=jf.remediation,
                                references=jf.references,
                                cwe=jf.cwe,
                                owasp=jf.owasp,
                                host=jf_host,
                                url=jf_url,
                                request_id=ctx.history_id,
                                evidence=jf.evidence,
                                payload=jf.payload,
                                confidence=getattr(
                                    jf, "confidence", "firm"),
                            )
                            if fid is not None:
                                result.findings_added += 1
                                result.js_static_findings += 1
                                result.by_severity[jf.severity] = (
                                    result.by_severity.get(
                                        jf.severity, 0) + 1
                                )
                except Exception:  # noqa: BLE001,S110 — never block a scan; JS-pipeline finding emission is best-effort and its failure must not abort the scan
                    pass
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        # Phase 10 — mirror the auth-session counters into the result
        # so the report renderer / web flash can show how busy the
        # auth machinery was without needing to introspect the
        # session object itself (which still holds an in-memory
        # cookie jar we must not surface).
        if opts.auth_session is not None:
            stats = getattr(opts.auth_session, "stats", None)
            if stats is not None:
                result.auth_macro_runs = getattr(stats, "macro_runs", 0)
                result.auth_macro_failures = getattr(stats, "macro_failures", 0)
                result.session_recoveries = getattr(stats, "session_recoveries", 0)
                result.validity_probes = getattr(stats, "validity_probes", 0)
                result.csrf_token_refetches = getattr(stats, "csrf_token_refetches", 0)
                result.csrf_token_swaps = getattr(stats, "csrf_token_swaps", 0)
        return result
