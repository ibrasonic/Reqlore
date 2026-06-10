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
import fnmatch
import json
import secrets
import ssl
import time
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import httpx

from ..engines import Request, Response
from ..engines import httpx_engine
from .findings import Finding
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

    def claim_probe(self, opts: "ActiveOptions", rule_id: str,
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
    def from_row(cls, row) -> "ActiveContext":
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
        return [tuple(p.split("=", 1)) if "=" in p else (p, "")
                for p in parts[1].split("&") if p]

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
        return [tuple(p.split("=", 1)) if "=" in p else (p, "")
                for p in text.split("&") if p]


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
             send: Callable[[Request], ProbeResult]) -> Iterable[Finding]:
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
            out.append((k, new)); replaced = True
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


# ---- individual checks ----

class ReflectedXSSCheck(ActiveCheck):
    meta = RuleMeta(
        id="active:xss-reflected",
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
                            "A marker payload sent in the '{p}' {l} parameter "
                            "appears verbatim in the response body, which "
                            "indicates the input is not HTML-encoded. An "
                            "attacker could turn this into a stored or "
                            "reflected cross-site-scripting attack."
                        ).format(p=key, l=loc),
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
                        description=("Appending a single quote to the '{p}' "
                                     "{l} parameter produced a {e} database "
                                     "error in the response. This is a strong "
                                     "indicator of SQL injection.").format(
                                     p=key, l=loc, e=engine),
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
                            description=("The '{p}' {l} parameter controls the "
                                         "redirect Location. An attacker can "
                                         "send users to any site they choose "
                                         "via a trusted link."
                                         ).format(p=key, l=loc),
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
                    if expected.encode() in pr.response.body[:200_000]:
                        # avoid the case where the literal already existed
                        if expected.encode() not in ctx.resp_body[:200_000]:
                            yield Finding(
                                severity="critical",
                                title=f"SSTI: template expression evaluated ({engine})",
                                description=(
                                    "The '{p}' {l} parameter was rendered by a "
                                    "{e} template engine. The probe '{pr}' "
                                    "evaluated to {ex}. Server-side template "
                                    "injection typically allows remote code "
                                    "execution."
                                ).format(p=key, l=loc, e=engine, pr=probe, ex=expected),
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
                        description=("Appending a sleep payload to the '{p}' {l} "
                                     "parameter made the response take {t} ms "
                                     "(baseline {b} ms). This delay strongly "
                                     "suggests the input is being executed as a "
                                     "shell command.").format(
                                     p=key, l=loc, t=pr.elapsed_ms, b=base_ms),
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
                    description=("A marker payload sent in the '{h}' request "
                                 "header was echoed verbatim in the response "
                                 "body, suggesting headers are reflected without "
                                 "HTML encoding.").format(h=hdr),
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
                    description=("A marker payload placed in the '{n}' cookie "
                                 "value was echoed verbatim in the response "
                                 "body. Cookie-borne XSS often bypasses "
                                 "request-body sanitisation.").format(n=name),
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
                            description=("A traversal probe sent in the '{p}' "
                                         "{l} parameter caused the response to "
                                         "include the contents of a sensitive "
                                         "OS file. This is local file inclusion."
                                         ).format(p=key, l=loc),
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
                    description=("Replacing the JSON field '{p}' with the "
                                 "Mongo operator `{{\"$ne\": null}}` produced a "
                                 "differential response (baseline status={bs} "
                                 "len={bl}; probe status={ns} len={nl}). The "
                                 "operator was likely passed to the database "
                                 "driver unfiltered."
                                 ).format(p=key, bs=base_status, bl=base_len,
                                          ns=new_status, nl=new_len),
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
                                 "Origin '{o}' in its Access-Control-Allow-Origin "
                                 "header and sent Access-Control-Allow-Credentials: "
                                 "true. An attacker page can issue authenticated "
                                 "cross-origin requests and read the responses."
                                 ).format(o=origin),
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
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    })
    elapsed_ms: int = 0


def _host_in_scope(host: str, scope_rules: list[dict]) -> bool:
    """Apply project scope rules using fnmatch on host patterns.

    Semantics (matches the existing UI):
      * No enabled `include` rules → everything is in-scope.
      * Any enabled `exclude` rule that matches → out of scope (wins over include).
      * Otherwise: must match at least one enabled `include` rule.

    Only `target == "host"` rules are considered — the scanner runs per-row
    keyed on host, so path-shaped scope is honoured elsewhere.
    """
    if not scope_rules:
        return True
    includes = [r for r in scope_rules
                if r.get("enabled") and r.get("kind") == "include"
                and (r.get("target") or "host") == "host"]
    excludes = [r for r in scope_rules
                if r.get("enabled") and r.get("kind") == "exclude"
                and (r.get("target") or "host") == "host"]
    for r in excludes:
        if fnmatch.fnmatch(host, r["pattern"]):
            return False
    if not includes:
        return True
    return any(fnmatch.fnmatch(host, r["pattern"]) for r in includes)


class ActiveScanner:
    """Run the active checks against recorded history rows."""

    def __init__(self, checks: list[ActiveCheck] | None = None,
                 sender: Callable[[Request], Response] | None = None):
        self.checks = list(checks if checks is not None else BUILTIN_ACTIVE_CHECKS)
        self._sender = sender  # tests inject a fake sender

    def _send_factory(self, opts: ActiveOptions, counter: list[int],
                       result: ActiveScanResult | None = None,
                       project: object | None = None,
                       ctx: "ActiveContext | None" = None):
        def _send(req: Request) -> ProbeResult:
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
            if self._sender is not None:
                resp = self._sender(req)
            else:
                resp = httpx_engine.send(
                    req, timeout=opts.timeout_s,
                    follow_redirects=opts.follow_redirects,
                )
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
                if self._sender is not None:
                    resp = self._sender(req)
                else:
                    resp = httpx_engine.send(
                        req, timeout=opts.timeout_s,
                        follow_redirects=opts.follow_redirects,
                    )
                elapsed = int((time.monotonic() - t1) * 1000)
                counter[0] += 1

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
        return _send

    def run_on_row(self, row, *, options: ActiveOptions | None = None
                    ) -> list[Finding]:
        opts = options or ActiveOptions()
        ctx = ActiveContext.from_row(row)
        counter = [0]
        send = self._send_factory(opts, counter, ctx=ctx)
        findings: list[Finding] = []
        for check in self.checks:
            if opts.enabled_checks and check.name not in opts.enabled_checks:
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
        from .rules import apply_meta_defaults, id_for, meta_for
        opts = options or ActiveOptions()
        t0 = time.monotonic()
        result = ActiveScanResult()
        # B.0.5 — apply project scope rules.
        try:
            scope_rules = list(project.list_scope())
        except AttributeError:
            scope_rules = []
        rows = project.list_history(limit=limit, host=host)
        for row in rows:
            if not _host_in_scope(row.host, scope_rules):
                result.skipped_out_of_scope += 1
                continue
            result.rows_scanned += 1
            ctx = ActiveContext.from_row(row)
            counter = [0]
            send = self._send_factory(opts, counter, result=result,
                                       project=project, ctx=ctx)
            for check in self.checks:
                if opts.enabled_checks and check.name not in opts.enabled_checks:
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
                    )
                    if fid is not None:
                        result.findings_added += 1
                        result.by_severity[f.severity] = (
                            result.by_severity.get(f.severity, 0) + 1
                        )
            result.probes_sent = result.probes_sent + counter[0]
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result
