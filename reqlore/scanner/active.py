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
    # Phase 1b — opt-in network-heavy probes. Off by default because they
    # bypass the standard httpx engine (smuggling needs raw socket bytes;
    # the field-suggestion probe sends a deliberately broken query).
    allow_smuggling_probes: bool = False
    # Phase 2 — opt-in credential-spray probe. Off by default because
    # sending login attempts to a real production system is a noisy and
    # potentially account-locking action.
    allow_credential_probes: bool = False


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
    WORDLIST: tuple[tuple[str, str, str], ...] = (
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
        if v.startswith(("http://", "https://", "//")):
            return True
        return False

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
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
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
    if name == "TLSv1.0":
        return True
    return False


def _is_weak_cipher(name: str, bits: int) -> bool:
    if not name:
        return False
    upper = name.upper()
    if any(tok in upper for tok in _WEAK_CIPHER_TOKENS):
        return True
    return bits and bits < 128


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
_TAKEOVER_FINGERPRINTS: tuple[tuple[str, bytes, str], ...] = (
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
                    f"{username}:{password}".encode("utf-8")).decode("ascii")
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
