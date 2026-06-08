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
import json
import re
import secrets
import time
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..engines import Request, Response
from ..engines import httpx_engine
from .findings import Finding
from .passive import _split_http  # reuse


# ---- options ----

@dataclass
class ActiveOptions:
    """Per-scan policy. Defaults are conservative."""
    max_requests_per_check: int = 4
    rate_delay_ms: int = 0
    timeout_s: float = 10.0
    follow_redirects: bool = False
    enabled_checks: list[str] | None = None  # None == all built-ins
    oast: object | None = None        # LocalOAST instance for OOB checks
    oast_wait_s: float = 0.6          # how long to poll OAST after a probe


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
    text = body.decode("utf-8", errors="replace")
    pairs = up.parse_qsl(text, keep_blank_values=True)
    out = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, new)); replaced = True
        else:
            out.append((k, v))
    return up.urlencode(out, doseq=True).encode("utf-8")


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


# ---- individual checks ----

class ReflectedXSSCheck(ActiveCheck):
    name = "xss-reflected"
    description = ("Replace each query / form value with a marker probe and "
                   "check whether the probe appears unescaped in the response.")

    PROBE_TPL = '"\'><wbr-{m}>'

    def run(self, ctx, send):
        n = 0
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if n >= 4:
                    return
                marker = secrets.token_hex(4)
                probe = self.PROBE_TPL.format(m=marker)
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                n += 1
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
    name = "sqli-error"
    description = ("Append a single quote to each parameter and look for "
                   "database error signatures in the response.")
    ERROR_SIGS = (
        b"You have an error in your SQL syntax",
        b"unclosed quotation mark",
        b"quoted string not properly terminated",
        b"PostgreSQL query failed",
        b"ORA-00933", b"ORA-00921", b"ORA-01756",
        b"SQLite3::SQLException",
        b"Microsoft OLE DB Provider",
        b"PG::SyntaxError",
    )

    def run(self, ctx, send):
        n = 0
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if n >= 4:
                    return
                probe = (val or "1") + "'"
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                n += 1
                body = pr.response.body[:65_536]
                for sig in self.ERROR_SIGS:
                    if sig in body:
                        yield Finding(
                            severity="high", title="SQL error triggered by quote injection",
                            description=("Appending a single quote to the '{p}' "
                                         "{l} parameter produced a database "
                                         "error in the response. This is a "
                                         "strong indicator of SQL injection.").format(p=key, l=loc),
                            remediation=("Use parameterised queries / prepared "
                                         "statements. Never concatenate user "
                                         "input into SQL text."),
                            cwe="CWE-89", owasp="A03:2021-Injection",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=probe,
                            evidence=sig.decode("latin-1", errors="replace"),
                        )
                        break


class OpenRedirectCheck(ActiveCheck):
    name = "open-redirect"
    description = ("Replace URL-shaped parameters with an attacker-controlled "
                   "host and confirm the server issues a 3xx Location to it.")
    PROBE = "https://reqlore-redir.invalid/"

    def run(self, ctx, send):
        n = 0
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if n >= 4:
                    return
                if not val:
                    continue
                if not (val.startswith("http://") or val.startswith("https://")
                        or val.startswith("/")):
                    continue
                req = _mutated(ctx, key, self.PROBE, loc)
                pr = send(req)
                n += 1
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
    name = "ssti"
    description = ("Inject template-engine probes (e.g. {{7*7}}) and look for "
                   "the evaluated result in the response.")
    PROBES = (
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
    )

    def run(self, ctx, send):
        n = 0
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for probe, expected in self.PROBES:
                    if n >= 4:
                        return
                    req = _mutated(ctx, key, probe, loc)
                    pr = send(req)
                    n += 1
                    if expected.encode() in pr.response.body[:200_000]:
                        # avoid the case where the literal '49' already existed
                        if expected.encode() not in ctx.resp_body[:200_000]:
                            yield Finding(
                                severity="critical", title="SSTI: template expression evaluated",
                                description=(
                                    "The '{p}' {l} parameter was rendered by a "
                                    "template engine. The probe '{pr}' evaluated "
                                    "to {ex}. Server-side template injection "
                                    "typically allows remote code execution."
                                ).format(p=key, l=loc, pr=probe, ex=expected),
                                remediation=("Never render untrusted input as a "
                                             "template. Use safe rendering APIs "
                                             "that treat input as plain text."),
                                cwe="CWE-1336", owasp="A03:2021-Injection",
                                host=ctx.host, url=ctx.full_url,
                                request_id=ctx.history_id,
                                payload=probe, evidence=f"output contains {expected}",
                            )
                            return


class TimeBasedOSCommandCheck(ActiveCheck):
    name = "os-cmd-time"
    description = ("Send a sleep-style payload and confirm the response is "
                   "delayed by roughly the requested duration.")
    PROBES = (
        ";sleep 5;",
        "&& ping -n 6 127.0.0.1",
        "$(sleep 5)",
        "|sleep 5",
    )
    DELAY_S = 5

    def run(self, ctx, send):
        # Baseline: how long does the unmodified request take?
        baseline = send(_baseline(ctx))
        base_ms = baseline.elapsed_ms
        n = 1
        for loc, pairs in (("query", ctx.query_pairs()),
                           ("form", ctx.form_pairs())):
            for key, val in pairs:
                if n >= 4:
                    return
                probe = (val or "") + self.PROBES[0]
                req = _mutated(ctx, key, probe, loc)
                pr = send(req)
                n += 1
                # Allow some slack: 0.7 × DELAY × 1000 ms above baseline.
                if pr.elapsed_ms - base_ms > int(self.DELAY_S * 0.7 * 1000):
                    yield Finding(
                        severity="critical", title="Time-based OS command injection",
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
                        evidence=f"baseline {base_ms} ms vs probe {pr.elapsed_ms} ms",
                    )


class JWTAlgNoneAcceptanceCheck(ActiveCheck):
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
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    })
    elapsed_ms: int = 0


class ActiveScanner:
    """Run the active checks against recorded history rows."""

    def __init__(self, checks: list[ActiveCheck] | None = None,
                 sender: Callable[[Request], Response] | None = None):
        self.checks = list(checks if checks is not None else BUILTIN_ACTIVE_CHECKS)
        self._sender = sender  # tests inject a fake sender

    def _send_factory(self, opts: ActiveOptions, counter: list[int]):
        def _send(req: Request) -> ProbeResult:
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
            if opts.rate_delay_ms:
                time.sleep(opts.rate_delay_ms / 1000.0)
            return ProbeResult(req, resp, elapsed)
        return _send

    def run_on_row(self, row, *, options: ActiveOptions | None = None
                    ) -> list[Finding]:
        opts = options or ActiveOptions()
        ctx = ActiveContext.from_row(row)
        counter = [0]
        send = self._send_factory(opts, counter)
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
            except Exception as exc:  # pragma: no cover — defensive
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
        opts = options or ActiveOptions()
        t0 = time.monotonic()
        result = ActiveScanResult()
        rows = project.list_history(limit=limit, host=host)
        for row in rows:
            result.rows_scanned += 1
            for f in self.run_on_row(row, options=opts):
                project.add_finding(
                    severity=f.severity, title=f.title, cwe=f.cwe, owasp=f.owasp,
                    host=f.host, url=f.url, request_id=f.request_id,
                    response_id=f.response_id, evidence=f.evidence, payload=f.payload,
                    dedupe_key=f.dedupe_key,
                )
                result.findings_added += 1
                result.by_severity[f.severity] = result.by_severity.get(f.severity, 0) + 1
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result
