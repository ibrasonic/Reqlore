"""Built-in passive rules. Each rule is a callable
``(ctx: RuleContext) -> Iterable[Finding]`` registered in :data:`BUILTIN_RULES`.

Rules are kept pure and side-effect-free so the scanner engine can run them in
any order, batch them, or hand them to a plugin sandbox later.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .findings import Finding

# ---- shared parsing helpers ----

_HEADER_SEP = b"\r\n\r\n"


def _split_http(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    sep = raw.find(_HEADER_SEP)
    if sep < 0:
        return "", [], raw
    head_b = raw[:sep]
    body = raw[sep + 4:]
    try:
        head = head_b.decode("latin-1")
    except UnicodeDecodeError:
        head = head_b.decode("latin-1", errors="replace")
    lines = head.split("\r\n")
    start = lines[0] if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return start, headers, body


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    n = name.lower()
    for k, v in headers:
        if k.lower() == n:
            return v
    return None


def _all_headers(headers: list[tuple[str, str]], name: str) -> list[str]:
    n = name.lower()
    return [v for k, v in headers if k.lower() == n]


@dataclass
class RuleContext:
    """Everything a passive rule may inspect for one history row."""
    history_id: int
    host: str
    url: str
    method: str
    status: int
    req_start_line: str
    req_headers: list[tuple[str, str]]
    req_body: bytes
    resp_start_line: str
    resp_headers: list[tuple[str, str]]
    resp_body: bytes

    @classmethod
    def from_row(cls, row) -> "RuleContext":
        rs, rh, rb = _split_http(row.req_blob)
        ss, sh, sb = _split_http(row.resp_blob)
        return cls(
            history_id=row.id, host=row.host, url=row.url, method=row.method,
            status=row.status, req_start_line=rs, req_headers=rh, req_body=rb,
            resp_start_line=ss, resp_headers=sh, resp_body=sb,
        )


Rule = Callable[[RuleContext], Iterable[Finding]]

# ---- rules ----

_SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium", "CWE-319", "A02:2021-Cryptographic Failures",
        "Browser will continue speaking HTTP on later visits, exposing traffic to "
        "downgrade attacks.",
        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on "
        "every HTTPS response.",
    ),
    "Content-Security-Policy": (
        "medium", "CWE-1021", "A05:2021-Security Misconfiguration",
        "No CSP — the browser has no allowlist for scripts, styles, or framing, "
        "which makes XSS and clickjacking easier to weaponise.",
        "Add a Content-Security-Policy header. Start with a strict baseline like "
        "\"default-src 'self'; object-src 'none'; base-uri 'self'\" and tighten.",
    ),
    "X-Content-Type-Options": (
        "low", "CWE-693", "A05:2021-Security Misconfiguration",
        "Without 'nosniff', browsers may MIME-sniff responses and execute "
        "text/plain payloads as scripts.",
        "Send 'X-Content-Type-Options: nosniff' on every response.",
    ),
    "Referrer-Policy": (
        "info", "CWE-200", "A01:2021-Broken Access Control",
        "No Referrer-Policy means full URLs (and any query-string tokens) may be "
        "leaked to third-party sites.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "Permissions-Policy": (
        "info", "CWE-693", "A05:2021-Security Misconfiguration",
        "No Permissions-Policy: the page can use every powerful browser feature "
        "(camera, mic, geolocation, …) without an explicit allowlist.",
        "Send a Permissions-Policy header listing only the features you need.",
    ),
}


def rule_missing_security_headers(ctx: RuleContext) -> Iterable[Finding]:
    # Only audit successful HTML-ish responses
    ct = (_header(ctx.resp_headers, "content-type") or "").lower()
    if not (200 <= ctx.status < 400):
        return
    if "html" not in ct and "json" not in ct and ct != "":
        return
    for name, (sev, cwe, owasp, desc, remed) in _SECURITY_HEADERS.items():
        if _header(ctx.resp_headers, name) is None:
            yield Finding(
                severity=sev, title=f"Missing response header: {name}",
                description=desc, remediation=remed, cwe=cwe, owasp=owasp,
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"{ctx.resp_start_line} — header '{name}' not present",
            )


def rule_xframe_options(ctx: RuleContext) -> Iterable[Finding]:
    if not (200 <= ctx.status < 400):
        return
    xfo = _header(ctx.resp_headers, "x-frame-options")
    csp = _header(ctx.resp_headers, "content-security-policy") or ""
    # CSP frame-ancestors supersedes XFO; only flag if neither is present.
    if xfo or "frame-ancestors" in csp.lower():
        return
    yield Finding(
        severity="low", title="No clickjacking defence",
        description=(
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, "
            "so any site can embed this page in a frame and trick a logged-in "
            "user into clicking on actions they cannot see."
        ),
        remediation=(
            "Send 'X-Frame-Options: DENY' or, preferably, a CSP with "
            "'frame-ancestors \\'none\\'' (or an explicit allowlist)."
        ),
        cwe="CWE-1021", owasp="A05:2021-Security Misconfiguration",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=ctx.resp_start_line,
    )


_SET_COOKIE_RE = re.compile(r"^([^=;]+)=", re.IGNORECASE)


def rule_insecure_cookies(ctx: RuleContext) -> Iterable[Finding]:
    for raw in _all_headers(ctx.resp_headers, "set-cookie"):
        m = _SET_COOKIE_RE.match(raw)
        name = m.group(1).strip() if m else "(unnamed)"
        low = raw.lower()
        problems: list[str] = []
        if "secure" not in low:
            problems.append("missing 'Secure' (cookie may leak over HTTP)")
        if "httponly" not in low:
            problems.append("missing 'HttpOnly' (cookie readable from JavaScript)")
        if "samesite" not in low:
            problems.append("missing 'SameSite' (cookie sent on cross-site requests)")
        if not problems:
            continue
        yield Finding(
            severity="medium", title=f"Insecure cookie: {name}",
            description="The Set-Cookie header is missing one or more hardening "
                        "attributes: " + "; ".join(problems) + ".",
            remediation="Reissue the cookie with 'Secure; HttpOnly; SameSite=Lax' "
                        "(or 'Strict') unless you have a documented reason not to.",
            cwe="CWE-614", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=raw[:300],
        )


def rule_server_banner(ctx: RuleContext) -> Iterable[Finding]:
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        v = _header(ctx.resp_headers, name)
        if not v:
            continue
        # Only flag when a version number is leaked.
        if not re.search(r"\d", v):
            continue
        yield Finding(
            severity="info", title=f"Software version disclosed in {name}",
            description=f"The {name} header reveals '{v}'. Attackers can map "
                        "this to known CVEs.",
            remediation=f"Remove or sanitise the {name} response header in your "
                        "reverse proxy or application config.",
            cwe="CWE-200", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=f"{name}: {v}",
        )


_CORS_WILDCARD_WITH_CREDS = (
    "Setting 'Access-Control-Allow-Origin: *' alongside "
    "'Access-Control-Allow-Credentials: true' is forbidden by the spec and "
    "browsers will reject it — but if any client honours it, every site can "
    "read the response with the user's cookies."
)


def rule_cors(ctx: RuleContext) -> Iterable[Finding]:
    acao = _header(ctx.resp_headers, "access-control-allow-origin")
    acac = _header(ctx.resp_headers, "access-control-allow-credentials")
    if not acao:
        return
    if acao == "*" and acac and acac.lower() == "true":
        yield Finding(
            severity="high", title="Dangerous CORS: '*' with credentials",
            description=_CORS_WILDCARD_WITH_CREDS,
            remediation="Echo a specific, validated Origin instead of '*' when "
                        "credentials are required, or drop the credentials flag.",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=f"ACAO: {acao} / ACAC: {acac}",
        )
        return
    # Reflected origin without an allowlist is a classic finding.
    req_origin = _header(ctx.req_headers, "origin")
    if req_origin and acao == req_origin and acac and acac.lower() == "true":
        yield Finding(
            severity="high", title="Reflected Origin with credentials",
            description="The response copies whatever Origin the request sent and "
                        "allows credentials, so any attacker-controlled origin "
                        "can read the response with the user's cookies.",
            remediation="Maintain a server-side allowlist of trusted origins and "
                        "only echo origins that match it.",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=f"Origin: {req_origin} -> ACAO: {acao}",
        )


_TRACE_SIGNATURES = (
    (b"Traceback (most recent call last):", "Python traceback"),
    (b"at java.", "Java stack trace"),
    (b"<title>Whitelabel Error Page</title>", "Spring Boot default error page"),
    (b"on line <b>", "PHP error with file/line numbers"),
    (b"Microsoft OLE DB Provider", "ASP/SQL Server error"),
    (b"You have an error in your SQL syntax", "MySQL error"),
    (b"PostgreSQL query failed", "PostgreSQL error"),
    (b"ORA-00", "Oracle error"),
    (b"System.NullReferenceException", ".NET null-reference exception"),
)


def rule_verbose_error(ctx: RuleContext) -> Iterable[Finding]:
    if ctx.status < 400:
        return
    # Only look at a window so a 50 MB body doesn't slow things down.
    window = ctx.resp_body[:65536]
    for sig, label in _TRACE_SIGNATURES:
        if sig in window:
            yield Finding(
                severity="medium", title=f"Verbose error page: {label}",
                description="The server returned a debugging-style error page that "
                            "discloses internal file paths, library versions, or "
                            "query fragments. Attackers use these to fingerprint "
                            "the stack and to craft follow-up payloads.",
                remediation="Disable debug mode in production and route 4xx/5xx "
                            "to a generic error page that does not leak internals.",
                cwe="CWE-209", owasp="A04:2021-Insecure Design",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=sig.decode("latin-1", errors="replace"),
            )
            return  # one finding per response is enough


def rule_directory_listing(ctx: RuleContext) -> Iterable[Finding]:
    if not (200 <= ctx.status < 300):
        return
    body = ctx.resp_body[:32768]
    if (b"<title>Index of /" in body
            or b"Directory listing for" in body
            or b"<h1>Index of" in body):
        yield Finding(
            severity="medium", title="Directory listing exposed",
            description="The server is returning an auto-generated file index. "
                        "This often discloses backup files, credentials, or "
                        "source code that should not be public.",
            remediation="Disable directory autoindex on the web server or place "
                        "an index file in the directory.",
            cwe="CWE-548", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=ctx.resp_start_line,
        )


_SENSITIVE_PATHS = (
    "/.git/", "/.env", "/.svn/", "/wp-config.php", "/.DS_Store",
    "/server-status", "/phpinfo.php", "/.aws/credentials",
    "/web.config", "/composer.lock",
)


def rule_sensitive_paths(ctx: RuleContext) -> Iterable[Finding]:
    if ctx.status >= 400:
        return
    low = ctx.url.lower()
    for path in _SENSITIVE_PATHS:
        if path in low:
            yield Finding(
                severity="high", title=f"Sensitive file accessible: {path}",
                description=f"The path {path} is being served with a successful "
                            "status, which means version-control data, "
                            "credentials, or configuration is exposed.",
                remediation="Remove the file from the web root or block the path "
                            "at the reverse proxy.",
                cwe="CWE-538", owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=ctx.url,
            )


def rule_mixed_content(ctx: RuleContext) -> Iterable[Finding]:
    # http resource referenced from an https page
    if not ctx.url.lower().startswith("https://"):
        return
    body = ctx.resp_body[:200_000]
    if b'src="http://' in body or b"src='http://" in body:
        yield Finding(
            severity="low", title="Mixed content reference",
            description="An https:// page includes an http:// subresource. "
                        "Browsers will either block the resource (passive types "
                        "may be upgraded) or warn the user, and on-path attackers "
                        "can swap it for a malicious payload.",
            remediation="Serve every subresource over HTTPS or use protocol-relative "
                        "URLs that match the parent document.",
            cwe="CWE-319", owasp="A02:2021-Cryptographic Failures",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence='src="http://...',
        )


_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _b64url_decode(s: bytes) -> bytes:
    pad = (-len(s)) % 4
    try:
        return base64.urlsafe_b64decode(s + b"=" * pad)
    except Exception:
        return b""


def rule_jwt_none_alg(ctx: RuleContext) -> Iterable[Finding]:
    # Inspect both directions — tokens in headers, cookies, body, …
    for label, blob in (("request", ctx.req_body), ("response", ctx.resp_body)):
        for m in _JWT_RE.finditer(blob[:200_000]):
            tok = m.group(0)
            try:
                header = json.loads(_b64url_decode(tok.split(b".")[0]) or b"{}")
            except (ValueError, json.JSONDecodeError):
                continue
            alg = str(header.get("alg", "")).lower()
            if alg in ("none", ""):
                yield Finding(
                    severity="critical", title="JWT with alg=none",
                    description=f"A JSON Web Token in the {label} declares 'alg: "
                                "none', meaning the signature is not verified. "
                                "Anyone can mint a token that the server will "
                                "trust as authentic.",
                    remediation="Reject 'alg=none' on the server and pin the "
                                "expected algorithm explicitly.",
                    cwe="CWE-347", owasp="A07:2021-Identification and Authentication Failures",
                    host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                    evidence=tok.decode("latin-1", errors="replace")[:120],
                )


def rule_open_redirect_hint(ctx: RuleContext) -> Iterable[Finding]:
    """Heuristic: 3xx response whose Location header is fully attacker-supplied."""
    if not (300 <= ctx.status < 400):
        return
    loc = _header(ctx.resp_headers, "location") or ""
    if not loc:
        return
    # If a query parameter value equals the Location, that's a strong open-redirect hint.
    # Parse the request URL's query.
    q_split = ctx.url.split("?", 1)
    if len(q_split) < 2:
        return
    for pair in q_split[1].split("&"):
        if "=" not in pair:
            continue
        _, val = pair.split("=", 1)
        # Be liberal in decoding — only one common encoding.
        try:
            from urllib.parse import unquote
            decoded = unquote(val)
        except Exception:
            decoded = val
        if decoded and (decoded == loc or decoded.rstrip("/") == loc.rstrip("/")):
            yield Finding(
                severity="medium", title="Possible open redirect",
                description="A redirect Location appears to be taken verbatim from "
                            "a request parameter. Attackers can craft links that "
                            "look legitimate but bounce the user to a phishing "
                            "site after they log in.",
                remediation="Validate the redirect target against a server-side "
                            "allowlist of hosts/paths and reject everything else.",
                cwe="CWE-601", owasp="A01:2021-Broken Access Control",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"Location: {loc}",
            )
            return


def rule_basic_auth_over_http(ctx: RuleContext) -> Iterable[Finding]:
    if ctx.url.lower().startswith("https://"):
        return
    auth = _header(ctx.req_headers, "authorization") or ""
    if auth.lower().startswith("basic "):
        yield Finding(
            severity="high", title="HTTP Basic Auth over plain HTTP",
            description="Credentials are being sent base64-encoded over an "
                        "unencrypted channel. Anyone on-path can decode them "
                        "trivially.",
            remediation="Move the endpoint behind HTTPS and consider replacing "
                        "Basic Auth with a session token or OAuth.",
            cwe="CWE-319", owasp="A02:2021-Cryptographic Failures",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=auth[:80],
        )


# Order matters only for human readability of the resulting list.
BUILTIN_RULES: list[Rule] = [
    rule_missing_security_headers,
    rule_xframe_options,
    rule_insecure_cookies,
    rule_server_banner,
    rule_cors,
    rule_verbose_error,
    rule_directory_listing,
    rule_sensitive_paths,
    rule_mixed_content,
    rule_jwt_none_alg,
    rule_open_redirect_hint,
    rule_basic_auth_over_http,
]


def run_passive(row, rules: list[Rule] | None = None) -> list[Finding]:
    """Run every rule against one history row, returning Findings."""
    ctx = RuleContext.from_row(row)
    out: list[Finding] = []
    for r in (rules or BUILTIN_RULES):
        try:
            out.extend(r(ctx))
        except Exception as exc:  # pragma: no cover — defensive
            # A rule must never crash the scanner. Surface the failure as an
            # info-level finding so users know to investigate or disable it.
            out.append(Finding(
                severity="info", title=f"Scanner rule raised: {r.__name__}",
                description=f"{type(exc).__name__}: {exc}",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=repr(exc)[:200],
            ))
    return out
