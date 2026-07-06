"""Built-in passive rules. Each rule is a callable
``(ctx: RuleContext) -> Iterable[Finding]`` registered in :data:`BUILTIN_RULES`.

Rules are kept pure and side-effect-free so the scanner engine can run them in
any order, batch them, or hand them to a plugin sandbox later.
"""
from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, cast

from .findings import Finding
from .rules import RuleMeta, rule_meta

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
    def from_row(cls, row) -> RuleContext:
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


@rule_meta(RuleMeta(
    id="passive:missing_security_headers",
    title="Missing security response headers",
    default_severity="medium",
    cwe="CWE-693",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Audits successful HTML/JSON responses for the common set of defensive "
        "headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, "
        "Permissions-Policy) and emits one finding per missing header."
    ),
    remediation=(
        "Add the missing headers at the reverse-proxy or framework layer."
    ),
    tags=("headers", "baseline"),
))
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
                severity=cast("Literal['info', 'low', 'medium', 'high', 'critical']", sev),
                title=f"Missing response header: {name}",
                description=desc, remediation=remed, cwe=cwe, owasp=owasp,
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"{ctx.resp_start_line} — header '{name}' not present",
            )


@rule_meta(RuleMeta(
    id="passive:xframe_options",
    title="No clickjacking defence",
    default_severity="low",
    cwe="CWE-1021",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Flags responses that set neither X-Frame-Options nor a CSP "
        "frame-ancestors directive."
    ),
    remediation=(
        "Send 'X-Frame-Options: DENY' or, preferably, a CSP with "
        "\"frame-ancestors 'none'\" (or an explicit allowlist)."
    ),
    tags=("headers", "clickjacking"),
))
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


@rule_meta(RuleMeta(
    id="passive:insecure_cookies",
    title="Insecure Set-Cookie attributes",
    default_severity="medium",
    cwe="CWE-614",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Inspects every Set-Cookie header for missing Secure / HttpOnly / "
        "SameSite hardening attributes."
    ),
    remediation=(
        "Reissue the cookie with 'Secure; HttpOnly; SameSite=Lax' (or "
        "'Strict') unless you have a documented reason not to."
    ),
    tags=("cookies", "session"),
))
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


@rule_meta(RuleMeta(
    id="passive:server_banner",
    title="Software version disclosed in response banner",
    default_severity="info",
    cwe="CWE-200",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Flags responses whose Server / X-Powered-By / X-AspNet*-Version "
        "headers expose a versioned product string."
    ),
    remediation=(
        "Remove or sanitise version-disclosing headers at the reverse proxy."
    ),
    tags=("info-leak", "fingerprinting"),
))
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


@rule_meta(RuleMeta(
    id="passive:cors",
    title="Dangerous CORS configuration",
    default_severity="high",
    cwe="CWE-942",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Detects two abusive CORS patterns: wildcard ACAO with credentials, "
        "and reflected request Origin with credentials."
    ),
    remediation=(
        "Maintain a server-side allowlist of trusted origins and only echo "
        "origins that match it; never combine '*' with credentials."
    ),
    tags=("cors",),
))
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


@rule_meta(RuleMeta(
    id="passive:verbose_error",
    title="Verbose error page leaks server internals",
    default_severity="medium",
    cwe="CWE-209",
    owasp="A04:2021-Insecure Design",
    description=(
        "Looks for debug-style stack traces and SQL/runtime error signatures "
        "in 4xx/5xx responses."
    ),
    remediation=(
        "Disable debug mode in production and route 4xx/5xx to a generic "
        "error page that does not leak internals."
    ),
    tags=("info-leak", "error-handling"),
))
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


@rule_meta(RuleMeta(
    id="passive:directory_listing",
    title="Directory listing exposed",
    default_severity="medium",
    cwe="CWE-548",
    owasp="A05:2021-Security Misconfiguration",
    description="Detects auto-generated 'Index of /' style file listings.",
    remediation=(
        "Disable directory autoindex on the web server or place an index "
        "file in the directory."
    ),
    tags=("info-leak",),
))
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


@rule_meta(RuleMeta(
    id="passive:sensitive_paths",
    title="Sensitive file or directory accessible",
    default_severity="high",
    cwe="CWE-538",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Flags URLs that successfully serve known-sensitive paths such as "
        "/.git/, /.env, /.aws/credentials, /server-status, etc."
    ),
    remediation=(
        "Remove the file from the web root or block the path at the "
        "reverse proxy."
    ),
    tags=("info-leak",),
))
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


@rule_meta(RuleMeta(
    id="passive:mixed_content",
    title="Mixed HTTP/HTTPS content reference",
    default_severity="low",
    cwe="CWE-319",
    owasp="A02:2021-Cryptographic Failures",
    description=(
        "Detects http:// subresources referenced from an https:// page."
    ),
    remediation=(
        "Serve every subresource over HTTPS or use protocol-relative URLs."
    ),
    tags=("tls", "mixed-content"),
))
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


@rule_meta(RuleMeta(
    id="passive:jwt_none_alg",
    title="JWT with alg=none",
    default_severity="critical",
    cwe="CWE-347",
    owasp="A07:2021-Identification and Authentication Failures",
    description=(
        "Decodes JWT-shaped tokens in requests and responses and flags any "
        "whose header declares alg=none (or empty)."
    ),
    remediation=(
        "Reject 'alg=none' on the server and pin the expected algorithm "
        "explicitly."
    ),
    tags=("jwt", "crypto"),
))
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


@rule_meta(RuleMeta(
    id="passive:open_redirect_hint",
    title="Possible open redirect",
    default_severity="medium",
    cwe="CWE-601",
    owasp="A01:2021-Broken Access Control",
    description=(
        "Heuristic: a 3xx response whose Location header equals a value "
        "taken verbatim from a request query parameter."
    ),
    remediation=(
        "Validate the redirect target against a server-side allowlist of "
        "hosts/paths and reject everything else."
    ),
    tags=("redirect",),
))
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


@rule_meta(RuleMeta(
    id="passive:basic_auth_over_http",
    title="HTTP Basic Auth over plain HTTP",
    default_severity="high",
    cwe="CWE-319",
    owasp="A02:2021-Cryptographic Failures",
    description=(
        "Flags Authorization: Basic credentials sent on a plain-HTTP URL."
    ),
    remediation=(
        "Move the endpoint behind HTTPS and consider replacing Basic Auth "
        "with a session token or OAuth."
    ),
    tags=("tls", "auth"),
))
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


# ============================================================================
# B.1 additions
# ============================================================================


@rule_meta(RuleMeta(
    id="passive:cors-null-origin",
    title="CORS allows the 'null' origin",
    default_severity="medium",
    cwe="CWE-942",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Access-Control-Allow-Origin is set to the literal string 'null', "
        "which is the Origin value used by sandboxed iframes, file:// pages, "
        "and some redirected requests. Any attacker page can claim Origin: null."
    ),
    remediation=(
        "Never echo 'null' in ACAO; maintain a server-side allowlist of "
        "real origins."
    ),
    tags=("cors",),
))
def rule_cors_null_origin(ctx: RuleContext) -> Iterable[Finding]:
    acao = _header(ctx.resp_headers, "access-control-allow-origin")
    if acao and acao.strip().lower() == "null":
        yield Finding(
            severity="medium", title="CORS allows the 'null' origin",
            description=("Access-Control-Allow-Origin: null lets sandboxed "
                          "iframes and other null-origin contexts read the "
                          "response \u2014 attackers can spawn those from any "
                          "page they control."),
            remediation=("Drop 'null' from ACAO. Echo only origins that match "
                          "a server-side allowlist."),
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=f"ACAO: {acao}",
        )


@rule_meta(RuleMeta(
    id="passive:cors-reflected-origin",
    title="CORS reflects request Origin with credentials",
    default_severity="high",
    cwe="CWE-942",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "The response echoes the request's Origin header verbatim into "
        "Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: "
        "true. Any attacker-controlled origin can read the response with the "
        "victim's cookies."
    ),
    remediation=(
        "Validate Origin against a server-side allowlist; never echo it "
        "unconditionally when credentials are allowed."
    ),
    tags=("cors",),
))
def rule_cors_reflected_origin(ctx: RuleContext) -> Iterable[Finding]:
    acao = _header(ctx.resp_headers, "access-control-allow-origin")
    acac = _header(ctx.resp_headers, "access-control-allow-credentials")
    req_origin = _header(ctx.req_headers, "origin")
    if not (acao and req_origin):
        return
    if acao.strip() != req_origin.strip():
        return
    if acac and acac.strip().lower() == "true":
        # `rule_cors` already fires for this exact case; keep this rule's
        # finding consistent so the new rule_id is recorded against the row.
        yield Finding(
            severity="high",
            title="CORS reflects request Origin with credentials",
            description=("The response copied the request Origin into ACAO and "
                          "allows credentials. Any attacker origin can mount a "
                          "cross-site read of the authenticated response."),
            remediation=("Validate Origin against a server-side allowlist "
                          "before echoing it. Drop credentials if you cannot."),
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=f"Origin: {req_origin} -> ACAO: {acao}; ACAC: {acac}",
        )


_AUTHISH_PATH = re.compile(r"/(login|signin|sign-in|auth|oauth|sso|account)/?",
                            re.IGNORECASE)


@rule_meta(RuleMeta(
    id="passive:weak-tls-hint",
    title="Authentication endpoint reached over plain HTTP",
    default_severity="medium",
    cwe="CWE-319",
    owasp="A02:2021-Cryptographic Failures",
    description=(
        "Detects authentication-shaped URLs (login/signin/auth/sso/oauth/account) "
        "served over http:// rather than https://. Credentials sent to these "
        "endpoints will travel in cleartext."
    ),
    remediation=(
        "Serve every authentication endpoint behind HTTPS and 301-redirect "
        "the http:// variant. Add HSTS so the browser never tries http:// again."
    ),
    tags=("tls", "auth"),
))
def rule_weak_tls_hint(ctx: RuleContext) -> Iterable[Finding]:
    if not ctx.url.lower().startswith("http://"):
        return
    # Strip the query before matching so /auth?foo=bar still matches.
    path = ctx.url.split("?", 1)[0]
    if not _AUTHISH_PATH.search(path):
        return
    yield Finding(
        severity="medium", title="Authentication endpoint reached over plain HTTP",
        description=("This URL looks like an authentication endpoint but is "
                      "served over plain HTTP. Credentials and session cookies "
                      "sent here travel in cleartext and can be intercepted on "
                      "any shared network."),
        remediation=("Move the endpoint behind HTTPS and force redirects from "
                      "http:// to https://. Add a strong HSTS policy so the "
                      "browser refuses future http:// attempts."),
        cwe="CWE-319", owasp="A02:2021-Cryptographic Failures",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=f"plain-http auth path: {path}",
    )


@rule_meta(RuleMeta(
    id="passive:graphql-batching-hint",
    title="GraphQL endpoint accepts batched queries",
    default_severity="low",
    cwe="CWE-770",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "GraphQL-shaped endpoints that accept a top-level JSON array can be "
        "abused for query amplification: a single HTTP request can run "
        "thousands of queries, bypassing per-request rate limits."
    ),
    remediation=(
        "Disable query batching, or cap the batch size and apply per-query "
        "complexity / depth limits."
    ),
    tags=("graphql", "dos"),
))
def rule_graphql_batching_hint(ctx: RuleContext) -> Iterable[Finding]:
    url_l = ctx.url.lower()
    if "graphql" not in url_l and "/gql" not in url_l:
        return
    if ctx.method.upper() != "POST" or not ctx.req_body:
        return
    body = ctx.req_body.lstrip()
    if not body.startswith(b"["):
        return
    try:
        obj = json.loads(ctx.req_body)
    except (ValueError, json.JSONDecodeError):
        return
    if not isinstance(obj, list) or len(obj) < 2:
        return
    # Only flag if the response was 2xx (server accepted the batch).
    if not (200 <= ctx.status < 300):
        return
    yield Finding(
        severity="low", title="GraphQL endpoint accepts batched queries",
        description=("The endpoint accepted a JSON-array body containing "
                      f"{len(obj)} queries in a single request. Batching is "
                      "commonly abused for query amplification and to bypass "
                      "rate limits."),
        remediation=("Disable GraphQL query batching, or cap the batch size "
                      "and apply per-query complexity / depth limits."),
        cwe="CWE-770", owasp="A05:2021-Security Misconfiguration",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=f"batched POST with {len(obj)} queries",
    )


_SESSION_COOKIE_NAMES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid",
    "session", "sessionid", "sid", "connect.sid", "laravel_session",
    "django_session", "_session", "session_id",
}
_AUTH_PATH_RE = re.compile(r"/(login|signin|sign-in|auth)/?", re.IGNORECASE)
_SET_COOKIE_NAME_RE = re.compile(r"^\s*([^=]+)=", re.IGNORECASE)


def _cookie_names(cookie_header: str) -> set[str]:
    out: set[str] = set()
    for chunk in cookie_header.split(";"):
        if "=" in chunk:
            k = chunk.split("=", 1)[0].strip().lower()
            if k:
                out.add(k)
    return out


@rule_meta(RuleMeta(
    id="passive:session-fixation",
    title="Possible session fixation on login",
    default_severity="medium",
    cwe="CWE-384",
    owasp="A07:2021-Identification and Authentication Failures",
    description=(
        "A successful login response sets a session cookie whose name matches "
        "a session cookie already presented in the request. If the server "
        "re-used the same identifier, an attacker who set the victim's "
        "pre-auth cookie can keep using it after login."
    ),
    remediation=(
        "Issue a brand-new session identifier on every successful "
        "authentication; invalidate the pre-auth one."
    ),
    tags=("auth", "session"),
))
def rule_session_fixation(ctx: RuleContext) -> Iterable[Finding]:
    if not (200 <= ctx.status < 300):
        return
    path = ctx.url.split("?", 1)[0]
    if not _AUTH_PATH_RE.search(path):
        return
    req_cookie = _header(ctx.req_headers, "cookie") or ""
    if not req_cookie:
        return
    req_names = _cookie_names(req_cookie)
    if not req_names & _SESSION_COOKIE_NAMES:
        # Request did not present a session cookie \u2014 nothing to fixate.
        return
    set_cookies = _all_headers(ctx.resp_headers, "set-cookie")
    for raw in set_cookies:
        m = _SET_COOKIE_NAME_RE.match(raw)
        if not m:
            continue
        name = m.group(1).strip().lower()
        if name in _SESSION_COOKIE_NAMES and name in req_names:
            yield Finding(
                severity="medium",
                title="Possible session fixation on login",
                description=("The login response re-issued a Set-Cookie for "
                              f"'{name}', which was already present in the "
                              "request. Servers should rotate session IDs on "
                              "successful authentication to defeat fixation."),
                remediation=("Generate a new session identifier on every "
                              "successful login and invalidate the pre-auth "
                              "one."),
                cwe="CWE-384",
                owasp="A07:2021-Identification and Authentication Failures",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"Set-Cookie: {raw[:80]}",
            )
            return


_PASSWORD_INPUT_RE = re.compile(
    rb"<input\b[^>]*type\s*=\s*['\"]?password['\"]?[^>]*>",
    re.IGNORECASE,
)
_AUTOCOMPLETE_OK_VALUES = (b"new-password", b"current-password")


@rule_meta(RuleMeta(
    id="passive:autocomplete-on-password",
    title="Password field lacks autocomplete hint",
    default_severity="low",
    cwe="CWE-549",
    owasp="A04:2021-Insecure Design",
    description=(
        "Found an <input type=\"password\"> element without an "
        "autocomplete=\"new-password\" or autocomplete=\"current-password\" "
        "attribute. Modern password managers may save the wrong value, and "
        "the field may be stored in browser autofill caches."
    ),
    remediation=(
        "Set autocomplete=\"new-password\" on signup / password-change forms "
        "and autocomplete=\"current-password\" on login forms."
    ),
    tags=("html", "forms"),
))
def rule_autocomplete_on_password(ctx: RuleContext) -> Iterable[Finding]:
    ct = (_header(ctx.resp_headers, "content-type") or "").lower()
    if "html" not in ct:
        return
    body = ctx.resp_body[:200_000]
    if not body:
        return
    for m in _PASSWORD_INPUT_RE.finditer(body):
        tag = m.group(0)
        low = tag.lower()
        if b"autocomplete" in low:
            # Pull the value out of the attribute, ignore case.
            val_m = re.search(rb"autocomplete\s*=\s*['\"]?([a-z\-]+)", low)
            val = val_m.group(1) if val_m else b""
            if val in _AUTOCOMPLETE_OK_VALUES:
                continue
        snippet = tag.decode("latin-1", errors="replace")[:120]
        yield Finding(
            severity="low", title="Password field lacks autocomplete hint",
            description=("A password input was rendered without an "
                          "autocomplete=\"new-password\" or "
                          "autocomplete=\"current-password\" attribute. "
                          "Password managers may save the wrong value or "
                          "leak it into autofill caches."),
            remediation=("Set autocomplete=\"new-password\" on signup forms "
                          "and autocomplete=\"current-password\" on login "
                          "forms."),
            cwe="CWE-549", owasp="A04:2021-Insecure Design",
            host=ctx.host, url=ctx.url, request_id=ctx.history_id,
            evidence=snippet,
        )
        return  # one finding per page is enough


@rule_meta(RuleMeta(
    id="passive:cache-control-on-private",
    title="Response with Set-Cookie lacks Cache-Control: no-store",
    default_severity="low",
    cwe="CWE-525",
    owasp="A04:2021-Insecure Design",
    description=(
        "A response that issues a Set-Cookie does not include "
        "Cache-Control: no-store. Intermediate caches and the browser's own "
        "back/forward cache may keep the authenticated body, leaking it to a "
        "later user of the same device."
    ),
    remediation=(
        "Send Cache-Control: no-store on every response that returns user-"
        "specific or authentication-related content."
    ),
    tags=("cache", "cookies"),
))
def rule_cache_control_on_private(ctx: RuleContext) -> Iterable[Finding]:
    if not _all_headers(ctx.resp_headers, "set-cookie"):
        return
    cc = (_header(ctx.resp_headers, "cache-control") or "").lower()
    # The directive set we accept as "safe enough".
    if "no-store" in cc:
        return
    yield Finding(
        severity="low",
        title="Response with Set-Cookie lacks Cache-Control: no-store",
        description=("The server returned a Set-Cookie but did not set "
                      "'Cache-Control: no-store'. Intermediate caches and "
                      "the browser's back/forward cache may keep this "
                      "authenticated response and leak it to later users."),
        remediation=("Send 'Cache-Control: no-store' on every response that "
                      "returns user-specific or authentication content."),
        cwe="CWE-525", owasp="A04:2021-Insecure Design",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=f"Cache-Control: {cc or '(missing)'}",
    )


# Headers that an attacker may control on a request and that should never
# round-trip into a redirect Location.
_REQ_HEADERS_TO_WATCH = (
    "host", "x-forwarded-host", "x-host", "x-original-host",
    "x-forwarded-server", "referer", "x-forwarded-for",
    "x-original-url", "x-rewrite-url",
)


@rule_meta(RuleMeta(
    id="passive:open-redirect-hint-headers",
    title="Redirect Location echoes a request header",
    default_severity="medium",
    cwe="CWE-601",
    owasp="A01:2021-Broken Access Control",
    description=(
        "A 3xx response's Location header contains a value taken from a "
        "request header an attacker can control (Host / X-Forwarded-Host / "
        "Referer / etc.). This pattern is the seed of host-header-injection "
        "and open-redirect chains."
    ),
    remediation=(
        "Build redirect targets from server-side allowlists, not from request "
        "headers. Validate Host / X-Forwarded-Host against the configured "
        "site list before using them."
    ),
    tags=("redirect", "host-header"),
))
def rule_open_redirect_hint_headers(ctx: RuleContext) -> Iterable[Finding]:
    if not (300 <= ctx.status < 400):
        return
    loc = _header(ctx.resp_headers, "location") or ""
    if not loc:
        return
    loc_l = loc.lower()
    for hname in _REQ_HEADERS_TO_WATCH:
        v = _header(ctx.req_headers, hname)
        if not v:
            continue
        token = v.strip().lower()
        # Reject too-short or obviously generic values that would false-match.
        if len(token) < 4 or token in ("http", "https", "/"):
            continue
        if token in loc_l:
            yield Finding(
                severity="medium",
                title="Redirect Location echoes a request header",
                description=("The Location of this 3xx response contains a "
                              f"value taken from the request header "
                              f"'{hname}'. Attackers who control that header "
                              "(via proxies, ALBs, or just direct requests) "
                              "can steer the redirect."),
                remediation=("Build redirect targets server-side from a "
                              "fixed allowlist; never trust Host or "
                              "X-Forwarded-* headers without validation."),
                cwe="CWE-601",
                owasp="A01:2021-Broken Access Control",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"{hname}: {v[:60]} -> Location: {loc[:80]}",
            )
            return


# ---- Phase 20 — PII / secrets passive scan ----

def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum on a digit-only string."""
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    parity = (len(digits) - 2) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character; 0.0 for empty input."""
    if not s:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _redact(s: str, *, head: int = 4, tail: int = 4) -> str:
    """First ``head`` + last ``tail`` chars; middle replaced by bullets.

    Strings shorter than ``head + tail`` are returned fully bulleted so
    the caller never accidentally exposes a short secret in evidence.
    """
    if not s:
        return ""
    if len(s) <= head + tail:
        return "\u2022" * len(s)
    return s[:head] + "\u2022" * (len(s) - head - tail) + s[-tail:]


def _is_text_response(headers: list[tuple[str, str]]) -> bool:
    """True for response types where a body scan is meaningful.

    Covers `text/*`, JSON, XML (including `+json` / `+xml` suffixes), and
    JavaScript / ECMAScript bundles. The JS family matters because modern
    SPAs ship webpack bundles served as `application/javascript` — that is
    the single richest place to find leaked Firebase / Stripe / Mapbox /
    SendGrid tokens in a real engagement, and skipping it cripples the
    secret-scanning rule.
    """
    ct = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ct = (v or "").lower()
            break
    if not ct:
        return False
    if ct.startswith("text/"):
        return True
    if "application/json" in ct or "application/xml" in ct:
        return True
    if "+json" in ct or "+xml" in ct:
        return True
    return bool(
        "application/javascript" in ct
        or "application/x-javascript" in ct
        or "application/ecmascript" in ct
    )


# Each entry: (slug, compiled regex, severity, cwe, owasp, label,
#              min_entropy_or_None, luhn_required)
# Patterns are bytes-mode so they run directly on the raw body.
_SECRET_PATTERNS: tuple[tuple, ...] = (
    # AWS access key id — fixed prefix AKIA/ASIA/AGPA/AROA + 16 base32-ish chars.
    ("aws-access-key", re.compile(rb"\b((?:AKIA|ASIA|AGPA|AROA)[A-Z0-9]{16})\b"),
     "critical", "CWE-798",
     "A07:2021-Identification and Authentication Failures",
     "AWS access key id", None, False),
    # GitHub personal-access tokens (classic + fine-grained + OAuth + app + refresh).
    ("github-token", re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "GitHub token", None, False),
    # Slack bot / user / workspace tokens.
    ("slack-token", re.compile(rb"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Slack token", None, False),
    # Google API key — fixed prefix AIza + 35 url-safe chars.
    ("google-api-key", re.compile(rb"\b(AIza[0-9A-Za-z_-]{35})\b"),
     "high", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Google API key", None, False),
    # OpenAI API key.
    ("openai-api-key", re.compile(rb"\b(sk-[A-Za-z0-9]{32,})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "OpenAI API key", 3.5, False),
    # PEM private-key headers (any kind).
    ("private-key", re.compile(
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "critical", "CWE-798", "A02:2021-Cryptographic Failures",
     "Private key block", None, False),
    # Credit-card-shaped digit runs (13-19 digits, optional space/dash separators).
    # Luhn-gated below to drop the obvious false positives.
    ("credit-card", re.compile(rb"\b((?:\d[ -]?){12,18}\d)\b"),
     "medium", "CWE-200", "A04:2021-Insecure Design",
     "Credit-card number", None, True),
    # US SSN — conservative: 3-2-4 with hyphens or spaces, not all zeros in a group.
    ("ssn-us", re.compile(
        rb"\b((?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4})\b"),
     "high", "CWE-200", "A04:2021-Insecure Design",
     "US Social-Security number", None, False),
    # ---- Phase 22 additions (bundle-friendly) ----
    # Stripe live secret key — fixed prefix, server-only secret.
    ("stripe-live-secret", re.compile(rb"\b(sk_live_[0-9a-zA-Z]{24,99})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Stripe live secret key", None, False),
    # Stripe restricted live key — narrower scope but still a server credential.
    ("stripe-restricted-key", re.compile(rb"\b(rk_live_[0-9a-zA-Z]{24,99})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Stripe restricted live key", None, False),
    # Stripe test secret key — non-production but still leaks the integration.
    ("stripe-test-secret", re.compile(rb"\b(sk_test_[0-9a-zA-Z]{24,99})\b"),
     "medium", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Stripe test secret key", None, False),
    # Mapbox SECRET token (sk.…). The pk.… public token is intentionally
    # excluded — it is meant to ship in client bundles by design.
    ("mapbox-secret-token", re.compile(rb"\b(sk\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Mapbox secret access token", None, False),
    # SendGrid API key — fixed `SG.` prefix + dotted segments.
    ("sendgrid-api-key", re.compile(rb"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
     "critical", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "SendGrid API key", None, False),
    # Twilio auth token / API SID (32-hex with TWILIO-specific SK or AC
    # prefix). AC prefixes the Account SID which Twilio docs label as
    # ‘not a secret’, so we restrict to SK (API key SID) only.
    ("twilio-api-key", re.compile(rb"\b(SK[0-9a-fA-F]{32})\b"),
     "high", "CWE-798", "A07:2021-Identification and Authentication Failures",
     "Twilio API key SID", None, False),
    # Bare JWT-shaped tokens — three base64url segments. Distinct from
    # `passive:jwt-none-alg` which inspects alg headers; this rule simply
    # flags the leak. Entropy floor 3.5 to skip placeholder samples.
    ("jwt-token", re.compile(
        rb"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
     "medium", "CWE-200", "A02:2021-Cryptographic Failures",
     "JWT in response body", 3.5, False),
)


@rule_meta(RuleMeta(
    id="passive:pii-secrets",
    title="PII or secret material in response body",
    default_severity="high",
    cwe="CWE-200",
    owasp="A04:2021-Insecure Design",
    description=(
        "Scan response bodies for high-confidence PII and credential "
        "patterns: AWS / GitHub / Slack / Google / OpenAI tokens, PEM "
        "private-key blocks, Luhn-valid credit-card numbers, and US "
        "SSN-shaped strings. Matches are redacted (first 4 + last 4 "
        "characters) before being recorded in the finding evidence."
    ),
    remediation=(
        "Never return secrets, API keys, or personally identifiable "
        "information in HTTP response bodies. Move credentials to "
        "server-side configuration, redact PII, and rotate any token "
        "that this rule surfaces."
    ),
    tags=("pii", "secrets", "leak"),
))
def rule_pii_secrets(ctx: RuleContext) -> Iterable[Finding]:
    if not _is_text_response(ctx.resp_headers):
        return
    body = ctx.resp_body[:200_000]
    if not body:
        return
    seen: set[tuple[str, str]] = set()
    for (slug, pattern, severity, cwe, owasp, label,
         min_entropy, luhn_required) in _SECRET_PATTERNS:
        for m in pattern.finditer(body):
            raw = m.group(1) if m.groups() else m.group(0)
            try:
                text = raw.decode("latin-1", errors="replace")
            except (UnicodeDecodeError, AttributeError):  # noqa: BLE001,S112  # skip regex match whose bytes aren't decodable, continue with remaining matches
                continue
            if luhn_required:
                digits = re.sub(r"[ -]", "", text)
                if not _luhn_ok(digits):
                    continue
                # Drop obvious noise: all-same-digit runs (`0000…`,
                # `7777…`). A real PAN always has at least two distinct
                # digits, but so does e.g. `4111111111111111` — keep
                # this guard minimal so we don't reject test cards.
                if len(set(digits)) < 2:
                    continue
                redacted = _redact(digits)
            else:
                if min_entropy is not None and _shannon_entropy(text) < min_entropy:
                    continue
                redacted = _redact(text)
            key = (slug, redacted)
            if key in seen:
                continue
            seen.add(key)
            yield Finding(
                severity=severity,
                title=f"{label} exposed in response body",
                description=(
                    f"The response body at {ctx.url} contains what looks "
                    f"like a {label.lower()} ({redacted}). Returning this "
                    "kind of data in an HTTP response exposes it to anyone "
                    "with access to the network path, browser cache, "
                    "proxy logs, or analytics pipeline."
                ),
                remediation=(
                    "Strip the value from the response. If it is a "
                    "credential, rotate it; if it is PII, mask or remove "
                    "it before serialisation."
                ),
                cwe=cwe, owasp=owasp,
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"{slug}={redacted}",
                confidence="firm",
            )


# ---- Phase 21 — Known-CVE fingerprint on response headers ----
#
# Curated bundled table — precision over coverage. Each entry pins a CVE (or
# end-of-life advisory) to a product + version predicate. The rule extracts
# product/version tokens from Server / X-Powered-By / X-AspNet-Version /
# X-AspNetMvc-Version headers and fires one finding per matching CVE per
# host. No network calls; the list is intentionally small. Extend via PR
# with verified, high-confidence entries only — false positives here cost
# operator trust on every scan.

def _ver_lt(target: tuple[int, ...]):
    """Predicate: matched version is strictly less than target."""
    t = tuple(target)
    return lambda v: v < t


def _ver_between(lo: tuple[int, ...], hi: tuple[int, ...]):
    """Predicate: matched version is in [lo, hi). hi is exclusive."""
    lo_t = tuple(lo)
    hi_t = tuple(hi)
    return lambda v: lo_t <= v < hi_t


# (product_lc, predicate, advisory_id, severity, cvss, summary, cwe)
_KNOWN_CVES: tuple[tuple, ...] = (
    # ---- Apache httpd ----
    ("apache", _ver_between((2, 4, 0), (2, 4, 49)),
     "CVE-2021-41773", "high", 7.5,
     "Path traversal in mod_alias; aliased directories allow '..' "
     "escapes. Often leads to RCE when mod_cgi is enabled.",
     "CWE-22"),
    ("apache", _ver_between((2, 4, 49), (2, 4, 51)),
     "CVE-2021-42013", "critical", 9.8,
     "Incomplete fix for CVE-2021-41773; path traversal + RCE.",
     "CWE-22"),
    ("apache", _ver_between((2, 4, 0), (2, 4, 52)),
     "CVE-2021-44790", "critical", 9.8,
     "mod_lua buffer overflow on multipart parsing.",
     "CWE-787"),
    ("apache", _ver_between((2, 4, 0), (2, 4, 55)),
     "CVE-2023-25690", "critical", 9.8,
     "mod_proxy HTTP request smuggling via crafted rewrite rules.",
     "CWE-444"),
    ("apache", _ver_between((2, 4, 0), (2, 4, 58)),
     "CVE-2023-45802", "high", 7.5,
     "HTTP/2 stream memory not reclaimed on RST; denial of service.",
     "CWE-400"),

    # ---- nginx ----
    ("nginx", _ver_between((0, 6, 18), (1, 20, 1)),
     "CVE-2021-23017", "critical", 9.4,
     "DNS resolver off-by-one; crafted UDP response triggers overflow "
     "in ngx_resolver.",
     "CWE-193"),
    ("nginx", _ver_between((1, 1, 4), (1, 23, 2)),
     "CVE-2022-41741", "high", 7.8,
     "ngx_http_mp4_module memory corruption (only relevant when the "
     "mp4 module is loaded).",
     "CWE-787"),

    # ---- OpenSSL (often in Server header parentheses) ----
    ("openssl", _ver_between((1, 0, 1, 0), (1, 0, 1, 7)),
     "CVE-2014-0160", "critical", 7.5,
     "Heartbleed; TLS heartbeat extension reads adjacent process memory "
     "(can disclose private keys, session tokens).",
     "CWE-125"),

    # ---- PHP ----
    ("php", _ver_lt((7, 4, 0)),
     "EOL-PHP-7.3", "high", 7.5,
     "PHP 7.3 and earlier are end-of-life; no upstream security patches "
     "since 2021-12-06. Many known unpatched issues.",
     "CWE-1104"),
    ("php", _ver_between((8, 0, 0), (8, 1, 0)),
     "EOL-PHP-8.0", "medium", 5.3,
     "PHP 8.0 is end-of-life (EOL 2023-11-26); no upstream patches.",
     "CWE-1104"),

    # ---- IIS ----
    ("microsoft-iis", _ver_lt((8, 0)),
     "EOL-IIS-7", "high", 7.5,
     "IIS 7.x ships on Windows Server 2008/2008R2 (end of extended "
     "support 2020-01-14); host OS is missing patches.",
     "CWE-1104"),

    # ---- ASP.NET ----
    ("asp.net", _ver_lt((4, 0)),
     "EOL-ASPNET-3.5", "high", 7.5,
     "ASP.NET 3.5 and earlier no longer receive security patches "
     "outside of Windows Server lifecycles.",
     "CWE-1104"),

    # ---- Tomcat ----
    ("apache-coyote", _ver_between((0, 0), (1, 1)),
     "EOL-TOMCAT-COYOTE-1.0", "medium", 5.3,
     "Apache Tomcat Coyote 1.0 ships with Tomcat 5.x / 6.x — both "
     "end-of-life since 2012 / 2016 respectively.",
     "CWE-1104"),
)


# Match strings like "Apache/2.4.59" or "nginx/1.18.0" or "PHP/8.0.30".
# Captures the product token (letters / digits / dot / dash / underscore)
# and a dotted numeric version. Bytes-mode for direct header scanning.
_VERSION_TOKEN_RE = re.compile(rb"([A-Za-z][A-Za-z0-9._-]*)/(\d+(?:\.\d+)+)")


def _parse_version_tokens(header_value: str) -> list[tuple[str, tuple[int, ...]]]:
    """Pull every `product/version` token out of a header value.

    Server headers commonly chain multiple components:
    ``Apache/2.4.59 (Ubuntu) OpenSSL/1.1.1f PHP/8.0.30`` — yield one
    `(product_lc, version_tuple)` per component.
    """
    if not header_value:
        return []
    out: list[tuple[str, tuple[int, ...]]] = []
    encoded = header_value.encode("latin-1", errors="replace")
    for m in _VERSION_TOKEN_RE.finditer(encoded):
        product = m.group(1).decode("latin-1").lower()
        raw = m.group(2).decode("latin-1")
        try:
            version = tuple(int(p) for p in raw.split("."))
        except ValueError:
            continue
        out.append((product, version))
    return out


@rule_meta(RuleMeta(
    id="passive:cve-fingerprint",
    title="Known CVE / EOL component in response header",
    default_severity="high",
    cwe="CWE-1104",
    owasp="A06:2021-Vulnerable and Outdated Components",
    description=(
        "Match product / version tokens disclosed in response headers "
        "(Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version) "
        "against a bundled, curated list of high-confidence CVEs and "
        "end-of-life advisories. The list is deliberately small and "
        "favours precision over coverage; extend by submitting a PR."
    ),
    remediation=(
        "Upgrade the disclosed component to a patched release. "
        "Independently suppress version disclosure in the response "
        "header (Apache: 'ServerTokens Prod'; nginx: "
        "'server_tokens off'; equivalent for other stacks)."
    ),
    tags=("cve", "outdated", "fingerprint"),
))
def rule_cve_server_fingerprint(ctx: RuleContext) -> Iterable[Finding]:
    seen: set[tuple[str, str]] = set()
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        v = _header(ctx.resp_headers, name)
        if not v:
            continue
        for product, version in _parse_version_tokens(v):
            for (p_lc, predicate, advisory_id, severity, cvss,
                 summary, cwe) in _KNOWN_CVES:
                if p_lc != product:
                    continue
                if not predicate(version):
                    continue
                key = (advisory_id, ctx.host)
                if key in seen:
                    continue
                seen.add(key)
                version_str = ".".join(str(x) for x in version)
                yield Finding(
                    severity=severity,
                    title=f"{advisory_id} affects {product} {version_str}",
                    description=(
                        f"The {name} header advertises {product} "
                        f"{version_str}, which is affected by "
                        f"{advisory_id} (CVSS {cvss}). {summary}"
                    ),
                    remediation=(
                        f"Upgrade {product} past the affected range, then "
                        "remove the version banner from the response "
                        "header so future scanners cannot fingerprint it."
                    ),
                    cwe=cwe,
                    owasp="A06:2021-Vulnerable and Outdated Components",
                    host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                    evidence=f"{name}: {v} -> {advisory_id}",
                    confidence="firm",
                )


# ---- Phase 23 — Framework debug pages (body-marker passive) ----
#
# Each marker is deliberately specific enough that body-only matching is
# safe — short, generic strings ("Django", "Rails") would false-positive
# on blog posts and tutorials. The markers below are signature lines
# that only appear when the framework is actively serving a debug or
# admin page in production.
#
# Layout: (slug, marker_regex, framework, severity, summary)

_DEBUG_PAGE_MARKERS: tuple[tuple, ...] = (
    # Spring Boot Actuator — /env, /configprops, /heapdump, /beans
    ("spring-actuator-env",
     re.compile(rb'"propertySources"\s*:\s*\['),
     "Spring Boot Actuator (/env)", "critical",
     "Spring Boot Actuator /env endpoint is exposed. Lists every "
     "environment variable, system property, and configuration value "
     "in the JVM — typically including database credentials, JWT "
     "signing keys, OAuth secrets, and cloud credentials."),
    ("spring-actuator-heapdump",
     re.compile(rb"^\x1f\x8b\x08|JAVA PROFILE 1\.0\.[12]"),
     "Spring Boot Actuator (/heapdump)", "critical",
     "Spring Boot Actuator /heapdump returns a full JVM heap dump. "
     "Anyone who downloads it can extract every in-memory secret: "
     "passwords, tokens, session cookies, encryption keys."),
    ("spring-actuator-configprops",
     re.compile(rb'"@ConfigurationProperties"|"contexts"\s*:\s*\{.*"beans"', re.S),
     "Spring Boot Actuator (/configprops)", "high",
     "Spring Boot Actuator /configprops lists every @ConfigurationProperties "
     "bean and its current values — often includes credentials and "
     "internal URLs."),

    # Werkzeug / Flask debug
    ("werkzeug-debugger",
     re.compile(rb"WERKZEUG_DEBUG_PIN|"
                rb"The console requires authentication for security reasons\.|"
                rb"<title>Error // Werkzeug Debugger</title>"),
     "Werkzeug / Flask debugger", "critical",
     "Werkzeug's interactive debugger is enabled on a production-facing "
     "endpoint. Any traceback grants the debugger console, and the "
     "console grants arbitrary Python execution as the web user. "
     "Equivalent to remote code execution."),

    # Django
    ("django-debug-page",
     re.compile(rb"You're seeing this error because you have <code>DEBUG = True</code>|"
                rb"<title>.+ at /.*</title>\s*<meta name=\"robots\" content=\"NONE,NOARCHIVE\">"),
     "Django DEBUG=True error page", "high",
     "Django is running with DEBUG=True in production. Stack traces "
     "leak source paths, template values, environment variables, "
     "installed apps, and SQL queries."),

    # Rails
    ("rails-error-page",
     re.compile(rb"<h1>(?:NoMethodError|RoutingError|ActionController::|"
                rb"ActiveRecord::|ActionView::Template::Error)|"
                rb"<title>Action Controller: Exception caught</title>|"
                rb"web-console-session"),
     "Rails error / web-console page", "critical",
     "Rails is rendering a debug error page (or the web-console gem is "
     "active). web-console exposes a remote IRB session — equivalent "
     "to remote code execution. The error template alone leaks routes, "
     "request env, session data, and source paths."),

    # PHP / Laravel
    ("laravel-ignition",
     re.compile(rb"laravel_ignition|Ignition\\\\Solutions|"
                rb"<title>Whoops! There was an error\.</title>"),
     "Laravel Ignition debug page", "critical",
     "Laravel Ignition (the default debug-error page) is exposed. "
     "Recent versions have shipped CVEs allowing remote code "
     "execution through the 'solution' apply endpoint. At minimum it "
     "leaks request payloads, env vars, source paths, and stack traces."),
    ("symfony-profiler",
     re.compile(rb"<title>Symfony Profiler</title>|"
                rb"sf-toolbar|<div id=\"sfwdt"),
     "Symfony profiler / web debug toolbar", "high",
     "Symfony's web-debug-toolbar / profiler is exposed. Reveals "
     "routes, controllers, services, env vars, request history, and "
     "database queries."),

    # ASP.NET / IIS
    ("aspnet-yellow-page",
     re.compile(rb"<title>(?:Server Error|Runtime Error|Compiler Error)</title>.*"
                rb"<span><H1>(?:Server|Runtime|Compiler) Error",
                re.S),
     "ASP.NET yellow-screen-of-death", "high",
     "ASP.NET is returning a full debug error page (Yellow Screen of "
     "Death). Reveals source file paths, stack traces, .NET versions, "
     "and often line-level source code."),
    ("aspnet-elmah",
     re.compile(rb"<title>(?:Error log for|Elmah Error)"
                rb"|ELMAH\.ErrorLogPage|elmah/main\.css"),
     "ELMAH error log exposed", "critical",
     "ELMAH (Error Logging Modules and Handlers) is unauthenticated. "
     "Every captured exception is browsable — leaks SQL, file paths, "
     "tokens passed in URLs, and session cookies."),

    # Express / Node
    ("express-error",
     re.compile(rb"<title>Error</title>.*<pre>(?:Error|TypeError|"
                rb"ReferenceError|SyntaxError):.+at \S+ \(/", re.S),
     "Express stack trace in production", "medium",
     "Express is returning full stack traces to the client (likely "
     "`app.set('env','development')` or missing error handler). Leaks "
     "source file paths, library versions, and internal structure."),

    # Generic phpinfo
    ("phpinfo",
     re.compile(rb"<title>phpinfo\(\)</title>|"
                rb"<h1 class=\"p\">PHP Version "),
     "phpinfo() page exposed", "high",
     "A phpinfo() page is reachable. Lists PHP version, modules, every "
     "environment variable (often with credentials), file system paths, "
     "and the full php.ini configuration. Standard recon target."),
)


@rule_meta(RuleMeta(
    id="passive:framework-debug-page",
    title="Framework debug or admin page exposed",
    default_severity="high",
    cwe="CWE-489",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Detect well-known framework debug, profiler, and "
        "administrative pages by matching signature strings in the "
        "response body. Covers Spring Boot Actuator (env, "
        "heapdump, configprops), Werkzeug / Flask debugger, Django "
        "DEBUG=True, Rails error / web-console, Laravel Ignition, "
        "Symfony profiler, ASP.NET yellow-screen / ELMAH, Express "
        "tracebacks, and phpinfo(). Each marker is a signature line "
        "(not a short generic substring) so body-only matching is "
        "safe."
    ),
    remediation=(
        "Disable debug mode in production (Spring: management "
        "endpoints behind auth and a separate management port; "
        "Django / Flask: DEBUG=False; Rails: production env; "
        "ASP.NET: customErrors mode=On). Where the endpoint is "
        "useful for ops, gate it behind authentication and "
        "network-level access control."
    ),
    tags=("debug", "info-leak", "framework", "misconfig"),
))
def rule_framework_debug_pages(ctx: RuleContext) -> Iterable[Finding]:
    if ctx.status >= 400:
        return
    if not _is_text_response(ctx.resp_headers):
        # Heapdump downloads as octet-stream / gzip; allow that one
        # marker to run even when the body is binary.
        binary_marker = next(
            (m for m in _DEBUG_PAGE_MARKERS if m[0] == "spring-actuator-heapdump"),
            None,
        )
        if binary_marker is None:
            return
        body = ctx.resp_body[:8_192]
        if binary_marker[1].search(body):
            yield from _yield_debug_finding(ctx, binary_marker)
        return
    body = ctx.resp_body[:200_000]
    if not body:
        return
    seen: set[str] = set()
    for entry in _DEBUG_PAGE_MARKERS:
        slug = entry[0]
        if slug in seen:
            continue
        if entry[1].search(body):
            seen.add(slug)
            yield from _yield_debug_finding(ctx, entry)


def _yield_debug_finding(ctx: RuleContext, entry: tuple) -> Iterable[Finding]:
    slug, _regex, framework, severity, summary = entry
    yield Finding(
        severity=severity,
        title=f"{framework} exposed",
        description=(
            f"The response at {ctx.url} matches the signature of "
            f"{framework}. {summary}"
        ),
        remediation=(
            "Disable the debug / admin endpoint in production, or "
            "gate it behind authentication and a private network "
            "segment."
        ),
        cwe="CWE-489",
        owasp="A05:2021-Security Misconfiguration",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=f"{slug} @ {ctx.url}",
        confidence="firm",
    )


# ---- Phase 24 — Subdomain-takeover hints (body-marker passive) ----
#
# When a DNS record points at a third-party platform (S3, GitHub Pages,
# Heroku, …) and the asset on that platform is not claimed, the platform
# returns a service-specific error page. An attacker who can register
# the unclaimed asset effectively hijacks the subdomain: phishing,
# cookie theft, OAuth-callback redirect, all become trivial.
#
# Markers are deliberately platform-specific strings, not generic 404
# vocabulary. Each marker is chosen to be precise enough that body-only
# matching cannot false-positive on a normal page that just mentions
# the provider name. The remediation text encodes the operator's next
# step (claim the asset before disclosing).
#
# Layout: (slug, compiled_regex_bytes, provider, remediation_hint)

_TAKEOVER_FINGERPRINTS: tuple[tuple, ...] = (
    ("aws-s3-bucket-xml",
     re.compile(rb"<Code>NoSuchBucket</Code>"),
     "AWS S3 (XML error)",
     "Register the bucket name in the same region in the target AWS "
     "account; if the bucket cannot be claimed safely, request that "
     "the DNS CNAME be removed."),
    ("aws-s3-bucket-text",
     re.compile(rb"The specified bucket does not exist"),
     "AWS S3 (text marker)",
     "Register the bucket name in the same region; otherwise remove "
     "the DNS CNAME pointing at the non-existent bucket."),
    ("github-pages",
     re.compile(rb"There isn't a GitHub Pages site here\."),
     "GitHub Pages",
     "Create a repo named for the unclaimed page and enable GitHub "
     "Pages; otherwise remove the CNAME."),
    ("heroku-no-such-app",
     re.compile(rb"<title>No such app</title>|"
                rb"herokucdn\.com/error-pages/no-such-app\.html"),
     "Heroku",
     "Register the Heroku app name and deploy any placeholder; "
     "otherwise remove the DNS CNAME."),
    ("azure-web-app",
     re.compile(rb"404 Web Site not found"),
     "Azure App Service",
     "Claim the App Service name in the Azure subscription that owns "
     "the DNS zone; otherwise remove the CNAME."),
    ("azure-traffic-manager",
     re.compile(rb"<title>azure traffic manager</title>", re.IGNORECASE),
     "Azure Traffic Manager",
     "Claim the Traffic Manager profile name; otherwise remove the "
     "DNS CNAME pointing at *.trafficmanager.net."),
    ("fastly-unknown-domain",
     re.compile(rb"Fastly error: unknown domain"),
     "Fastly",
     "Add the customer-owned domain to the Fastly service "
     "configuration; otherwise remove the DNS CNAME."),
    ("bitbucket-repo",
     re.compile(rb"Repository not found"),
     "Bitbucket Pages",
     "Register the Bitbucket repository under the same workspace as "
     "the DNS owner; otherwise remove the CNAME."),
    ("surge-sh",
     re.compile(rb"project not found"),
     "Surge.sh",
     "Publish a Surge.sh project under the unclaimed subdomain; "
     "otherwise remove the CNAME pointing at na-west1.surge.sh."),
    ("tilda-subscription",
     re.compile(rb"Please renew your subscription"),
     "Tilda",
     "Renew or re-claim the Tilda site; otherwise remove the CNAME."),
    ("wpengine-site",
     re.compile(rb"The site you were looking for couldn't be found"),
     "WP Engine",
     "Claim the WP Engine install name; otherwise remove the CNAME."),
    ("ghost-pro",
     re.compile(rb"The thing you were looking for is no longer here, "
                rb"or never was"),
     "Ghost (Ghost Pro)",
     "Claim the Ghost Pro subdomain; otherwise remove the CNAME."),
    ("pantheon",
     re.compile(rb"The gods are wise, but do not know of the site "
                rb"which you seek"),
     "Pantheon",
     "Claim the Pantheon site name; otherwise remove the CNAME."),
    ("shopify-shop-unavailable",
     re.compile(rb"Sorry, this shop is currently unavailable"),
     "Shopify",
     "Claim the *.myshopify.com store name with matching domain "
     "alias; otherwise remove the DNS record."),
    ("readme-io",
     re.compile(rb"Project doesnt exist\.\.\. yet!"),
     "Readme.io",
     "Claim the Readme.io project name; otherwise remove the CNAME."),
    ("teamwork",
     re.compile(rb"Oops - We didn't find your site"),
     "Teamwork",
     "Claim the Teamwork site name; otherwise remove the CNAME."),
)


@rule_meta(RuleMeta(
    id="passive:subdomain-takeover-hint",
    title="Subdomain-takeover fingerprint in response",
    default_severity="high",
    cwe="CWE-1395",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Detect responses that match the service-specific error page "
        "of an unclaimed third-party asset (S3 bucket, GitHub Pages "
        "site, Heroku app, Azure App Service, Fastly service, "
        "Bitbucket repo, Surge / Tilda / WP Engine / Ghost / "
        "Pantheon / Shopify / Readme.io / Teamwork). A dangling DNS "
        "record pointing at one of these is takeover-capable: "
        "register the unclaimed asset and the attacker controls the "
        "subdomain (phishing, cookie theft, OAuth-callback redirect)."
    ),
    remediation=(
        "Either claim the third-party asset (preferred — defangs the "
        "attack permanently) or remove the dangling DNS record. "
        "Audit every CNAME / ALIAS record in the DNS zone for "
        "providers that allow user-chosen asset names."
    ),
    tags=("subdomain-takeover", "dns", "misconfig"),
))
def rule_subdomain_takeover_hint(ctx: RuleContext) -> Iterable[Finding]:
    if not _is_text_response(ctx.resp_headers):
        return
    body = ctx.resp_body[:100_000]
    if not body:
        return
    seen: set[str] = set()
    for entry in _TAKEOVER_FINGERPRINTS:
        slug = entry[0]
        if slug in seen:
            continue
        if entry[1].search(body):
            seen.add(slug)
            yield from _yield_takeover_finding(ctx, entry)


def _yield_takeover_finding(ctx: RuleContext, entry: tuple) -> Iterable[Finding]:
    slug, _regex, provider, remediation_hint = entry
    yield Finding(
        severity="high",
        title=f"Subdomain takeover hint: unclaimed {provider}",
        description=(
            f"The response at {ctx.url} matches the error template "
            f"served by {provider} when the requested asset does not "
            "exist. If a DNS record (CNAME / ALIAS) points the "
            f"hostname {ctx.host} at this provider and the asset is "
            "unclaimed, an attacker can register the asset and take "
            "over the subdomain."
        ),
        remediation=remediation_hint,
        cwe="CWE-1395",
        owasp="A05:2021-Security Misconfiguration",
        host=ctx.host, url=ctx.url, request_id=ctx.history_id,
        evidence=f"{slug} @ {ctx.url}",
        confidence="tentative",
    )


# ---- Phase 25: infrastructure leaks in error responses ---------------------
#
# When a 4xx/5xx error page is verbose enough to embed internal
# infrastructure detail, that detail is gold to a pentester:
#   - DB connection strings (often with embedded creds) -> immediate
#     credential capture or pivot to the DB host
#   - RFC1918 IPs -> internal network topology, SSRF target list
#   - Internal hostnames (.local, .internal, .corp, ...) -> AD / DNS
#     reconnaissance, SSRF target list
#   - Absolute filesystem paths -> webroot, OS, app install layout
#     (feeds LFI / RCE later)
#
# The rule is status-gated on >= 400 so legitimate APIs that return
# hostnames or paths as data don't fire.  Each leak type yields a
# separate finding with the redacted match in evidence.  Per-response
# dedupe keyed on (slug, redacted_match).

# RFC1918 + loopback + link-local. Anchored with word boundaries to
# avoid catching version numbers like "10.0.1.4" inside library tags.
_INTERNAL_IP_RE = re.compile(
    rb"\b("
    rb"10\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    rb"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}"
    rb"|172\.(?:1[6-9]|2\d|3[01])"
    rb"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}"
    rb"|192\.168(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}"
    rb"|127\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    rb"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}"
    rb"|169\.254(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}"
    rb")\b"
)

# Internal-only TLD suffixes commonly seen in AD / corporate networks.
# Anchored to a hostname-shaped label preceding the suffix.
_INTERNAL_HOST_RE = re.compile(
    rb"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    rb"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    rb"\.(?:local|internal|intranet|intra|corp|lan|home|localdomain))\b",
    re.IGNORECASE,
)

# Absolute Windows path with at least one subdirectory after the drive.
_WIN_PATH_RE = re.compile(
    rb"\b([A-Za-z]:\\(?:[A-Za-z0-9_.\- ]+\\)+[A-Za-z0-9_.\- ]+)"
)

# Absolute *nix paths under common webroot / app install prefixes.
_NIX_PATH_RE = re.compile(
    rb"(?<![A-Za-z0-9_/])(/(?:var/www|var/log|var/lib|home|opt|srv|usr/local|"
    rb"etc/(?:apache2|nginx|httpd|php|mysql|postgresql))"
    rb"(?:/[A-Za-z0-9_.\-]+)+)"
)

# JDBC / common DB connection URIs. user[:pass]@host[:port]/db is the
# typical shape; treat the entire match as the redacted token.
_DB_URI_RE = re.compile(
    rb"\b("
    rb"jdbc:[a-zA-Z0-9]+://[^\s\"'<>]+"
    rb"|mongodb(?:\+srv)?://[^\s\"'<>]+"
    rb"|postgres(?:ql)?://[^\s\"'<>]+"
    rb"|mysql://[^\s\"'<>]+"
    rb"|redis://[^\s\"'<>]+"
    rb"|amqp(?:s)?://[^\s\"'<>]+"
    rb")"
)

# .NET-style key/value connection strings. We require both a host-
# bearing key and a Password= token to keep the precision high.
_DOTNET_CONN_RE = re.compile(
    rb"((?:Server|Data Source|Host)=[^;\s\"'<>]+;[^\"'<>]{0,200}?"
    rb"Password=[^;\s\"'<>]+)",
    re.IGNORECASE,
)

# Each entry: (slug, compiled regex, severity, title, description,
# remediation). The description is generic enough that the redacted
# match in evidence carries the specifics.
_ERROR_LEAK_PATTERNS: tuple[tuple, ...] = (
    ("db-uri-with-creds", _DB_URI_RE, "critical",
     "Database connection URI leaked in error response",
     "An error page exposed a database connection URI. If the URI "
     "embeds credentials, those are now compromised and the DB host "
     "itself may be reachable from the attacker's network.",
     "Move connection strings into secret stores; never serialise them "
     "into error responses. Rotate any credential that this rule "
     "surfaces."),
    ("db-connection-string", _DOTNET_CONN_RE, "critical",
     "Database connection string leaked in error response",
     "A .NET / SQL Server-style connection string with a Password= "
     "field appeared in an error response. The credentials are now "
     "compromised.",
     "Catch exceptions before serialisation and rotate the leaked "
     "credentials. Configure ASP.NET / connection-string providers to "
     "redact the Password key in logs and error output."),
    ("internal-ip", _INTERNAL_IP_RE, "medium",
     "Internal IP address leaked in error response",
     "An error page exposed an RFC1918 / loopback / link-local IP "
     "address. This reveals internal network topology and feeds SSRF "
     "target lists.",
     "Sanitise stack traces and error templates before returning them "
     "to clients."),
    ("internal-hostname", _INTERNAL_HOST_RE, "medium",
     "Internal hostname leaked in error response",
     "An error page exposed a hostname under an internal-only TLD "
     "(.local / .internal / .corp / ...). This reveals AD or DNS "
     "naming conventions and feeds further reconnaissance.",
     "Catch and sanitise exceptions before returning them; route 4xx/"
     "5xx through a generic error template."),
    ("filesystem-path-win", _WIN_PATH_RE, "medium",
     "Absolute Windows filesystem path leaked in error response",
     "An error page exposed an absolute Windows filesystem path. "
     "This reveals webroot, OS and install-layout details that feed "
     "LFI / RCE follow-up.",
     "Disable production stack traces; route errors through a generic "
     "template."),
    ("filesystem-path-nix", _NIX_PATH_RE, "medium",
     "Absolute Unix filesystem path leaked in error response",
     "An error page exposed an absolute *nix filesystem path under a "
     "common app / webroot prefix. This reveals install layout and "
     "feeds LFI / RCE follow-up.",
     "Disable production stack traces; route errors through a generic "
     "template."),
)


def _redact_leak(raw: bytes) -> str:
    """Truncate-and-redact a leaked token for finding evidence."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = repr(raw)
    if len(text) <= 60:
        return text
    return text[:40] + "..." + text[-12:]


@rule_meta(RuleMeta(
    id="passive:error-leak",
    title="Internal infrastructure leak in error response",
    default_severity="medium",
    cwe="CWE-209",
    owasp="A05:2021-Security Misconfiguration",
    description=(
        "Scan 4xx/5xx response bodies for internal IPs, internal "
        "hostnames, absolute filesystem paths, JDBC / Mongo / Postgres "
        "/ MySQL / Redis / AMQP connection URIs, and .NET-style "
        "connection strings with embedded passwords."
    ),
    remediation=(
        "Disable production stack traces; route 4xx/5xx through a "
        "generic error template. Catch exceptions before serialisation "
        "and rotate any credential surfaced in evidence."
    ),
    tags=("info-leak", "error-handling", "infra-leak"),
))
def rule_error_response_leaks(ctx: RuleContext) -> Iterable[Finding]:
    if ctx.status < 400:
        return
    if not _is_text_response(ctx.resp_headers):
        return
    body = ctx.resp_body[:200_000]
    if not body:
        return
    seen: set[tuple[str, bytes]] = set()
    for slug, regex, severity, title, description, remediation in _ERROR_LEAK_PATTERNS:
        for match in regex.finditer(body):
            token = match.group(1) if match.groups() else match.group(0)
            key = (slug, token)
            if key in seen:
                continue
            seen.add(key)
            redacted = _redact_leak(token)
            yield Finding(
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
                cwe="CWE-209",
                owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=ctx.url, request_id=ctx.history_id,
                evidence=f"{slug}: {redacted} (status {ctx.status})",
                confidence="firm",
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
    # ---- B.1 additions ----
    rule_cors_null_origin,
    rule_cors_reflected_origin,
    rule_weak_tls_hint,
    rule_graphql_batching_hint,
    rule_session_fixation,
    rule_autocomplete_on_password,
    rule_cache_control_on_private,
    rule_open_redirect_hint_headers,
    # ---- Phase 20 ----
    rule_pii_secrets,
    # ---- Phase 21 ----
    rule_cve_server_fingerprint,
    # ---- Phase 23 ----
    rule_framework_debug_pages,
    # ---- Phase 24 ----
    rule_subdomain_takeover_hint,
    rule_error_response_leaks,
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
