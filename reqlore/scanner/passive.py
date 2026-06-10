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
                severity=sev, title=f"Missing response header: {name}",
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
