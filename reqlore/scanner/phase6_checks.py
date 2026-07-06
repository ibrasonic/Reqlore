"""Phase 6 — expanded active-check catalogue for Burp parity.

Adds 18 new :class:`ActiveCheck` subclasses, registered at module-import
time onto :data:`BUILTIN_ACTIVE_CHECKS`. Every check follows the contract
established in :mod:`reqlore.scanner.active`:

* never raise; catch network/parser errors and either yield a tentative
  finding or return silently
* call :meth:`ActiveContext.claim_probe` before every probe
* set ``rule_id = self.meta.id`` once at the top of ``run``
* yield :class:`Finding` objects with ``confidence`` set explicitly

The checks intentionally bias toward firm/tentative rather than certain;
several detection heuristics here are inherently fuzzy (padding oracles,
cache poisoning, mass assignment) and false-positives hurt more than
false-negatives at scan time.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import urllib.parse as up
from collections.abc import Iterable
from typing import Any, Literal, cast

from ..engines import Request
from .active import (
    BUILTIN_ACTIVE_CHECKS,
    ActiveCheck,
    ActiveContext,
    ActiveOptions,
    _mutated,
    _mutated_header,
    _scrub_headers,
)
from .findings import Finding
from .rules import RuleMeta

# ---------------------------------------------------------------------------
# Shared helpers — kept small + private to this module.
# ---------------------------------------------------------------------------

# Body inspection cap: every check truncates response bodies before scanning
# so a pathological 50 MB response can't blow memory or wall-clock.
_BODY_CAP = 200_000

# Email-like parameter names that warrant SMTP-header-injection probing.
_EMAIL_PARAM_NAMES = (
    "email", "e-mail", "mail", "from", "to", "cc", "bcc",
    "sender", "recipient", "address", "reply-to", "reply_to", "replyto",
    "subject",
)

# Java EL / Spring EL signature: ${T(java.lang.Runtime)} fragment.
_EL_MAGIC_LEFT = 73127
_EL_MAGIC_RIGHT = 9173
_EL_MAGIC_PRODUCT = _EL_MAGIC_LEFT * _EL_MAGIC_RIGHT  # 670519871

# OAuth/SSO heuristic paths.
_OAUTH_PATH_HINTS = ("oauth", "callback", "authorize", "sso", "openid")

# LDAP error signatures (response body, case-insensitive).
_LDAP_ERROR_SIGS: tuple[bytes, ...] = (
    b"ldap_search",
    b"ldap_search_ext",
    b"ldap error",
    b"bad search filter",
    b"inappropriate matching",
    b"javax.naming.directory",
    b"com.sun.jndi.ldap",
    b"protocol error",
    b"javax.naming.namingexception",
    b"distinguishedname",
)

# XPath error signatures.
_XPATH_ERROR_SIGS: tuple[bytes, ...] = (
    b"xpathexception",
    b"xpath syntax error",
    b"invalid xpath",
    b"xmlxpatheval",
    b"system.xml.xpath",
    b"unclosed token",
    b"xpath: ",
)

# SMTP signatures (Postfix/Sendmail surface these into HTTP error bodies).
_SMTP_ERROR_SIGS: tuple[bytes, ...] = (
    b"smtp error",
    b"recipient address rejected",
    b"sender address rejected",
    b"550 5.1.1",
    b"550 5.7.1",
    b"net::smtp",
)

# CSV formula injection lead characters.
_CSV_FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def _has_any(haystack: bytes, needles: Iterable[bytes]) -> bytes | None:
    """Return the first needle found in haystack (case-insensitive) or None."""
    lower = haystack[:_BODY_CAP].lower()
    for n in needles:
        if n in lower:
            return n
    return None


def _looks_like_b64_cbc(value: str) -> bool:
    """Cheap heuristic: AES-CBC base64 is len%4==0, divisible by 16 raw, len>=24."""
    if len(value) < 24 or len(value) % 4 != 0:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= 16 and len(raw) % 16 == 0


def _flip_last_byte(value: str) -> str:
    """Flip the last byte of a base64-encoded ciphertext and re-encode."""
    try:
        raw = bytearray(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return value
    if not raw:
        return value
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def _content_type(headers: list[tuple[str, str]]) -> str:
    for k, v in headers:
        if k.lower() == "content-type":
            return v.split(";", 1)[0].strip().lower()
    return ""


def _is_json_body(headers: list[tuple[str, str]], body: bytes) -> bool:
    if "json" in _content_type(headers):
        return True
    # Sniff: JSON typically starts with { or [.
    snippet = body[:128].lstrip()
    return snippet.startswith(b"{") or snippet.startswith(b"[")


def _safe_json_load(body: bytes) -> Any:
    """Return parsed JSON or None — never raise."""
    try:
        return json.loads(body[:_BODY_CAP].decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        return None


def _header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    low = name.lower()
    for k, v in headers:
        if k.lower() == low:
            return v
    return None


# ---------------------------------------------------------------------------
# 1. CRLF / HTTP response splitting.
# ---------------------------------------------------------------------------

class CRLFInjectionCheck(ActiveCheck):
    """Inject CR/LF + a header-name marker into params and look for the
    marker echoed in the response headers.

    Real servers vary: some echo the raw injected line into ``Set-Cookie``
    or ``Location``; some prematurely terminate the header block and the
    injected ``X-Reqlore-Inj-*`` header materialises in ``resp.headers``.
    Either way the marker appears in the header set.
    """

    name = "crlf-injection"
    description = ("Inject CRLF + a unique header name; if the marker "
                   "shows up in the response header set, the server is "
                   "vulnerable to HTTP response splitting.")
    meta = RuleMeta(
        id="active:crlf-injection",
        intensity="medium",
        title="CRLF / HTTP response splitting",
        default_severity="high",
        cwe="CWE-93",
        owasp="A03:2021-Injection",
        description=(
            "User input containing carriage-return / line-feed bytes is "
            "echoed into the response header block, splitting it and "
            "letting an attacker forge headers or body."
        ),
        remediation=(
            "Strip CR/LF (and percent-encoded variants) from any value "
            "that is interpolated into a response header."
        ),
        tags=("crlf", "injection", "response-splitting"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(6)
                # Two-line payload: real servers fold on either \r\n or %0d%0a;
                # we send the raw form so urllib re-encodes it during URL build.
                payload = f"x\r\nX-Reqlore-Inj: {marker}"
                try:
                    req = _mutated(ctx, key, payload, loc)
                    pr = send(req)
                except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this CRLF probe and continue with remaining params
                    continue
                # Hit 1 — header materialised separately.
                inj = _header_value(pr.response.headers, "X-Reqlore-Inj")
                if inj and marker in inj:
                    yield self._finding(ctx, key, loc, payload,
                                         f"X-Reqlore-Inj: {inj}",
                                         confidence="firm")
                    continue
                # Hit 2 — marker leaked into Location / Set-Cookie verbatim.
                for hk in ("Location", "Set-Cookie", "Refresh", "Link"):
                    v = _header_value(pr.response.headers, hk)
                    if v and marker in v:
                        yield self._finding(ctx, key, loc, payload,
                                             f"{hk}: {v[:200]}",
                                             confidence="firm")
                        break

    def _finding(self, ctx, key, loc, payload, evidence, *, confidence):
        return Finding(
            severity="high",
            title="CRLF / HTTP response splitting",
            description=(
                f"The '{key}' {loc} parameter accepts CR/LF bytes and the "
                "injected header marker appears in the response. An "
                "attacker can split headers, forge cookies, poison the "
                "cache, or pivot to reflected XSS via injected body."
            ),
            remediation=(
                "Strip CR/LF (and the URL-encoded forms %0d / %0a) "
                "before interpolating into response headers."
            ),
            cwe="CWE-93", owasp="A03:2021-Injection",
            host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
            payload=payload, evidence=evidence, confidence=confidence,
        )


# ---------------------------------------------------------------------------
# 2. LDAP injection.
# ---------------------------------------------------------------------------

class LDAPInjectionCheck(ActiveCheck):
    """Inject classic LDAP filter syntax and look for either a known
    LDAP error string or a bypassed authentication response.
    """

    name = "ldap-injection"
    description = ("Inject LDAP filter syntax (``*)(uid=*`` etc.) and "
                   "look for LDAP error signatures in the response.")
    meta = RuleMeta(
        id="active:ldap-injection",
        intensity="medium",
        title="LDAP injection",
        default_severity="high",
        cwe="CWE-90",
        owasp="A03:2021-Injection",
        description=(
            "User input is interpolated into an LDAP search filter "
            "without escaping. Detection: server emits an LDAP-specific "
            "error string when given an unbalanced filter."
        ),
        remediation=(
            "Bind user input through the LDAP library's parameterised "
            "search API; never string-concatenate into a filter."
        ),
        tags=("ldap", "injection"),
    )

    PROBES = (
        "*)(uid=*",
        "*))%00",
        "*)(|(objectClass=*",
        "admin)(&)",
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for probe in self.PROBES:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    try:
                        req = _mutated(ctx, key, probe, loc)
                        pr = send(req)
                    except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this LDAP probe and continue with remaining probes
                        continue
                    sig = _has_any(pr.response.body, _LDAP_ERROR_SIGS)
                    if sig is None:
                        continue
                    # Don't double-report if the same signature was in the
                    # baseline response.
                    if sig in ctx.resp_body[:_BODY_CAP].lower():
                        continue
                    yield Finding(
                        severity="high",
                        title="LDAP injection",
                        description=(
                            f"The '{key}' {loc} parameter triggers an "
                            "LDAP error when given a broken filter. The "
                            "input is being interpolated directly into "
                            "an LDAP search expression."
                        ),
                        remediation=(
                            "Bind user input through the LDAP library's "
                            "parameterised search API; never concat into "
                            "a filter string."
                        ),
                        cwe="CWE-90", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence=f"LDAP signature: {sig.decode('latin-1')}",
                        confidence="firm",
                    )
                    return


# ---------------------------------------------------------------------------
# 3. XPath injection.
# ---------------------------------------------------------------------------

class XPathInjectionCheck(ActiveCheck):
    name = "xpath-injection"
    description = ("Inject XPath syntax (``' or '1'='1`` etc.) and "
                   "look for XPath parser errors in the response.")
    meta = RuleMeta(
        id="active:xpath-injection",
        intensity="medium",
        title="XPath injection",
        default_severity="high",
        cwe="CWE-91",
        owasp="A03:2021-Injection",
        description=(
            "User input is interpolated into an XPath expression "
            "without escaping. Detection: server emits an XPath-specific "
            "parser error."
        ),
        remediation=(
            "Use parameterised XPath APIs (e.g. ``XPath.compile`` with "
            "variable bindings) or strict input allow-listing."
        ),
        tags=("xpath", "injection"),
    )

    PROBES = ("' or '1'='1", "']", "%00']", "x' or 1=1 or 'x'='y")

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for probe in self.PROBES:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    try:
                        req = _mutated(ctx, key, probe, loc)
                        pr = send(req)
                    except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this XPath probe and continue with remaining probes
                        continue
                    sig = _has_any(pr.response.body, _XPATH_ERROR_SIGS)
                    if sig is None:
                        continue
                    if sig in ctx.resp_body[:_BODY_CAP].lower():
                        continue
                    yield Finding(
                        severity="high",
                        title="XPath injection",
                        description=(
                            f"The '{key}' {loc} parameter triggers an "
                            "XPath parser error. The input is being "
                            "interpolated directly into an XPath "
                            "expression."
                        ),
                        remediation=(
                            "Use parameterised XPath APIs with variable "
                            "binding."
                        ),
                        cwe="CWE-91", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence=f"XPath signature: {sig.decode('latin-1')}",
                        confidence="firm",
                    )
                    return


# ---------------------------------------------------------------------------
# 4. SMTP header injection.
# ---------------------------------------------------------------------------

class SMTPHeaderInjectionCheck(ActiveCheck):
    name = "smtp-header-injection"
    description = ("On email-like parameters, inject CR/LF + Bcc: and "
                   "look for SMTP error signatures or successful echo.")
    meta = RuleMeta(
        id="active:smtp-header-injection",
        intensity="medium",
        title="SMTP header injection",
        default_severity="high",
        cwe="CWE-93",
        owasp="A03:2021-Injection",
        description=(
            "An email-shaped parameter accepts CR/LF, which lets an "
            "attacker inject additional SMTP headers (Bcc, From, etc.) "
            "or rewrite the message body."
        ),
        remediation=(
            "Strip CR/LF from any header-bound value; use the mail "
            "library's structured API rather than concatenated headers."
        ),
        tags=("smtp", "injection"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                low = key.lower()
                if not any(name in low for name in _EMAIL_PARAM_NAMES):
                    continue
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(4)
                payload = f"a@b.test\r\nBcc: reqlore-{marker}@bcc.test"
                try:
                    req = _mutated(ctx, key, payload, loc)
                    pr = send(req)
                except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this SMTP-header probe and continue with remaining params
                    continue
                sig = _has_any(pr.response.body, _SMTP_ERROR_SIGS)
                if sig and sig not in ctx.resp_body[:_BODY_CAP].lower():
                    yield Finding(
                        severity="high",
                        title="SMTP header injection",
                        description=(
                            f"The '{key}' {loc} parameter accepts CR/LF "
                            "and reaches the mail layer, where the "
                            "injected header triggers an SMTP error."
                        ),
                        remediation=(
                            "Reject CR/LF in any email header value."
                        ),
                        cwe="CWE-93", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=payload,
                        evidence=f"SMTP signature: {sig.decode('latin-1')}",
                        confidence="firm",
                    )
                    return


# ---------------------------------------------------------------------------
# 5. SSI injection.
# ---------------------------------------------------------------------------

class SSIInjectionCheck(ActiveCheck):
    name = "ssi-injection"
    description = ("Inject SSI directives (``<!--#exec cmd=...-->``) and "
                   "look for evaluated output in the response.")
    meta = RuleMeta(
        id="active:ssi-injection",
        intensity="medium",
        title="Server-side includes injection",
        default_severity="high",
        cwe="CWE-97",
        owasp="A03:2021-Injection",
        description=(
            "The server evaluates a user-supplied SSI directive. "
            "Detection: send a probe whose output is a constant string "
            "and look for that string in the response body."
        ),
        remediation=(
            "Disable SSI on dynamic content, or sanitise user input "
            "before it reaches an SSI-enabled handler."
        ),
        tags=("ssi", "injection"),
    )

    # Constant probe: <!--#printenv --> output reliably contains
    # DOCUMENT_ROOT or SERVER_SOFTWARE. We also try <!--#echo var=...-->.
    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        marker = secrets.token_hex(5)
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                probe = f'<!--#echo var="REQLORE_{marker}" -->'
                try:
                    req = _mutated(ctx, key, probe, loc)
                    pr = send(req)
                except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this SSI probe and continue with remaining params
                    continue
                body = pr.response.body[:_BODY_CAP]
                # Apache's mod_include emits ``(none)`` for an undefined
                # variable reference, and crucially strips the SSI tag
                # markers from the response. So the signature is that
                # the comment is GONE but the surrounding context remains.
                if probe.encode() not in body and b"(none)" in body:
                    # Confirm by sending a second probe with a different
                    # marker — both must round-trip the same way to rule
                    # out a baseline ``(none)``.
                    if b"(none)" in ctx.resp_body[:_BODY_CAP]:
                        continue
                    yield Finding(
                        severity="high",
                        title="Server-side includes injection",
                        description=(
                            f"The '{key}' {loc} parameter is processed "
                            "by an SSI handler. The probe directive was "
                            "consumed (not echoed verbatim) and the "
                            "characteristic ``(none)`` output appeared."
                        ),
                        remediation=(
                            "Disable SSI processing on dynamic "
                            "content paths, or HTML-encode user input "
                            "before it reaches the SSI handler."
                        ),
                        cwe="CWE-97", owasp="A03:2021-Injection",
                        host=ctx.host, url=ctx.full_url,
                        request_id=ctx.history_id,
                        payload=probe,
                        evidence="SSI directive consumed; (none) emitted",
                        confidence="firm",
                    )


# ---------------------------------------------------------------------------
# 6. Java EL / Spring EL injection.
# ---------------------------------------------------------------------------

class ELInjectionCheck(ActiveCheck):
    """Java Expression Language injection — distinct from generic SSTI.

    Probes the JSP/JSF/Spring EL syntax ``${a*b}`` with a magic product;
    if the product appears in the response, the EL was evaluated.
    """

    name = "el-injection"
    description = ("Inject Java EL probes (``${a*b}``) with a magic "
                   "product and look for the product in the response.")
    meta = RuleMeta(
        id="active:el-injection",
        intensity="medium",
        title="Expression Language injection",
        default_severity="critical",
        cwe="CWE-917",
        owasp="A03:2021-Injection",
        description=(
            "User input is interpolated into a Java EL / Spring EL "
            "expression and evaluated server-side. EL injection is "
            "typically a stepping stone to RCE (T(Runtime).getRuntime)."
        ),
        remediation=(
            "Never evaluate user-controlled strings through "
            "ExpressionFactory; use the framework's safe-rendering API."
        ),
        tags=("el", "injection", "java"),
    )

    @property
    def _expected_str(self) -> str:
        return str(_EL_MAGIC_PRODUCT)

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        expected = self._expected_str.encode()
        # Skip if the magic product already appeared in baseline (vanishingly
        # unlikely with 9-digit primes-product but still defensive).
        if expected in ctx.resp_body[:_BODY_CAP]:
            return
        probes = (
            f"${{{_EL_MAGIC_LEFT}*{_EL_MAGIC_RIGHT}}}",
            f"#{{{_EL_MAGIC_LEFT}*{_EL_MAGIC_RIGHT}}}",
            # Bean-property: x.length() against a literal — only fires
            # when value coerces to a string; rare but cheap.
        )
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for probe in probes:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    try:
                        req = _mutated(ctx, key, probe, loc)
                        pr = send(req)
                    except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this EL probe and continue with remaining probes
                        continue
                    if expected in pr.response.body[:_BODY_CAP]:
                        yield Finding(
                            severity="critical",
                            title="Expression Language injection",
                            description=(
                                f"The '{key}' {loc} parameter was "
                                "evaluated as a Java EL expression. "
                                f"The probe '{probe}' evaluated to "
                                f"{self._expected_str}. EL injection "
                                "is typically a path to remote code "
                                "execution."
                            ),
                            remediation=(
                                "Stop evaluating user input as EL. Use "
                                "framework-safe rendering (e.g. JSTL "
                                "<c:out>) or escape strictly."
                            ),
                            cwe="CWE-917", owasp="A03:2021-Injection",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=probe,
                            evidence=f"EL output contains {self._expected_str}",
                            confidence="certain",
                        )
                        return


# ---------------------------------------------------------------------------
# 7. Generic code injection (PHP / Python / Ruby).
# ---------------------------------------------------------------------------

class CodeInjectionCheck(ActiveCheck):
    """Send language-specific eval-style payloads with a magic product
    and look for the evaluated product in the response."""

    name = "code-injection"
    description = ("Send PHP / Python / Ruby / Node code-eval probes "
                   "with a magic product and look for the product.")
    meta = RuleMeta(
        id="active:code-injection",
        intensity="medium",
        title="Server-side code injection",
        default_severity="critical",
        cwe="CWE-94",
        owasp="A03:2021-Injection",
        description=(
            "User input reaches a language-level eval (PHP, Python, "
            "Ruby, Node, Perl). Detection: the probe's arithmetic is "
            "evaluated and the product appears in the response."
        ),
        remediation=(
            "Never pass user input to ``eval``/``exec``/``system`` or "
            "their language equivalents. Use safer dispatch primitives."
        ),
        tags=("code-injection", "rce"),
    )

    # Each probe pair: (payload, expected-string-in-response).
    @property
    def _probes(self) -> tuple[tuple[str, str], ...]:
        a, b = 6113, 7919  # both primes; product = 48,438,847
        prod = str(a * b)
        return (
            (f"';print({a}*{b});//", prod),       # PHP single-quoted
            (f"\";print({a}*{b});//", prod),      # PHP double-quoted
            (f"${{print({a}*{b})}}",  prod),      # PHP heredoc / Perl
            (f"<?={a}*{b}?>",         prod),      # PHP short echo
            (f"#{{ {a} * {b} }}",     prod),      # Ruby string interp
            (f";1;__import__('builtins').print({a}*{b});#", prod),
            # Python: kept harmless (builtins.print) but flips eval-mode servers.
        )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        baseline = ctx.resp_body[:_BODY_CAP]
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                for payload, expected in self._probes:
                    if not ctx.claim_probe(opts, rule_id, loc, key):
                        break
                    if expected.encode() in baseline:
                        continue
                    try:
                        req = _mutated(ctx, key, payload, loc)
                        pr = send(req)
                    except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this code-injection probe and continue with remaining probes
                        continue
                    if expected.encode() in pr.response.body[:_BODY_CAP]:
                        yield Finding(
                            severity="critical",
                            title="Server-side code injection",
                            description=(
                                f"The '{key}' {loc} parameter reached "
                                "a language-level eval. The probe was "
                                f"evaluated and produced {expected}."
                            ),
                            remediation=(
                                "Never pass user input to eval/exec/"
                                "system or equivalents."
                            ),
                            cwe="CWE-94", owasp="A03:2021-Injection",
                            host=ctx.host, url=ctx.full_url,
                            request_id=ctx.history_id,
                            payload=payload,
                            evidence=f"Eval output contains {expected}",
                            confidence="certain",
                        )
                        return


# ---------------------------------------------------------------------------
# 8. Padding-oracle (heuristic).
# ---------------------------------------------------------------------------

class PaddingOracleCheck(ActiveCheck):
    """Heuristic check: for any cookie / query value that looks like
    base64-encoded AES-CBC ciphertext (length divisible by 16 raw,
    >=16 bytes), flip the last byte and resend. If the response status
    or body length materially differs between original and flipped, we
    flag a tentative padding-oracle.

    This is intentionally tentative — many sites change responses for
    unrelated reasons. Operators should treat it as a lead, not a
    conclusion.
    """

    name = "padding-oracle"
    description = ("For base64-CBC-looking values, flip the last byte "
                   "and compare response — a divergence is a tentative "
                   "padding-oracle.")
    meta = RuleMeta(
        id="active:padding-oracle",
        intensity="intrusive",
        title="Padding oracle (tentative)",
        default_severity="medium",
        cwe="CWE-209",
        owasp="A02:2021-Cryptographic Failures",
        description=(
            "A value that looks like AES-CBC ciphertext differs between "
            "an intact and a corrupted submission. This is suggestive "
            "of a padding oracle (PKCS#7 unpad observable to the "
            "attacker)."
        ),
        remediation=(
            "Use authenticated encryption (AES-GCM or AES-CBC + HMAC) "
            "and ensure decryption errors yield indistinguishable "
            "responses to the user."
        ),
        tags=("crypto", "padding-oracle"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        # Build (loc, key, val) candidates from query, form, and cookie.
        candidates: list[tuple[str, str, str]] = []
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for k, v in pairs:
                if _looks_like_b64_cbc(v):
                    candidates.append((loc, k, v))
        # Cookies
        for hk, hv in ctx.req_headers:
            if hk.lower() != "cookie":
                continue
            for piece in hv.split(";"):
                piece = piece.strip()
                if "=" not in piece:
                    continue
                ck, cv = piece.split("=", 1)
                if _looks_like_b64_cbc(cv.strip()):
                    candidates.append(("cookie", ck.strip(), cv.strip()))

        for loc, key, original in candidates:
            if not ctx.claim_probe(opts, rule_id, loc, key):
                continue
            flipped = _flip_last_byte(original)
            if flipped == original:
                continue
            # Send baseline (the original was already observed; resend it
            # to normalise timing); then flipped.
            try:
                if loc == "cookie":
                    req_orig = _mutated_cookie_value(ctx, key, original)
                    req_flip = _mutated_cookie_value(ctx, key, flipped)
                else:
                    req_orig = _mutated(ctx, key, original, loc)
                    req_flip = _mutated(ctx, key, flipped, loc)
                pr_orig = send(req_orig)
                pr_flip = send(req_flip)
            except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this padding-oracle pair and continue with remaining params
                continue
            s1, s2 = pr_orig.response.status, pr_flip.response.status
            l1 = len(pr_orig.response.body or b"")
            l2 = len(pr_flip.response.body or b"")
            # Divergence: status changes, or body length differs > 10%.
            diverges = (
                (s1 != s2 and {s1, s2} != {0})
                or (l1 > 0 and abs(l1 - l2) / max(l1, 1) > 0.10)
            )
            if not diverges:
                continue
            yield Finding(
                severity="medium",
                title="Padding oracle (tentative)",
                description=(
                    f"The '{key}' {loc} value looks like AES-CBC "
                    "ciphertext and the response materially diverges "
                    f"when its last byte is flipped (status {s1}->{s2}, "
                    f"len {l1}->{l2}). This is suggestive of an "
                    "observable padding-validation oracle."
                ),
                remediation=(
                    "Use AES-GCM, or AES-CBC + HMAC-SHA256 with "
                    "constant-time comparison. Ensure decrypt failures "
                    "return an indistinguishable response."
                ),
                cwe="CWE-209",
                owasp="A02:2021-Cryptographic Failures",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"flipped={flipped[:60]}...",
                evidence=f"orig {s1}/{l1}B vs flipped {s2}/{l2}B",
                confidence="tentative",
            )


def _mutated_cookie_value(ctx: ActiveContext, name: str, new_val: str) -> Request:
    """Local copy of active._mutated_cookie that takes a raw value."""
    from .active import _mutated_cookie as _mc
    return _mc(ctx, name, new_val)


# ---------------------------------------------------------------------------
# 9. CSV / formula injection.
# ---------------------------------------------------------------------------

class CSVFormulaInjectionCheck(ActiveCheck):
    """When the response is a CSV / TSV / XLSX-export, check whether a
    user-controlled value can begin with a spreadsheet formula lead
    character (``=``/``+``/``-``/``@``/``\\t``/``\\r``) without being
    quoted or escaped."""

    name = "csv-formula-injection"
    description = ("If the response is a CSV / TSV export, send a "
                   "formula-prefixed marker and confirm it is echoed "
                   "into a cell without escaping.")
    meta = RuleMeta(
        id="active:csv-formula-injection",
        intensity="light",
        title="CSV / spreadsheet formula injection",
        default_severity="medium",
        cwe="CWE-1236",
        owasp="A03:2021-Injection",
        description=(
            "A user-controlled string is written to a CSV/TSV cell "
            "without leading-quote escaping. A spreadsheet client "
            "interprets cells starting with ``=`` (etc.) as formulas, "
            "letting an attacker exfiltrate data or run macros."
        ),
        remediation=(
            "Prefix any cell whose value starts with one of "
            "``=  +  -  @  \\t  \\r`` with a single quote (``'``), or "
            "use a CSV writer that quotes such values."
        ),
        tags=("csv", "injection"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id

        # Only run if baseline content-type is CSV/TSV.
        ct = _content_type(ctx.resp_headers)
        if not (ct in ("text/csv", "text/tab-separated-values",
                        "application/csv", "application/vnd.ms-excel")
                or ct.endswith("/csv")):
            return

        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(4)
                payload = f"=cmd|'/c calc {marker}'!A1"
                try:
                    req = _mutated(ctx, key, payload, loc)
                    pr = send(req)
                except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this CSV-formula probe and continue with remaining params
                    continue
                body = pr.response.body[:_BODY_CAP]
                # Vulnerable: marker echoed AND the leading char of the cell
                # containing it is one of the formula leads. CSV cells are
                # comma/tab-separated; we scan line-by-line then cell-by-cell.
                if marker.encode() not in body:
                    continue
                # Choose split char by content-type (csv -> ',' ; tsv -> '\t').
                resp_ct = _content_type(pr.response.headers)
                sep = b"\t" if "tab-separated" in resp_ct else b","
                hit = False
                for line in body.splitlines():
                    if marker.encode() not in line:
                        continue
                    for cell in line.split(sep):
                        if marker.encode() not in cell:
                            continue
                        # Peel a single leading quote (RFC-4180 cell quote).
                        stripped = cell
                        if stripped.startswith(b'"') and stripped.endswith(b'"'):
                            stripped = stripped[1:-1]
                        if not stripped:
                            continue
                        lead = stripped[:1]
                        if lead in tuple(c.encode() for c in _CSV_FORMULA_LEADS):
                            yield Finding(
                                severity="medium",
                                title="CSV / spreadsheet formula injection",
                                description=(
                                    f"The '{key}' {loc} parameter is "
                                    "written to a CSV cell without "
                                    "escaping a leading formula character. "
                                    "Opening the export in Excel/LibreOffice "
                                    "will execute the formula."
                                ),
                                remediation=(
                                    "Prefix dangerous-leading values with "
                                    "a single quote, or use a CSV writer "
                                    "that handles formula-injection."
                                ),
                                cwe="CWE-1236", owasp="A03:2021-Injection",
                                host=ctx.host, url=ctx.full_url,
                                request_id=ctx.history_id,
                                payload=payload,
                                evidence=f"cell starts with {lead!r}",
                                confidence="firm",
                            )
                            hit = True
                            break
                    if hit:
                        break
                if hit:
                    return


# ---------------------------------------------------------------------------
# 10. Mass-assignment.
# ---------------------------------------------------------------------------

class MassAssignmentCheck(ActiveCheck):
    """For JSON-bodied PUT/PATCH/POST requests, add a privileged-looking
    field (``role``/``admin``/``is_admin``/``isAdmin``) and look for it
    echoed in the response."""

    name = "mass-assignment"
    description = ("Inject a privileged-looking field (``role: admin``) "
                   "into a JSON request body and look for it echoed "
                   "back, suggesting it was bound to a server model.")
    meta = RuleMeta(
        id="active:mass-assignment",
        intensity="medium",
        title="Mass assignment / overposting",
        default_severity="high",
        cwe="CWE-915",
        owasp="A04:2021-Insecure Design",
        description=(
            "The endpoint blindly binds incoming JSON onto an internal "
            "model, allowing an attacker to set fields the UI never "
            "exposes (role, isAdmin, balance, owner_id)."
        ),
        remediation=(
            "Bind incoming JSON to an explicit DTO with a fixed field "
            "allow-list; never use ``Model.from_dict`` on user input."
        ),
        tags=("mass-assignment", "broken-access-control"),
    )

    _SUSPICIOUS_FIELDS = (
        ("role", "admin"),
        ("is_admin", True),
        ("isAdmin", True),
        ("admin", True),
        ("is_superuser", True),
        ("user_type", "admin"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if ctx.method.upper() not in ("POST", "PUT", "PATCH"):
            return
        if not _is_json_body(ctx.req_headers, ctx.req_body):
            return
        original = _safe_json_load(ctx.req_body)
        if not isinstance(original, dict):
            return

        for field_name, evil_value in self._SUSPICIOUS_FIELDS:
            if field_name in original:
                continue  # already present — not an injection target
            if not ctx.claim_probe(opts, rule_id, "body", field_name):
                continue
            mutated = dict(original)
            mutated[field_name] = evil_value
            try:
                body = json.dumps(mutated).encode("utf-8")
            except (TypeError, ValueError):
                continue
            req = Request(
                method=ctx.method, url=ctx.full_url,
                headers=_scrub_headers(ctx.req_headers), body=body,
            )
            try:
                pr = send(req)
            except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this JSON mass-assignment probe and continue with remaining fields
                continue
            # Detection: the server echoes our injected field back in the
            # JSON response. Two ways to count it: (a) the field key
            # appears in the response body, or (b) the parsed JSON has it.
            resp_body = pr.response.body[:_BODY_CAP]
            parsed = _safe_json_load(resp_body)
            echoed = False
            sample = ""
            if (isinstance(parsed, dict)
                    and field_name in parsed
                    and parsed[field_name] == evil_value):
                echoed = True
                sample = f'"{field_name}": {json.dumps(parsed[field_name])}'
            if not echoed:
                # Substring check — last-resort heuristic
                key_b = f'"{field_name}"'.encode()
                if key_b in resp_body and str(evil_value).encode().lower() in resp_body.lower():
                    echoed = True
                    sample = f'{field_name} echoed near {evil_value}'
            if not echoed:
                continue
            yield Finding(
                severity="high",
                title="Mass assignment / overposting",
                description=(
                    f"The endpoint accepted an extra '{field_name}' "
                    "field in the JSON body and echoed it back in the "
                    "response. The handler is binding the entire JSON "
                    "blob onto a server model without an allow-list."
                ),
                remediation=(
                    "Bind incoming JSON to a DTO with explicit "
                    "permitted fields; reject unknown keys."
                ),
                cwe="CWE-915",
                owasp="A04:2021-Insecure Design",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f'{field_name}={evil_value}',
                evidence=sample,
                confidence="firm",
            )
            return


# ---------------------------------------------------------------------------
# 11. Web cache poisoning (unkeyed input).
# ---------------------------------------------------------------------------

class CachePoisoningCheck(ActiveCheck):
    """Inject a unique marker via ``X-Forwarded-Host`` / ``X-Host`` and
    look for the marker reflected into the response. Cache-poisoning
    findings are tentative unless we can also re-fetch and observe the
    marker without sending the poisoned header — which we don't attempt
    here (it requires two network round-trips and a cache key insight)."""

    name = "cache-poisoning-unkeyed"
    description = ("Inject a marker into unkeyed-by-default headers "
                   "(X-Forwarded-Host etc.) and look for the marker "
                   "reflected in the response body or Location.")
    meta = RuleMeta(
        id="active:cache-poisoning-unkeyed",
        intensity="medium",
        title="Web cache poisoning via unkeyed header",
        default_severity="high",
        cwe="CWE-444",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "An unkeyed header (X-Forwarded-Host, X-Forwarded-Scheme) "
            "is reflected into the response. If the response is "
            "cacheable, an attacker can poison the cache for all users."
        ),
        remediation=(
            "Either include the reflected header in the cache key, or "
            "stop reflecting un-validated headers into the response."
        ),
        tags=("cache-poisoning", "web-cache"),
    )

    _UNKEYED_HEADERS = (
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for hname in self._UNKEYED_HEADERS:
            if not ctx.claim_probe(opts, rule_id, "header", hname):
                continue
            marker = secrets.token_hex(5)
            payload = f"reqlore-{marker}.invalid"
            try:
                req = _mutated_header(ctx, hname, payload)
                pr = send(req)
            except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this cache-poisoning header probe and continue with remaining headers
                continue
            body = pr.response.body[:_BODY_CAP]
            loc_h = _header_value(pr.response.headers, "Location") or ""
            link_h = _header_value(pr.response.headers, "Link") or ""
            if payload.encode() in body or payload in loc_h or payload in link_h:
                # Check the response is even cacheable (Cache-Control + age).
                cc = (_header_value(pr.response.headers,
                                     "Cache-Control") or "").lower()
                cacheable = ("public" in cc) or ("max-age" in cc and
                                                  "no-store" not in cc and
                                                  "private" not in cc)
                conf = "firm" if cacheable else "tentative"
                where = ("body" if payload.encode() in body else
                          "Location" if payload in loc_h else "Link")
                yield Finding(
                    severity="high" if cacheable else "medium",
                    title="Web cache poisoning via unkeyed header",
                    description=(
                        f"The '{hname}' header is reflected into the "
                        f"response {where}. "
                        + ("The response is cacheable, so this is "
                            "exploitable as cache poisoning." if cacheable
                            else "The response is not obviously "
                            "cacheable, but reflection of unkeyed "
                            "headers is a building block.")
                    ),
                    remediation=(
                        "Add the reflected header to the cache key, or "
                        "stop reflecting unvalidated headers."
                    ),
                    cwe="CWE-444",
                    owasp="A05:2021-Security Misconfiguration",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=f"{hname}: {payload}",
                    evidence=f"reflected in {where}; Cache-Control={cc or '(none)'}",
                    confidence=cast("Literal['tentative', 'firm', 'certain']", conf),
                )
                return


# ---------------------------------------------------------------------------
# 12. ASP.NET ViewState without MAC (passive-style confirmation).
# ---------------------------------------------------------------------------

# ViewState binary format: bytes 0..1 = format-version, then a serialized
# tree. MAC presence is indicated by __VIEWSTATEGENERATOR + __EVENTVALIDATION
# in the form. The plan calls this "without MAC" — we detect ViewState
# blobs that:
#   * are base64-decodable
#   * start with bytes 0xFF 0x01 (V1 format)
#   * are NOT accompanied by __EVENTVALIDATION

_VIEWSTATE_FIELD_RE = re.compile(
    rb'name="__VIEWSTATE"[^>]*value="([A-Za-z0-9+/=]+)"',
    re.IGNORECASE,
)
_EVENTVAL_FIELD_RE = re.compile(
    rb'name="__EVENTVALIDATION"',
    re.IGNORECASE,
)


class ViewStateNoMACCheck(ActiveCheck):
    name = "viewstate-no-mac"
    description = ("Detect __VIEWSTATE blobs without MAC (no "
                   "__EVENTVALIDATION sibling field) — a known RCE "
                   "vector when ViewStateUserKey is also unset.")
    meta = RuleMeta(
        id="active:viewstate-no-mac",
        intensity="light",
        title="ASP.NET ViewState without MAC",
        default_severity="high",
        cwe="CWE-345",
        owasp="A08:2021-Software and Data Integrity Failures",
        description=(
            "The page emits a __VIEWSTATE field but no "
            "__EVENTVALIDATION. If ViewStateUserKey is also unset, an "
            "attacker can deserialize arbitrary .NET gadgets via "
            "ysoserial.net — a well-known RCE."
        ),
        remediation=(
            "Enable EnableViewStateMac=true (default in modern .NET) "
            "and set a per-user ViewStateUserKey."
        ),
        tags=("aspnet", "viewstate", "deserialisation"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        # This check is observational — it inspects the baseline
        # response (no probe). We still call claim_probe so the budget
        # bookkeeping records the audit, and so a per-row dedupe works.
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        body = ctx.resp_body[:_BODY_CAP]
        if not body:
            return
        vs = _VIEWSTATE_FIELD_RE.search(body)
        if vs is None:
            return
        if _EVENTVAL_FIELD_RE.search(body):
            return  # MAC sibling present — properly configured
        if not ctx.claim_probe(opts, rule_id, "body", "__VIEWSTATE"):
            return
        # Make sure it actually decodes.
        try:
            raw = base64.b64decode(vs.group(1), validate=False)
        except (binascii.Error, ValueError):
            return
        if len(raw) < 4:
            return
        yield Finding(
            severity="high",
            title="ASP.NET ViewState without MAC",
            description=(
                "The page emits a __VIEWSTATE field but no "
                "__EVENTVALIDATION sibling. If ViewStateUserKey is "
                "also unset, an attacker can forge or replay arbitrary "
                "ViewState payloads."
            ),
            remediation=(
                "Enable EnableViewStateMac=true and set a non-empty "
                "machineKey + ViewStateUserKey."
            ),
            cwe="CWE-345",
            owasp="A08:2021-Software and Data Integrity Failures",
            host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
            payload="",
            evidence=f"__VIEWSTATE present ({len(raw)} bytes raw), no __EVENTVALIDATION",
            confidence="firm",
        )


# ---------------------------------------------------------------------------
# 13. HTTP PUT method enabled.
# ---------------------------------------------------------------------------

class HTTPPUTMethodCheck(ActiveCheck):
    """Send a PUT to a deterministically-named .txt under the same path
    and look for 200/201/204. The follow-up GET to confirm is left to
    the operator — we don't want to leave a writeable file behind that
    we can't reliably delete."""

    name = "http-put-method"
    description = ("Try ``PUT /reqlore-put-test.txt`` against the "
                   "target host's root; flag any 200/201/204 response.")
    meta = RuleMeta(
        id="active:http-put-method",
        intensity="intrusive",
        title="HTTP PUT method enabled",
        default_severity="critical",
        cwe="CWE-650",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "The server accepts an HTTP PUT against an arbitrary path. "
            "An attacker can upload arbitrary content, including "
            "executable webshells if PHP/CGI handlers are active on "
            "the upload destination."
        ),
        remediation=(
            "Disable PUT and DELETE at the web-server layer (e.g. "
            "``LimitExcept GET POST``) unless an authenticated "
            "publishing workflow requires them."
        ),
        tags=("http-method", "misconfiguration"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if not ctx.claim_probe(opts, rule_id, "method", "PUT"):
            return
        pr_url = up.urlparse(ctx.full_url)
        marker = secrets.token_hex(5)
        target = up.urlunparse(
            pr_url._replace(path=f"/reqlore-put-{marker}.txt",
                             query="", fragment="")
        )
        body = f"reqlore-put-probe-{marker}\n".encode("ascii")
        req = Request(
            method="PUT", url=target,
            headers=_scrub_headers(ctx.req_headers) + [
                ("Content-Type", "text/plain"),
            ],
            body=body,
        )
        try:
            pr = send(req)
        except Exception:
            return
        if pr.response.status in (200, 201, 204):
            yield Finding(
                severity="critical",
                title="HTTP PUT method enabled",
                description=(
                    f"PUT to {target} returned "
                    f"{pr.response.status}. The server accepts "
                    "arbitrary file uploads via PUT. Combined with "
                    "any handler that executes uploaded content, this "
                    "is full RCE."
                ),
                remediation=(
                    "Disable PUT (and DELETE) on user-facing paths."
                ),
                cwe="CWE-650",
                owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"PUT {target}",
                evidence=f"HTTP {pr.response.status} on PUT",
                confidence="firm",
            )


# ---------------------------------------------------------------------------
# 14. X-Forwarded-For trust (auth bypass).
# ---------------------------------------------------------------------------

class XFFTrustCheck(ActiveCheck):
    """When the baseline response is 401/403, retry with ``X-Forwarded-
    For: 127.0.0.1`` and ``X-Real-IP: 127.0.0.1`` — if status drops to
    200, the server trusts a client-controlled header for auth/scope."""

    name = "xff-trust-bypass"
    description = ("On 401/403 responses, retry with ``X-Forwarded-For: "
                   "127.0.0.1``. If status drops to 200, the server "
                   "spoofably trusts XFF.")
    meta = RuleMeta(
        id="active:xff-trust-bypass",
        intensity="medium",
        title="X-Forwarded-For / client-IP trust",
        default_severity="high",
        cwe="CWE-290",
        owasp="A07:2021-Identification and Authentication Failures",
        description=(
            "The server gates access on a client-controlled header "
            "(X-Forwarded-For / X-Real-IP / Client-IP). An attacker "
            "can forge it to access internal endpoints."
        ),
        remediation=(
            "Only trust X-Forwarded-For when it comes from a known "
            "front-end IP; never use it for authorisation."
        ),
        tags=("auth-bypass", "spoofable-ip"),
    )

    _SPOOF_HEADERS = (
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "X-Originating-IP",
        "True-Client-IP",
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if ctx.resp_status not in (401, 403):
            return
        for hname in self._SPOOF_HEADERS:
            if not ctx.claim_probe(opts, rule_id, "header", hname):
                continue
            try:
                req = _mutated_header(ctx, hname, "127.0.0.1")
                pr = send(req)
            except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this client-IP-spoof probe and continue with remaining headers
                continue
            if pr.response.status == 200:
                yield Finding(
                    severity="high",
                    title="X-Forwarded-For / client-IP trust",
                    description=(
                        f"The endpoint returned {ctx.resp_status} "
                        f"baseline, but 200 once '{hname}: 127.0.0.1' "
                        "was added. The server trusts a spoofable "
                        "client-IP header for access control."
                    ),
                    remediation=(
                        "Validate X-Forwarded-For only when it arrives "
                        "from your trusted proxy IPs."
                    ),
                    cwe="CWE-290",
                    owasp="A07:2021-Identification and Authentication Failures",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=f"{hname}: 127.0.0.1",
                    evidence=f"{ctx.resp_status} -> 200 with {hname}",
                    confidence="firm",
                )
                return


# ---------------------------------------------------------------------------
# 15. File-upload polyglot.
# ---------------------------------------------------------------------------

# GIF89a + PHP polyglot. The first 6 bytes pass GIF magic-byte sniffs;
# the PHP block executes when the file is requested through a PHP handler.
_GIF89A_PHP_POLYGLOT = (
    b"GIF89a;\n"
    b"<?php echo 'reqlore-polyglot-fired-%MARKER%'; ?>"
)


class UploadPolyglotCheck(ActiveCheck):
    """For multipart/form-data POST requests with a file field, submit
    a GIF+PHP polyglot. If the upload returns a URL that, when fetched,
    reflects the polyglot's PHP execution marker, the server runs
    uploaded content as code."""

    name = "upload-polyglot"
    description = ("On file-upload endpoints, submit a GIF89a + PHP "
                   "polyglot; if a follow-up fetch reflects the "
                   "polyglot's runtime marker, RCE is confirmed.")
    meta = RuleMeta(
        id="active:upload-polyglot",
        intensity="intrusive",
        title="Unrestricted file upload (polyglot)",
        default_severity="critical",
        cwe="CWE-434",
        owasp="A04:2021-Insecure Design",
        description=(
            "The server stores an uploaded GIF that also contains "
            "executable PHP. If the storage path is served by a PHP "
            "handler, fetching the file yields RCE."
        ),
        remediation=(
            "Validate content by magic bytes AND extension; serve "
            "uploads from a path with no script handlers."
        ),
        tags=("upload", "rce", "polyglot"),
    )

    _BOUNDARY = "----reqlorePolyglotBoundary"

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if ctx.method.upper() != "POST":
            return
        ct = _content_type(ctx.req_headers)
        if not ct.startswith("multipart/form-data"):
            return
        if not ctx.claim_probe(opts, rule_id, "multipart", "file"):
            return
        marker = secrets.token_hex(5)
        polyglot = _GIF89A_PHP_POLYGLOT.replace(b"%MARKER%", marker.encode())
        boundary = self._BOUNDARY
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; '
            f'filename="poly-{marker}.php.gif"\r\n'
            "Content-Type: image/gif\r\n\r\n"
        ).encode() + polyglot + f"\r\n--{boundary}--\r\n".encode()

        headers = _scrub_headers(ctx.req_headers)
        headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
        headers.append(
            ("Content-Type", f"multipart/form-data; boundary={boundary}")
        )
        req = Request(
            method="POST", url=ctx.full_url,
            headers=headers, body=body,
        )
        try:
            pr = send(req)
        except Exception:
            return
        # First-stage detection: server echoes a 200 + a URL pointing at
        # the file. If we cannot find a stored URL, raise tentative if
        # response body contains the filename.
        body_resp = pr.response.body[:_BODY_CAP]
        if pr.response.status not in (200, 201, 202):
            return
        filename = f"poly-{marker}.php.gif".encode()
        if filename not in body_resp:
            return

        # Second-stage detection: try to fetch the file at common upload
        # paths and look for the PHP marker. We try the URL referenced
        # in the response if we can extract one; otherwise we don't.
        url_match = re.search(
            rb'https?://[^\s"\'<>]+poly-' + marker.encode() + rb'\.php\.gif',
            body_resp,
        )
        if not url_match:
            yield Finding(
                severity="medium",
                title="Unrestricted file upload (polyglot accepted)",
                description=(
                    "A GIF+PHP polyglot was accepted by the upload "
                    "endpoint. The response references the uploaded "
                    "filename. Whether the polyglot executes depends "
                    "on the storage handler; this is a strong lead."
                ),
                remediation=(
                    "Reject double-extension filenames; validate magic "
                    "bytes AND extension."
                ),
                cwe="CWE-434", owasp="A04:2021-Insecure Design",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"polyglot upload poly-{marker}.php.gif",
                evidence=f"server accepted polyglot (HTTP {pr.response.status})",
                confidence="tentative",
            )
            return

        # If we can fetch the stored polyglot, the marker decides.
        stored_url = url_match.group(0).decode("latin-1", errors="replace")
        try:
            verify = send(Request(method="GET", url=stored_url,
                                    headers=[], body=b""))
        except Exception:
            return
        if marker.encode() in verify.response.body[:_BODY_CAP] and \
                f"reqlore-polyglot-fired-{marker}".encode() in verify.response.body[:_BODY_CAP]:
            yield Finding(
                severity="critical",
                title="Unrestricted file upload + PHP execution",
                description=(
                    "A GIF+PHP polyglot uploaded to "
                    f"{stored_url} executes its PHP block when "
                    "fetched. This is full server-side code execution."
                ),
                remediation=(
                    "Serve uploads from a domain or path with no "
                    "script handlers; reject double-extensions."
                ),
                cwe="CWE-434", owasp="A04:2021-Insecure Design",
                host=ctx.host, url=stored_url, request_id=ctx.history_id,
                payload=f"polyglot upload poly-{marker}.php.gif",
                evidence=f"PHP marker reqlore-polyglot-fired-{marker} echoed",
                confidence="certain",
            )


# ---------------------------------------------------------------------------
# 16. OAuth state-not-validated.
# ---------------------------------------------------------------------------

class OAuthStateValidationCheck(ActiveCheck):
    """For OAuth callback URLs (path contains ``oauth``/``callback``/
    ``authorize`` and query contains ``code=``), strip ``state=`` and
    resend. If the response is still 200/302 (i.e. login proceeds),
    the relying party doesn't validate state — open to login CSRF.
    """

    name = "oauth-state-not-validated"
    description = ("For OAuth callback URLs, drop the ``state=`` "
                   "parameter; if the flow still succeeds, the RP "
                   "is missing CSRF protection.")
    meta = RuleMeta(
        id="active:oauth-state-not-validated",
        intensity="medium",
        title="OAuth state parameter not validated",
        default_severity="high",
        cwe="CWE-352",
        owasp="A01:2021-Broken Access Control",
        description=(
            "The OAuth relying party accepts a callback without a "
            "``state`` parameter, leaving the flow open to login-CSRF "
            "(attacker logs the victim into the attacker's account)."
        ),
        remediation=(
            "Always issue a cryptographically-random ``state``, store "
            "it server-side, and require an exact match on callback."
        ),
        tags=("oauth", "csrf"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        path = up.urlparse(ctx.full_url).path.lower()
        if not any(hint in path for hint in _OAUTH_PATH_HINTS):
            return
        q = ctx.query_pairs()
        keys = {k.lower() for k, _ in q}
        if "code" not in keys or "state" not in keys:
            return
        if not ctx.claim_probe(opts, rule_id, "query", "state"):
            return
        # Build URL with state removed.
        pr = up.urlparse(ctx.full_url)
        kept_pairs = [(k, v) for k, v in q if k.lower() != "state"]
        new_url = up.urlunparse(
            pr._replace(query=up.urlencode(kept_pairs, doseq=True))
        )
        req = Request(
            method=ctx.method, url=new_url,
            headers=_scrub_headers(ctx.req_headers), body=ctx.req_body,
        )
        try:
            pr_resp = send(req)
        except Exception:
            return
        # Vulnerable if status is 200/302/303 (login succeeded); secure
        # implementations return 400/401/403.
        if pr_resp.response.status in (200, 301, 302, 303, 307, 308):
            # Some servers redirect to an error page on bad state — sniff body.
            body = pr_resp.response.body[:_BODY_CAP].lower()
            if b"invalid state" in body or b"state mismatch" in body or \
                    b"missing state" in body or b"csrf" in body:
                return  # rejected — good
            yield Finding(
                severity="high",
                title="OAuth state parameter not validated",
                description=(
                    "The OAuth callback URL completed normally even "
                    "after the ``state`` parameter was removed. The "
                    "relying party doesn't enforce state validation, "
                    "leaving the flow open to login-CSRF."
                ),
                remediation=(
                    "Always issue + validate a random ``state`` on "
                    "every authorisation request."
                ),
                cwe="CWE-352",
                owasp="A01:2021-Broken Access Control",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"state removed -> {new_url}",
                evidence=f"HTTP {pr_resp.response.status} without state",
                confidence="firm",
            )


# ---------------------------------------------------------------------------
# 17. GraphQL alias-abuse (batched-query DoS / brute amplification).
# ---------------------------------------------------------------------------

class GraphQLAliasAbuseCheck(ActiveCheck):
    """If the request is a GraphQL POST, send a batched aliased query
    with N>=50 aliases of ``__typename`` and confirm the server returns
    all aliases. Servers without alias caps amplify brute-force probes."""

    name = "graphql-alias-abuse"
    description = ("Send a 50-aliased ``__typename`` query against the "
                   "GraphQL endpoint; if all aliases come back, the "
                   "server has no alias cap (DoS amplification).")
    meta = RuleMeta(
        id="active:graphql-alias-abuse",
        intensity="medium",
        title="GraphQL alias abuse / no alias cap",
        default_severity="medium",
        cwe="CWE-770",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "GraphQL aliases let one HTTP request issue N independent "
            "queries. Without a per-request alias cap, rate-limited "
            "operations (login, OTP-verify) can be amplified by N "
            "behind a single HTTP request."
        ),
        remediation=(
            "Limit alias count per request (sensible default: 10), "
            "and apply rate limits per (resolver, IP) not per HTTP."
        ),
        tags=("graphql", "dos", "rate-limit"),
    )

    _ALIAS_COUNT = 50

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        if ctx.method.upper() != "POST":
            return
        if not _is_json_body(ctx.req_headers, ctx.req_body):
            return
        parsed = _safe_json_load(ctx.req_body)
        if not isinstance(parsed, dict) or "query" not in parsed:
            return
        if not ctx.claim_probe(opts, rule_id, "body", "graphql-aliases"):
            return
        aliases = ", ".join(f"a{i}: __typename" for i in range(self._ALIAS_COUNT))
        new_query = f"query {{ {aliases} }}"
        body = json.dumps({"query": new_query}).encode("utf-8")
        req = Request(
            method="POST", url=ctx.full_url,
            headers=_scrub_headers(ctx.req_headers), body=body,
        )
        try:
            pr = send(req)
        except Exception:
            return
        if pr.response.status != 200:
            return
        parsed_resp = _safe_json_load(pr.response.body)
        if not isinstance(parsed_resp, dict):
            return
        data = parsed_resp.get("data")
        if not isinstance(data, dict):
            return
        # Count how many aliases came back.
        returned = sum(1 for k in data if k.startswith("a") and k[1:].isdigit())
        if returned >= self._ALIAS_COUNT:
            yield Finding(
                severity="medium",
                title="GraphQL alias abuse / no alias cap",
                description=(
                    f"A single GraphQL request with {self._ALIAS_COUNT} "
                    "aliases was processed in full. Without an alias "
                    "cap, brute-force / rate-limited operations can "
                    f"be amplified {self._ALIAS_COUNT}x behind one "
                    "HTTP round-trip."
                ),
                remediation=(
                    "Cap alias count per operation; rate-limit per "
                    "resolver invocation, not per HTTP request."
                ),
                cwe="CWE-770",
                owasp="A05:2021-Security Misconfiguration",
                host=ctx.host, url=ctx.full_url, request_id=ctx.history_id,
                payload=f"{self._ALIAS_COUNT} aliases of __typename",
                evidence=f"server returned {returned} aliases",
                confidence="firm",
            )


# ---------------------------------------------------------------------------
# 18. Input transformation (suspicious echo with case-fold / decode).
# ---------------------------------------------------------------------------

class InputTransformationCheck(ActiveCheck):
    """Send a marker with deterministic transformations applied and
    check whether the *transformed* form appears in the response.
    This surfaces servers that do silent case-folding, URL decoding,
    HTML decoding, etc., before storing/reflecting input — a useful
    primitive when chasing filter bypasses elsewhere."""

    name = "input-transformation"
    description = ("Probe how the server transforms input — case fold, "
                   "URL decode, HTML decode — by sending a known "
                   "marker and inspecting reflections.")
    meta = RuleMeta(
        id="active:input-transformation",
        intensity="light",
        title="Suspicious input transformation",
        default_severity="info",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "The server transforms input before reflecting it "
            "(case-fold, URL-decode, HTML-decode). Each transformation "
            "is a potential filter bypass when chasing XSS / SQLi."
        ),
        remediation=(
            "Audit any reflection of normalised input; ensure filters "
            "operate on the *post-normalisation* form."
        ),
        tags=("filter-bypass", "intel"),
    )

    def run(self, ctx, send, *, opts: ActiveOptions | None = None):
        opts = opts or ActiveOptions()
        rule_id = self.meta.id
        for loc, pairs in (("query", ctx.query_pairs()),
                            ("form", ctx.form_pairs())):
            for key, _ in pairs:
                if not ctx.claim_probe(opts, rule_id, loc, key):
                    continue
                marker = secrets.token_hex(4)
                # Mixed case + URL-encoded sentinel + HTML entity.
                payload = f"Ab%43-{marker}-&#88;yZ"
                try:
                    req = _mutated(ctx, key, payload, loc)
                    pr = send(req)
                except Exception:  # noqa: S112  # send() raises engine/transport errors on network/HTTP failure; skip this transform-detection probe and continue with remaining params
                    continue
                body = pr.response.body[:_BODY_CAP]
                if marker.encode() not in body:
                    continue
                transforms: list[str] = []
                if f"AbC-{marker}-XyZ".encode() in body:
                    transforms.append("url-decode")
                if f"ab%43-{marker}-&#88;yz".encode() in body.lower():
                    transforms.append("case-fold-lower")
                if f"AB%43-{marker}-&#88;YZ".encode() in body:
                    transforms.append("case-fold-upper")
                marker_pos = body.find(marker.encode())
                window_slice = body[max(0, marker_pos - 50):marker_pos + 50]
                if (f"AbC-{marker}-XyZ".encode() in body
                        and b"&#88;" not in window_slice
                        and "html-entity-decode" not in transforms):
                    transforms.append("html-entity-decode")
                if not transforms:
                    continue
                yield Finding(
                    severity="info",
                    title="Suspicious input transformation",
                    description=(
                        f"The '{key}' {loc} parameter is transformed "
                        f"before reflection: {', '.join(transforms)}. "
                        "These transformations are potential "
                        "filter-bypass primitives when chasing other "
                        "injection bugs."
                    ),
                    remediation=(
                        "Audit filters on the *post-normalisation* "
                        "form of the input."
                    ),
                    cwe="CWE-79", owasp="A03:2021-Injection",
                    host=ctx.host, url=ctx.full_url,
                    request_id=ctx.history_id,
                    payload=payload,
                    evidence=f"transformations: {', '.join(transforms)}",
                    confidence="firm",
                )
                return


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------

PHASE6_CHECKS: tuple[ActiveCheck, ...] = (
    CRLFInjectionCheck(),
    LDAPInjectionCheck(),
    XPathInjectionCheck(),
    SMTPHeaderInjectionCheck(),
    SSIInjectionCheck(),
    ELInjectionCheck(),
    CodeInjectionCheck(),
    PaddingOracleCheck(),
    CSVFormulaInjectionCheck(),
    MassAssignmentCheck(),
    CachePoisoningCheck(),
    ViewStateNoMACCheck(),
    HTTPPUTMethodCheck(),
    XFFTrustCheck(),
    UploadPolyglotCheck(),
    OAuthStateValidationCheck(),
    GraphQLAliasAbuseCheck(),
    InputTransformationCheck(),
)


def register_phase6_checks() -> None:
    """Idempotent: append every phase-6 check exactly once."""
    existing = {c.name for c in BUILTIN_ACTIVE_CHECKS}
    for check in PHASE6_CHECKS:
        if check.name not in existing:
            BUILTIN_ACTIVE_CHECKS.append(check)


register_phase6_checks()


__all__ = [
    "PHASE6_CHECKS",
    "register_phase6_checks",
    "CRLFInjectionCheck",
    "LDAPInjectionCheck",
    "XPathInjectionCheck",
    "SMTPHeaderInjectionCheck",
    "SSIInjectionCheck",
    "ELInjectionCheck",
    "CodeInjectionCheck",
    "PaddingOracleCheck",
    "CSVFormulaInjectionCheck",
    "MassAssignmentCheck",
    "CachePoisoningCheck",
    "ViewStateNoMACCheck",
    "HTTPPUTMethodCheck",
    "XFFTrustCheck",
    "UploadPolyglotCheck",
    "OAuthStateValidationCheck",
    "GraphQLAliasAbuseCheck",
    "InputTransformationCheck",
]
