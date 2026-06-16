"""DOM Hunter - DOM XSS source/sink tracer for Reqlore.

This package holds the server-side pieces. The browser-side agent lives
in ``reqlore/dom_hunter/extension/`` and POSTs findings to ``/_dom_hunter/report``.
"""
from __future__ import annotations

import hashlib
import secrets

# Default project-state keys used by DOM Hunter.
TOKEN_KEY = "dom_hunter_token"
CANARY_KEY = "dom_hunter_canary"
ENABLED_KEY = "dom_hunter_enabled"
SCOPE_KEY = "dom_hunter_scope"
AUTO_INJECT_KEY = "dom_hunter_auto_inject"  # comma-list: hash,search,winname,referrer

# Severity scale, low->high.
SEVERITIES = ("info", "low", "medium", "high", "critical")

# Canonical source catalog. Each entry has a stable id, a label, and a
# one-sentence plain-language explanation for screen-reader readers.
SOURCES: list[dict] = [
    {"id": "location.hash", "label": "URL fragment (after #)",
     "plain": "Text after # in the URL. Never sent to the server, so it is "
              "invisible to server logs and firewalls."},
    {"id": "location.search", "label": "URL query (after ?)",
     "plain": "Text after ? in the URL. Often shared in links."},
    {"id": "location.pathname", "label": "URL path",
     "plain": "The /path/part of the URL, when client-side routers read it."},
    {"id": "document.referrer", "label": "Referrer header",
     "plain": "The address of the page the user came from. Attackers control it "
              "from their own site."},
    {"id": "window.name", "label": "window.name",
     "plain": "A string a previous page or opener can set; persists across "
              "navigations within the same tab."},
    {"id": "document.cookie", "label": "Cookies",
     "plain": "Values stored as cookies; often previously tainted."},
    {"id": "localStorage", "label": "localStorage",
     "plain": "Persistent key/value store; often holds previously tainted data."},
    {"id": "sessionStorage", "label": "sessionStorage",
     "plain": "Per-tab key/value store; often holds previously tainted data."},
    {"id": "postMessage", "label": "Web message (postMessage)",
     "plain": "A message from another window or iframe, potentially "
              "cross-origin."},
    {"id": "fetch.response", "label": "fetch / XHR response body",
     "plain": "Data returned by an HTTP request; only as trustworthy as the "
              "responding endpoint."},
    {"id": "websocket.message", "label": "WebSocket message",
     "plain": "Data received over a WebSocket connection."},
    {"id": "unknown", "label": "Unknown",
     "plain": "Source not tracked yet. The agent saw the canary at the sink "
              "but could not attribute the original source."},
]

# Canonical sink catalog. Each entry has a stable id, a label, the default
# severity when the canary reaches it, and a plain-language explanation.
SINKS: list[dict] = [
    {"id": "Element.innerHTML", "label": "innerHTML assignment",
     "severity": "high",
     "plain": "The page set an element's HTML from a string. If the string "
              "came from the attacker, the browser parses it as HTML and "
              "runs any scripts inside."},
    {"id": "Element.outerHTML", "label": "outerHTML assignment",
     "severity": "high",
     "plain": "Same as innerHTML, but replaces the element itself."},
    {"id": "Element.insertAdjacentHTML", "label": "insertAdjacentHTML()",
     "severity": "high",
     "plain": "The page inserted HTML at a specific position from a string. "
              "Same risk as innerHTML."},
    {"id": "document.write", "label": "document.write()",
     "severity": "high",
     "plain": "The page wrote raw HTML into the document, which can include "
              "scripts."},
    {"id": "document.writeln", "label": "document.writeln()",
     "severity": "high",
     "plain": "Same as document.write, with a trailing newline."},
    {"id": "eval", "label": "eval()",
     "severity": "critical",
     "plain": "The page ran a string as JavaScript directly. Anything in the "
              "string executes."},
    {"id": "Function", "label": "Function() constructor",
     "severity": "critical",
     "plain": "The page compiled a string into a JavaScript function and ran "
              "it. Equivalent to eval."},
    {"id": "setTimeout(string)", "label": "setTimeout with a string",
     "severity": "high",
     "plain": "The page scheduled a string to be evaluated as JavaScript after "
              "a delay."},
    {"id": "setInterval(string)", "label": "setInterval with a string",
     "severity": "high",
     "plain": "The page scheduled a string to be evaluated as JavaScript "
              "repeatedly."},
    {"id": "Element.setAttribute(on*)", "label": "setAttribute on an event handler",
     "severity": "high",
     "plain": "The page installed an inline event handler (like onclick) from "
              "a string. The string runs as JavaScript when the event fires."},
    {"id": "HTMLScriptElement.src", "label": "script.src assignment",
     "severity": "critical",
     "plain": "The page set the URL of a script tag from a string, causing the "
              "browser to load and run that script."},
    {"id": "HTMLIFrameElement.src", "label": "iframe.src assignment",
     "severity": "medium",
     "plain": "The page set the URL of an iframe from a string; a "
              "javascript: URL would execute as code."},
    {"id": "location.href", "label": "location.href assignment",
     "severity": "high",
     "plain": "The page navigated to a URL from a string; a javascript: URL "
              "would execute as code."},
    {"id": "Worker", "label": "new Worker(url)",
     "severity": "high",
     "plain": "The page started a background worker from a URL string; the "
              "worker can run attacker code."},
    {"id": "importScripts", "label": "importScripts()",
     "severity": "high",
     "plain": "Inside a worker, the page loaded another script from a URL."},
    {"id": "HTMLIFrameElement.srcdoc", "label": "iframe.srcdoc assignment",
     "severity": "high",
     "plain": "The page set an iframe's full HTML document from a string. "
              "Scripts in the string run inside the iframe."},
    {"id": "DOMParser.parseFromString", "label": "DOMParser.parseFromString()",
     "severity": "medium",
     "plain": "The page parsed a string into a DOM. Risky if the parsed "
              "nodes are later inserted into the live document."},
    {"id": "Range.createContextualFragment", "label": "Range.createContextualFragment()",
     "severity": "high",
     "plain": "The page built a DocumentFragment from a string; the fragment "
              "is parsed as HTML and scripts may run when inserted."},
]

SINK_INDEX = {s["id"]: s for s in SINKS}
SOURCE_INDEX = {s["id"]: s for s in SOURCES}

# Auto-inject toggles available to the user. Keys match SOURCES ids.
AUTO_INJECT_TARGETS: list[tuple[str, str]] = [
    ("location.hash", "URL fragment (after #)"),
    ("location.search", "URL query (after ?)"),
    ("window.name", "window.name"),
    ("document.referrer", "document.referrer"),
]

# Per-auto-inject-source canary tag suffix. When auto-injecting we
# append "-<tag>" to the base canary so the agent can PROVE which
# source a tainted value flowed through by exact substring match,
# instead of guessing from canary co-occurrence across sources.
# Single ASCII letter, URL-safe in fragment / query / Referer / name.
CANARY_TAGS: dict[str, str] = {
    "location.hash":     "h",
    "location.search":   "s",
    "window.name":       "n",
    "document.referrer": "r",
}
CANARY_TAG_SEP = "-"


def tagged_canary(canary: str, source_id: str) -> str:
    """Return the canary variant the auto-inject path stamps into ``source_id``.

    Falls back to the base canary when ``source_id`` is not an auto-inject
    source (postMessage, document.cookie, storage, ...): those are
    observation-only and there is nothing to tag.
    """
    if not canary:
        return ""
    tag = CANARY_TAGS.get(source_id)
    if not tag:
        return canary
    return f"{canary}{CANARY_TAG_SEP}{tag}"


def tagged_canaries(canary: str) -> dict[str, str]:
    """Return ``{source_id: tagged_canary}`` for every auto-inject source.

    The agent uses this map to (a) auto-inject the right variant into
    each enabled source and (b) prove source attribution at sink-fire
    time by exact-substring match. Missing or empty ``canary`` yields
    an empty dict.
    """
    if not canary:
        return {}
    return {sid: f"{canary}{CANARY_TAG_SEP}{tag}"
            for sid, tag in CANARY_TAGS.items()}


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index((sev or "info").lower())
    except ValueError:
        return 0


def normalise_severity(sev: str | None) -> str:
    s = (sev or "").lower()
    return s if s in SEVERITIES else "medium"


def get_or_make_token(project) -> str:
    """Return the project's DOM Hunter bridge token, generating one on first call."""
    tok = project.get_state(TOKEN_KEY, "")
    if not tok:
        tok = secrets.token_urlsafe(32)
        project.set_state(TOKEN_KEY, tok)
    return tok


def get_or_make_canary(project) -> str:
    """Return the project's DOM Hunter canary string, generating one on first call.

    The canary is short, alphanumeric, and unlikely to appear naturally in
    page content (no dictionary substring).
    """
    c = project.get_state(CANARY_KEY, "")
    if not c:
        c = "rqdomh" + secrets.token_hex(6)
        project.set_state(CANARY_KEY, c)
    return c


def normalize_scope_entry(s: str) -> str:
    """Convert a user-typed scope entry to a canonical bare host[:port].

    Accepts the natural forms a user might paste in:

        example.com               -> example.com
        EXAMPLE.com               -> example.com
        http://example.com/path   -> example.com
        https://localhost:3001/   -> localhost:3001
        //example.com             -> example.com
        *.example.com             -> *.example.com   (wildcards preserved)
        ""                        -> ""               (caller filters)
    """
    s = (s or "").strip().lower()
    if not s:
        return ""
    if s.startswith("*."):
        # Wildcard. Still strip path/scheme just in case the user wrote
        # http://*.example.com/foo -- shouldn't happen, but be forgiving.
        rest = s[2:]
        if "://" in rest:
            rest = rest.split("://", 1)[1]
        for sep in ("/", "?", "#"):
            i = rest.find(sep)
            if i >= 0:
                rest = rest[:i]
        return "*." + rest if rest else ""
    if "://" in s:
        from urllib.parse import urlsplit
        try:
            u = urlsplit(s)
            return (u.netloc or "").lower()
        except Exception:
            return ""
    if s.startswith("//"):
        s = s[2:]
    for sep in ("/", "?", "#"):
        i = s.find(sep)
        if i >= 0:
            s = s[:i]
    return s


def get_scope(project) -> list[str]:
    raw = project.get_state(SCOPE_KEY, "")
    # Normalize on read too, so legacy entries (saved before the
    # normalizer existed) are still matched correctly without forcing
    # the user to re-save.
    out: list[str] = []
    for s in raw.split(","):
        n = normalize_scope_entry(s)
        if n:
            out.append(n)
    return out


def set_scope(project, hosts: list[str]) -> None:
    cleaned = ",".join(
        n for n in (normalize_scope_entry(h) for h in hosts) if n
    )
    project.set_state(SCOPE_KEY, cleaned)


def is_enabled(project) -> bool:
    return project.get_state(ENABLED_KEY, "0") == "1"


def set_enabled(project, on: bool) -> None:
    project.set_state(ENABLED_KEY, "1" if on else "0")


def get_auto_inject(project) -> list[str]:
    raw = project.get_state(AUTO_INJECT_KEY, "")
    return [s for s in raw.split(",") if s]


def set_auto_inject(project, targets: list[str]) -> None:
    valid = {t for t, _ in AUTO_INJECT_TARGETS}
    cleaned = ",".join(t for t in targets if t in valid)
    project.set_state(AUTO_INJECT_KEY, cleaned)


def host_in_scope(host: str, scope: list[str]) -> bool:
    """Return True if `host` is covered by the scope list.

    Empty scope means "every host" (DOM Hunter's default). Each entry can be a
    literal host or ``*.example.com`` for that domain and subdomains.
    """
    if not scope:
        return True
    h = (host or "").lower()
    for pat in scope:
        p = pat.lower()
        if p.startswith("*."):
            base = p[2:]
            if h == base or h.endswith("." + base):
                return True
        elif h == p:
            return True
    return False


# Query-string parameter name used by all four auto-inject paths so the
# server-side test logic only has to look for one tag regardless of which
# source the canary entered through.
REFERER_CANARY_PARAM = "rqdomh"


def inject_referer_canary(
    headers: list[tuple[str, str]],
    canary: str,
) -> list[tuple[str, str]]:
    """Return a copy of ``headers`` with the canary appended to Referer.

    Behaviour:
      * No ``Referer`` header (case-insensitive): returns ``headers`` unchanged.
        We deliberately do NOT synthesise a Referer when the browser omitted
        one (e.g. ``Referrer-Policy: no-referrer``, cross-origin downgrades),
        because doing so would leak origin information the user's policy
        explicitly suppressed.
      * Referer is present but empty: unchanged.
      * Referer already contains the canary value: unchanged (idempotent).
      * Referer is a URL with no query: append ``?rqdomh=<canary>``.
      * Referer is a URL with a query: append ``&rqdomh=<canary>``.
      * If the URL already has a fragment we splice the param into the query,
        not after the ``#`` (the server never sees fragments anyway, but a
        well-formed Referer keeps the fragment trailing).

    Only the FIRST Referer header is rewritten if multiple are somehow
    present (RFC 7230 forbids that, but proxies see broken clients).
    """
    if not canary:
        return headers
    out: list[tuple[str, str]] = []
    rewritten = False
    for k, v in headers:
        if not rewritten and k.lower() == "referer":
            new_v = _append_canary_to_url(v, canary)
            out.append((k, new_v))
            rewritten = True
        else:
            out.append((k, v))
    return out


def _append_canary_to_url(url: str, canary: str) -> str:
    """Splice ``rqdomh=<canary>`` into the query of ``url``. Pure string op.

    Preserves the fragment when present so the resulting URL stays
    syntactically valid. Returns the original string untouched when the
    canary already appears anywhere in the URL.
    """
    if not url:
        return url
    if canary in url:
        return url
    # Split off fragment first so '#' doesn't get treated as part of the query.
    frag = ""
    hash_at = url.find("#")
    if hash_at >= 0:
        frag = url[hash_at:]
        url = url[:hash_at]
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{REFERER_CANARY_PARAM}={canary}{frag}"


def should_inject_referer(
    project,
    host: str,
) -> bool:
    """Cheap, no-fetch check used by the proxy hook on every request.

    Returns True iff DOM Hunter is enabled, ``document.referrer`` is one of
    the user's auto-inject choices, and ``host`` is in scope. Keep it tight
    -- this runs in the proxy's hot path.
    """
    if not is_enabled(project):
        return False
    targets = get_auto_inject(project)
    if "document.referrer" not in targets:
        return False
    return host_in_scope(host, get_scope(project))


def dedupe_key(*, sink: str, source: str, page_url: str,
               stack: str, canary_seen: bool) -> str:
    """Produce a stable dedupe key. Stack top frame collapses duplicates."""
    top = ""
    for line in (stack or "").splitlines():
        line = line.strip()
        if line and not line.startswith("Error"):
            top = line
            break
    raw = "|".join([sink, source, page_url, top, "c" if canary_seen else "n"])
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
