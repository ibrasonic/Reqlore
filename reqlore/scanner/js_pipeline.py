"""Phase 13 — JavaScript analysis pipeline integration.

Auto-invokes the Phase 7 static analyser (:mod:`reqlore.scanner.js_static`)
and the Phase 8 dynamic DOM analyser (:mod:`reqlore.scanner.js_dynamic`)
during an active scan. The trigger is the
:attr:`ActiveOptions.js_analysis_mode` field, normally set by the
scan preset (Phase 9):

* ``"off"`` — skip JS analysis entirely. Used by ``lightweight`` /
  ``fast`` presets so cheap scans stay cheap.
* ``"static_only"`` — run the AST taint analyser against JS response
  bodies and inline ``<script>`` blocks inside HTML responses. No
  headless browser involved; safe for any environment.
* ``"static_plus_confirm"`` — run static analysis on every JS / HTML
  response, and *only* spin up the headless browser for URLs that
  produced at least one static finding. The dynamic hits are then
  passed back to :func:`reqlore.scanner.js_dynamic.cross_confirm_findings`
  so confirmed findings get promoted ``firm → certain``. This is the
  cheapest path to runtime evidence and is the ``balanced`` preset
  default.
* ``"static_plus_dynamic"`` — always run dynamic analysis for any
  response containing JavaScript, with full event driving and
  optional DOM Hunter persistence. Used by the ``deep`` preset.

Design contract:

* **Pure-Python by default.** The static stage works without any
  optional dependency installed (esprima absence is handled inside
  ``analyze_js`` itself by returning ``[]``).
* **Dynamic stage is opt-in via Playwright.** When Playwright isn't
  installed, ``analyze_dynamic`` returns ``[]`` and the pipeline
  silently degrades to static-only behaviour. The mode label remains
  whatever the caller asked for — we don't silently rewrite it.
* **Never blocks a scan.** Every exception path returns whatever
  partial results were collected so far. The caller wraps the whole
  hook in its own try/except as a second line of defence, but the
  pipeline itself is defensive at every analyser call site.
* **Injectable analysers.** The two analyser functions can be passed
  in directly via ``static_analyzer`` / ``dynamic_analyzer``, which
  is what the unit tests use to avoid the optional dependency cost.

The module exposes:

* :class:`JSPipelineResult` — the value returned by the hook.
* :func:`run_js_pipeline` — the single entry point.
* :func:`is_javascript_response` / :func:`is_html_response` /
  :func:`extract_inline_scripts` — helpers re-used by both the
  scanner and the test suite.
* :data:`JS_ANALYSIS_MODES` — the canonical tuple of accepted mode
  strings. ``ActiveOptions.__post_init__`` validates against it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .findings import Finding


# Canonical tuple of accepted modes. Order matters: it's the order
# the web UI renders them and the order ``preset_summary`` reports.
JS_ANALYSIS_MODES: tuple[str, ...] = (
    "off",
    "static_only",
    "static_plus_confirm",
    "static_plus_dynamic",
)

DEFAULT_JS_ANALYSIS_MODE: str = "off"


# Content-Type substrings that count as "JavaScript response body".
# Lower-cased; matched as substrings so attribute suffixes like
# ``application/javascript; charset=utf-8`` still trigger.
_JS_CONTENT_TYPES: tuple[str, ...] = (
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/ecmascript",
)

# Content-Type substrings that count as "HTML response body" — used
# to decide whether to extract inline ``<script>`` blocks.
_HTML_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml",
)

# Caps so a pathological page can't blow the pipeline budget.
_MAX_INLINE_SCRIPTS_PER_PAGE: int = 32
_MAX_SCRIPT_BYTES: int = 2_000_000  # matches js_static.analyze_js default


# ``<script ... >...</script>`` extractor. The first capture is the
# attribute soup (used to skip non-JS script types), the second is
# the script body.
_SCRIPT_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)

# Script ``type=`` values that mean "not executable JavaScript".
# Anything that isn't in this list (or absent entirely) is treated
# as JS. ``module`` *is* JS so it isn't here. JSON islands and
# templates are.
_NON_JS_SCRIPT_TYPES: frozenset[str] = frozenset({
    "application/json",
    "application/ld+json",
    "text/json",
    "text/template",
    "text/x-template",
    "text/x-handlebars-template",
    "text/x-jsrender",
    "text/x-mustache-template",
})


def _content_type(headers: Iterable[tuple[str, str]]) -> str:
    """Return the lower-cased ``Content-Type`` value, or ``""`` when
    absent. Header names are matched case-insensitively. Only the
    first header wins (per RFC 7231 a duplicate is malformed)."""
    for k, v in headers or ():
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def is_javascript_response(headers: Iterable[tuple[str, str]]) -> bool:
    """True when the response advertises a JavaScript MIME type."""
    ct = _content_type(headers)
    return any(t in ct for t in _JS_CONTENT_TYPES)


def is_html_response(headers: Iterable[tuple[str, str]]) -> bool:
    """True when the response advertises an HTML MIME type."""
    ct = _content_type(headers)
    return any(t in ct for t in _HTML_CONTENT_TYPES)


def _decode_body(body: bytes | str) -> str:
    """Best-effort decode of a response body to a Python ``str``.

    The Phase 7 analyser operates on text. Most JS / HTML bodies are
    UTF-8 or ASCII; latin-1 is the safe fallback because it round-trips
    every byte without raising. We never want this to throw — a parse
    failure later just means zero findings, which is the safe default.
    """
    if isinstance(body, str):
        return body
    if not body:
        return ""
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1", errors="replace")


def extract_inline_scripts(html: bytes | str) -> list[str]:
    """Return the JS source of every executable inline ``<script>``.

    External scripts (``<script src=...>`` with no body) yield empty
    string and are skipped. JSON islands and template scripts are
    skipped via :data:`_NON_JS_SCRIPT_TYPES`. The result is capped at
    :data:`_MAX_INLINE_SCRIPTS_PER_PAGE` so a pathological page can't
    spike the budget.
    """
    text = _decode_body(html)
    if not text:
        return []
    out: list[str] = []
    for m in _SCRIPT_RE.finditer(text):
        attrs = (m.group(1) or "").lower()
        body = m.group(2) or ""
        if not body.strip():
            continue
        # Crude type= extraction — ``type='text/template'`` etc.
        type_match = re.search(
            r"""type\s*=\s*['"]?([^'">\s]+)""", attrs)
        if type_match:
            type_val = type_match.group(1).lower()
            if type_val in _NON_JS_SCRIPT_TYPES:
                continue
        out.append(body)
        if len(out) >= _MAX_INLINE_SCRIPTS_PER_PAGE:
            break
    return out


# ---------------------------------------------------------------------------
# Result object + entry point.
# ---------------------------------------------------------------------------

@dataclass
class JSPipelineResult:
    """What :func:`run_js_pipeline` returns to the active scanner.

    Attributes
    ----------
    static_findings
        Every :class:`Finding` returned by the AST analyser, with
        ``host`` / ``url`` already stamped. The active scanner is
        responsible for handing each to :func:`record_finding` so
        suppression and fingerprinting are honoured.
    dynamic_hits
        Every :class:`DOMHit` collected by the runtime analyser.
        Empty in ``off`` / ``static_only`` modes, or when Playwright
        is unavailable. Persistence is the scanner's call (we hand
        the storage handle, the scanner decides whether to invoke
        :func:`persist_hits`).
    cross_confirmed_count
        Number of static findings whose ``confidence`` was promoted
        to ``"certain"`` by cross-confirmation. ``0`` whenever the
        dynamic stage didn't run.
    pages_analysed
        How many distinct response bodies the pipeline looked at.
        Useful for the run summary: an opt-in mode that processed
        zero pages tells the operator nothing on the wire was JS-y.
    """
    static_findings: list[Finding] = field(default_factory=list)
    dynamic_hits: list[Any] = field(default_factory=list)
    cross_confirmed_count: int = 0
    pages_analysed: int = 0


# Default analyser hooks — imported lazily inside ``run_js_pipeline``
# so importing this module never pulls esprima / Playwright in.
_StaticFn = Callable[..., list[Finding]]
_DynamicFn = Callable[..., list[Any]]
_CrossConfirmFn = Callable[[list[Finding], list[Any]], list[Finding]]


def _default_static_analyzer(source: str, *, host: str, url: str
                               ) -> list[Finding]:
    from .js_static import analyze_js
    return analyze_js(source, host=host, url=url)


def _default_dynamic_analyzer(url: str, **kwargs: Any) -> list[Any]:
    from .js_dynamic import analyze_dynamic
    return analyze_dynamic(url, **kwargs)


def _default_cross_confirm(static_findings: list[Finding],
                            dynamic_hits: list[Any]) -> list[Finding]:
    from .js_dynamic import cross_confirm_findings
    return cross_confirm_findings(static_findings, dynamic_hits)


def _normalise_mode(mode: str | None) -> str:
    """Coerce ``mode`` to a canonical entry of :data:`JS_ANALYSIS_MODES`.

    Unknown / blank input degrades to ``"off"`` rather than raising —
    this is called from inside the scanner hot path and a bad value
    means "don't run JS" rather than "crash the scan".
    """
    if not mode:
        return "off"
    norm = str(mode).strip().lower()
    return norm if norm in JS_ANALYSIS_MODES else "off"


def run_js_pipeline(
    *,
    response_body: bytes | str,
    response_headers: Iterable[tuple[str, str]],
    host: str,
    url: str,
    mode: str,
    static_analyzer: _StaticFn | None = None,
    dynamic_analyzer: _DynamicFn | None = None,
    cross_confirm: _CrossConfirmFn | None = None,
    dynamic_options: Any | None = None,
) -> JSPipelineResult:
    """Run the configured JS analysis stages for a single response.

    Returns a :class:`JSPipelineResult`. Never raises — analyser
    failures yield empty stage output and the rest of the pipeline
    continues. The caller is responsible for persisting findings /
    DOM hits and updating any run-level counters.
    """
    result = JSPipelineResult()
    canonical = _normalise_mode(mode)
    if canonical == "off":
        return result

    body_text = _decode_body(response_body)
    if not body_text:
        return result
    if len(body_text) > _MAX_SCRIPT_BYTES * 4:
        # The static analyser caps itself at 2 MB per call. An HTML
        # page bigger than 8 MB is almost certainly not worth scoring
        # for inline scripts — bail to keep the wall-clock honest.
        return result

    # Decide which source snippets to feed the analyser.
    snippets: list[str] = []
    if is_javascript_response(response_headers):
        snippets.append(body_text)
    elif is_html_response(response_headers):
        snippets = extract_inline_scripts(body_text)
    else:
        # Not a JS-bearing response by content type. Skip cleanly so
        # we don't fingerprint binary payloads.
        return result

    if not snippets:
        return result

    static_fn = static_analyzer or _default_static_analyzer
    static_findings: list[Finding] = []
    for snippet in snippets:
        try:
            static_findings.extend(
                static_fn(snippet, host=host, url=url) or [])
        except Exception:  # noqa: BLE001 — never raise from the hook
            continue

    result.static_findings = static_findings
    result.pages_analysed = 1

    # Static-only stops here.
    if canonical == "static_only":
        return result

    # Decide whether to invoke the dynamic stage.
    should_dynamic = (
        canonical == "static_plus_dynamic"
        or (canonical == "static_plus_confirm" and bool(static_findings))
    )
    if not should_dynamic:
        return result

    dynamic_fn = dynamic_analyzer or _default_dynamic_analyzer
    try:
        kwargs: dict[str, Any] = {}
        if dynamic_options is not None:
            kwargs["options"] = dynamic_options
        hits = dynamic_fn(url, **kwargs) or []
    except Exception:  # noqa: BLE001
        hits = []
    result.dynamic_hits = list(hits)

    # Only attempt cross-confirmation when both stages produced
    # something. Empty lists are cheap to skip.
    if static_findings and hits:
        try:
            confirm_fn = cross_confirm or _default_cross_confirm
            confirmed = confirm_fn(static_findings, list(hits))
        except Exception:  # noqa: BLE001
            confirmed = static_findings
        before = sum(
            1 for f in static_findings
            if getattr(f, "confidence", "firm") == "certain"
        )
        after = sum(
            1 for f in confirmed
            if getattr(f, "confidence", "firm") == "certain"
        )
        if after >= before:
            result.cross_confirmed_count = max(0, after - before)
            result.static_findings = confirmed

    return result
