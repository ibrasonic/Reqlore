"""Phase 8 — JavaScript dynamic DOM analysis (headless browser).

The **scanner-driven** sibling of the interactive
:mod:`reqlore.dom_hunter` Firefox extension. Same canonical sink and
source catalogues; same tagged-canary attribution model; same severity
policy; same dedup key; same SQLite table when persisted.

Difference: DOM Hunter expects a human to walk the app in their own
Firefox; this module spins up headless Chromium during an automated
scan.

Pre-load instrumentation hooks the canonical DOM Hunter sink set
(``Element.innerHTML``, ``eval``, ``document.write``, ...) using the
same wrapping strategy as
``reqlore/dom_hunter/extension/content/agent.js``. Source attribution
uses per-source tagged canaries (``-h``, ``-s``, ``-n``, ``-r``) so the
analyser can prove which source a value flowed through by exact
substring match.

Public surface::

    from reqlore.scanner.js_dynamic import (
        DOMHit, DynamicOptions, analyze_dynamic,
        cross_confirm_findings, persist_hits,
    )

    hits = analyze_dynamic(url, canary="RQLDYN1234")
    upgraded = cross_confirm_findings(static_findings, hits)
    persist_hits(storage, hits)  # appear under /dom-hunter/

When Playwright is unavailable :func:`analyze_dynamic` returns ``[]``.
"""
from __future__ import annotations

import contextlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .. import dom_hunter as _dh
from ..dom_hunter import (
    CANARY_TAGS,
    SINK_INDEX,
    dedupe_key,
    normalise_severity,
    tagged_canaries,
)
from .findings import Finding

try:
    from .._optdeps import PLAYWRIGHT_AVAILABLE
except ImportError:  # pragma: no cover — _optdeps is part of the package
    PLAYWRIGHT_AVAILABLE = False


# Canonical DOM Hunter source ids the analyser can *inject* canaries
# into. Other source ids in SOURCE_INDEX (cookie, storage, fetch
# response, websocket message) are observation-only.
_INJECTABLE_SOURCES: frozenset[str] = frozenset(CANARY_TAGS.keys())


# ---------------------------------------------------------------------------
# Public types.
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DOMHit:
    """A single record of a canary flowing into a dangerous DOM sink.

    Fields mirror the DOM Hunter ``dom_hunter_findings`` columns so
    :func:`persist_hits` can drop hits straight into the same store.
    """

    sink: str                   # canonical DOM Hunter sink id, e.g. "Element.innerHTML"
    source_label: str           # canonical DOM Hunter source id (may be comma-list)
    canary: str                 # base canary (without -h/-s/-n/-r tag)
    severity: str = "high"      # from SINK_INDEX[sink]["severity"]
    snippet: str = ""           # truncated copy of the offending value
    via_event: str = ""         # event that triggered the hit (or "")
    page_url: str = ""          # URL the analyser navigated to
    canary_seen: bool = True


@dataclass(slots=True)
class DynamicOptions:
    """Runtime knobs for :func:`analyze_dynamic`."""

    budget_s: float = 15.0
    nav_timeout_ms: int = 8_000
    settle_ms: int = 250
    drive_events: bool = True
    max_events: int = 20
    headless: bool = True
    snippet_chars: int = 120
    inject_referrer: bool = True


# ---------------------------------------------------------------------------
# Instrumentation — hook set identical to DOM Hunter's content agent.
# ---------------------------------------------------------------------------

_INSTRUMENTATION_JS = r"""
(canaryArg, taggedMap, snippetChars) => {
    if (window.__reqlore_installed) return;
    window.__reqlore_installed = true;
    window.__reqlore_hits = [];
    window.__reqlore_via_event = '';

    const CANARY = String(canaryArg || '');
    const TAG_ENTRIES = Object.keys(taggedMap || {})
        .filter(k => typeof taggedMap[k] === 'string'
                       && taggedMap[k].length > CANARY.length)
        .map(k => [k, String(taggedMap[k])])
        .sort((a, b) => b[1].length - a[1].length);

    const safeStr = (v) => {
        try { return v == null ? String(v) : String(v); }
        catch (e) { return ''; }
    };
    const truncate = (s) => {
        s = safeStr(s);
        if (s.length <= snippetChars) return s;
        return s.slice(0, snippetChars) + '...';
    };
    const safeDecode = (s) => {
        try { return decodeURIComponent(s); }
        catch (e) { return ''; }
    };
    const overlap = (srcVal, needle) => {
        if (!srcVal || !needle) return false;
        const variants = [srcVal];
        const dec = safeDecode(srcVal);
        if (dec && dec !== srcVal) variants.push(dec);
        const c0 = srcVal.charCodeAt(0);
        if (c0 === 35 || c0 === 63) {  // # or ?
            const tail = srcVal.slice(1);
            if (tail) {
                variants.push(tail);
                const tdec = safeDecode(tail);
                if (tdec && tdec !== tail) variants.push(tdec);
            }
        }
        for (const v of variants) {
            if (!v) continue;
            if (v.indexOf(CANARY) === -1) continue;
            if (v.indexOf(needle) !== -1) return true;
            if (needle.indexOf(v) !== -1) return true;
        }
        return false;
    };

    // Snapshot sources at install time.
    const initial = { hash: '', search: '', pathname: '',
                       referrer: '', name: '' };
    try { initial.hash = location.hash || ''; } catch (e) {}
    try { initial.search = location.search || ''; } catch (e) {}
    try { initial.pathname = location.pathname || ''; } catch (e) {}
    try { initial.referrer = document.referrer || ''; } catch (e) {}
    try { initial.name = window.name || ''; } catch (e) {}

    const MSG_BUF_SIZE = 8;
    const msgBuf = [];

    const detectSource = (value) => {
        const s = safeStr(value);
        if (!s || s.indexOf(CANARY) === -1) return 'unknown';
        // Pass 1: tagged canaries — deterministic.
        if (TAG_ENTRIES.length) {
            const out = [];
            const seen = Object.create(null);
            for (const [sid, tagged] of TAG_ENTRIES) {
                if (!seen[sid] && s.indexOf(tagged) !== -1) {
                    out.push(sid);
                    seen[sid] = true;
                }
            }
            if (out.length) return out.join(',');
        }
        // Pass 2: heuristic overlap.
        const live = {};
        try { live.hash = location.hash || ''; } catch (e) { live.hash = ''; }
        try { live.search = location.search || ''; } catch (e) { live.search = ''; }
        try { live.path = location.pathname || ''; } catch (e) { live.path = ''; }
        try { live.ref = document.referrer || ''; } catch (e) { live.ref = ''; }
        try { live.name = window.name || ''; } catch (e) { live.name = ''; }
        try { live.cookie = document.cookie || ''; } catch (e) { live.cookie = ''; }
        const cands = [
            ['location.hash', live.hash], ['location.hash', initial.hash],
        ];
        for (let i = msgBuf.length - 1; i >= 0; i--) {
            cands.push(['postMessage', msgBuf[i]]);
        }
        cands.push(
            ['window.name', live.name], ['window.name', initial.name],
            ['document.referrer', live.ref],
            ['document.referrer', initial.referrer],
            ['location.search', live.search],
            ['location.search', initial.search],
            ['document.cookie', live.cookie],
            ['location.pathname', live.path],
            ['location.pathname', initial.pathname]
        );
        const out = [];
        const seen = Object.create(null);
        for (const [id, content] of cands) {
            if (seen[id]) continue;
            if (overlap(content, s)) {
                out.push(id);
                seen[id] = true;
            }
        }
        if (out.length === 0) {
            try {
                const ls = window.localStorage;
                if (ls) {
                    const n = Math.min(ls.length, 200);
                    for (let i = 0; i < n; i++) {
                        const v = ls.getItem(ls.key(i)) || '';
                        if (overlap(v, s)) { out.push('localStorage'); break; }
                    }
                }
            } catch (e) {}
            try {
                const ss = window.sessionStorage;
                if (ss) {
                    const n = Math.min(ss.length, 200);
                    for (let i = 0; i < n; i++) {
                        const v = ss.getItem(ss.key(i)) || '';
                        if (overlap(v, s)) { out.push('sessionStorage'); break; }
                    }
                }
            } catch (e) {}
        }
        return out.length ? out.join(',') : 'unknown';
    };

    const record = (sink, value) => {
        try {
            const s = safeStr(value);
            if (s.indexOf(CANARY) === -1) return;
            window.__reqlore_hits.push({
                sink: sink,
                source: detectSource(s),
                canary: CANARY,
                snippet: truncate(s),
                via_event: window.__reqlore_via_event || '',
                page_url: (typeof location !== 'undefined'
                            && location.href) || ''
            });
        } catch (e) {}
    };

    const wrapSetter = (proto, prop, sinkName) => {
        try {
            const d = Object.getOwnPropertyDescriptor(proto, prop);
            if (!d || !d.set || !d.configurable) return;
            const orig = d.set;
            Object.defineProperty(proto, prop, {
                configurable: true,
                enumerable: d.enumerable,
                get: d.get,
                set: function(v) {
                    record(sinkName, v);
                    return orig.call(this, v);
                }
            });
        } catch (e) {}
    };
    const wrapMethod = (obj, name, sinkName, argIndex) => {
        try {
            const orig = obj[name];
            if (typeof orig !== 'function') return;
            Object.defineProperty(obj, name, {
                configurable: true, writable: true, enumerable: false,
                value: function() {
                    try {
                        const v = arguments[argIndex || 0];
                        const s = safeStr(v);
                        if (s.indexOf(CANARY) !== -1) {
                            if (sinkName === 'Element.setAttribute(on*)') {
                                const attr = String(arguments[0] || '').toLowerCase();
                                if (attr.indexOf('on') === 0) {
                                    record(sinkName, s);
                                }
                            } else {
                                record(sinkName, s);
                            }
                        }
                    } catch (e) {}
                    return orig.apply(this, arguments);
                }
            });
        } catch (e) {}
    };

    // Canonical DOM Hunter sink set.
    wrapSetter(Element.prototype, 'innerHTML', 'Element.innerHTML');
    wrapSetter(Element.prototype, 'outerHTML', 'Element.outerHTML');
    if (typeof HTMLScriptElement !== 'undefined') {
        wrapSetter(HTMLScriptElement.prototype, 'src',
                    'HTMLScriptElement.src');
    }
    if (typeof HTMLIFrameElement !== 'undefined') {
        wrapSetter(HTMLIFrameElement.prototype, 'src',
                    'HTMLIFrameElement.src');
        wrapSetter(HTMLIFrameElement.prototype, 'srcdoc',
                    'HTMLIFrameElement.srcdoc');
    }
    wrapMethod(Element.prototype, 'insertAdjacentHTML',
                'Element.insertAdjacentHTML', 1);
    wrapMethod(Element.prototype, 'setAttribute',
                'Element.setAttribute(on*)', 1);
    wrapMethod(document, 'write', 'document.write', 0);
    wrapMethod(document, 'writeln', 'document.writeln', 0);

    if (typeof DOMParser !== 'undefined' && DOMParser.prototype) {
        wrapMethod(DOMParser.prototype, 'parseFromString',
                    'DOMParser.parseFromString', 0);
    }
    if (typeof Range !== 'undefined' && Range.prototype) {
        wrapMethod(Range.prototype, 'createContextualFragment',
                    'Range.createContextualFragment', 0);
    }
    try {
        const OrigWorker = window.Worker;
        if (typeof OrigWorker === 'function') {
            function _W(url, opts) {
                try {
                    const s = safeStr(url);
                    if (s.indexOf(CANARY) !== -1) record('Worker', s);
                } catch (e) {}
                return new OrigWorker(url, opts);
            }
            _W.prototype = OrigWorker.prototype;
            window.Worker = _W;
        }
    } catch (e) {}

    try {
        const origEval = window.eval;
        Object.defineProperty(window, 'eval', {
            configurable: true, writable: true,
            value: function(code) {
                try {
                    const s = safeStr(code);
                    if (s.indexOf(CANARY) !== -1) record('eval', s);
                } catch (e) {}
                return origEval.call(this, code);
            }
        });
    } catch (e) {}

    try {
        const OrigFunc = window.Function;
        function _F() {
            try {
                for (const a of arguments) {
                    const s = safeStr(a);
                    if (s.indexOf(CANARY) !== -1) {
                        record('Function', s);
                        break;
                    }
                }
            } catch (e) {}
            return OrigFunc.apply(this, arguments);
        }
        _F.prototype = OrigFunc.prototype;
        window.Function = _F;
    } catch (e) {}

    try {
        const orig = window.setTimeout;
        window.setTimeout = function(handler) {
            try {
                if (typeof handler === 'string'
                        && handler.indexOf(CANARY) !== -1) {
                    record('setTimeout(string)', handler);
                }
            } catch (e) {}
            return orig.apply(this, arguments);
        };
        const orig2 = window.setInterval;
        window.setInterval = function(handler) {
            try {
                if (typeof handler === 'string'
                        && handler.indexOf(CANARY) !== -1) {
                    record('setInterval(string)', handler);
                }
            } catch (e) {}
            return orig2.apply(this, arguments);
        };
    } catch (e) {}

    // location.href setter.
    try {
        const LocProto = (typeof Location !== 'undefined')
                          ? Location.prototype : null;
        if (LocProto) {
            const d = Object.getOwnPropertyDescriptor(LocProto, 'href');
            if (d && d.set && d.configurable) {
                const orig = d.set;
                Object.defineProperty(LocProto, 'href', {
                    configurable: true, enumerable: d.enumerable,
                    get: d.get,
                    set: function(v) {
                        record('location.href', v);
                        return orig.call(this, v);
                    }
                });
            }
        }
    } catch (e) {}

    // postMessage observer — feeds detectSource's attribution buffer.
    try {
        window.addEventListener('message', function(ev) {
            try {
                const s = safeStr(ev && ev.data);
                if (s && s.indexOf(CANARY) !== -1) {
                    if (msgBuf.indexOf(s) === -1) {
                        msgBuf.push(s);
                        if (msgBuf.length > MSG_BUF_SIZE) msgBuf.shift();
                    }
                }
            } catch (e) {}
        }, true);
    } catch (e) {}

    // MutationObserver — catch DOM insertions via paths we didn't wrap.
    // Restricted to Element nodes; Text-only insertions can't execute.
    try {
        const observer = new MutationObserver((muts) => {
            for (const m of muts) {
                if (m.type === 'childList') {
                    for (const n of m.addedNodes) {
                        if (!n || n.nodeType !== 1) continue;
                        const text = n.outerHTML || '';
                        if (text && text.indexOf(CANARY) !== -1) {
                            window.__reqlore_hits.push({
                                sink: 'dom-mutation',
                                source: detectSource(text),
                                canary: CANARY,
                                snippet: truncate(text),
                                via_event: window.__reqlore_via_event || '',
                                page_url: (typeof location !== 'undefined'
                                            && location.href) || ''
                            });
                        }
                    }
                }
            }
        });
        observer.observe(document.documentElement || document, {
            childList: true, subtree: true
        });
        window.__reqlore_observer = observer;
    } catch (e) {}
}
"""


_DRIVE_EVENTS_JS = r"""
(maxEvents) => {
    const selectors = [
        'a[href]', 'button', '[onclick]', '[role="button"]',
        '[role="link"]', 'input[type="button"]', 'input[type="submit"]'
    ];
    const seen = new Set();
    const targets = [];
    for (const sel of selectors) {
        for (const el of document.querySelectorAll(sel)) {
            if (seen.has(el)) continue;
            seen.add(el);
            targets.push(el);
            if (targets.length >= maxEvents) break;
        }
        if (targets.length >= maxEvents) break;
    }
    let counter = 0;
    for (const el of targets) {
        for (const evt of ['click', 'mouseover']) {
            window.__reqlore_via_event = evt;
            try {
                const ev = new Event(evt, { bubbles: true, cancelable: true });
                el.dispatchEvent(ev);
            } catch (e) {}
            counter++;
        }
    }
    window.__reqlore_via_event = '';
    return counter;
}
"""


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------

def analyze_dynamic(
    url: str,
    *,
    canary: str | None = None,
    sources: dict[str, str] | None = None,
    options: DynamicOptions | None = None,
) -> list[DOMHit]:
    """Drive a headless browser at ``url`` with tagged canaries injected
    into supported DOM sources, and return canonical-id sinks the
    canary reached.

    Parameters
    ----------
    url
        Absolute URL to navigate to.
    canary
        Base canary string. Each injectable source receives the per-
        source tagged variant (``canary + "-" + tag``) so source
        attribution is provable at sink-fire time. When omitted a
        fresh 16-hex canary is generated.
    sources
        Optional override — ``{source_id: value}`` map. When omitted,
        all injectable sources receive their tagged variant of
        ``canary``.
    options
        Tuning knobs.

    Returns
    -------
    list[DOMHit]
        Possibly empty. ``[]`` if Playwright is not installed.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return []
    opts = options or DynamicOptions()
    explicit_sources = sources is not None
    if not canary and not explicit_sources:
        canary = "RQLDYN" + secrets.token_hex(5)
    if sources is None:
        sources = tagged_canaries(canary or "RQLDYN")
    sources = {k: v for k, v in sources.items() if k in _INJECTABLE_SOURCES}
    if not sources:
        return []
    if not canary:
        # Search-needle = longest common prefix of injected values, so any
        # of them firing into a sink trips the detector. Falls back to the
        # first value when there's no common prefix.
        values = list(sources.values())
        from os.path import commonprefix as _cp
        prefix = _cp(values)
        canary = prefix if len(prefix) >= 4 else values[0]

    deadline = time.monotonic() + max(opts.budget_s, 0.5)

    nav_url = url
    if "location.hash" in sources:
        sep = "" if "#" in nav_url else "#"
        nav_url = nav_url + sep + sources["location.hash"]
    if "location.search" in sources:
        sep = "&" if "?" in nav_url else "?"
        nav_url = nav_url + sep + "rqlc=" + sources["location.search"]

    try:
        from playwright.sync_api import sync_playwright  # local import
    except ImportError:  # pragma: no cover
        return []

    try:
        pw_ctx = sync_playwright().start()
    except Exception:                                       # noqa: BLE001
        return []
    try:
        try:
            browser = pw_ctx.chromium.launch(headless=opts.headless)
        except Exception:                                   # noqa: BLE001
            return []
        try:
            context = browser.new_context()

            init_args = [canary, sources, int(opts.snippet_chars)]
            try:
                context.add_init_script(
                    _INSTRUMENTATION_JS, arg=init_args,
                )
            except TypeError:
                literal = (
                    "(" + _INSTRUMENTATION_JS + ")("
                    + _js_literal(canary) + ", "
                    + _js_literal(sources) + ", "
                    + str(int(opts.snippet_chars)) + ");"
                )
                context.add_init_script(literal)

            page = context.new_page()
            try:
                if "window.name" in sources:
                    page.evaluate(
                        "(c) => { window.name = c; }",
                        sources["window.name"],
                    )

                referrer_canary = sources.get("document.referrer", "")
                goto_kwargs: dict[str, Any] = {
                    "timeout": opts.nav_timeout_ms,
                    "wait_until": "load",
                }
                if opts.inject_referrer and referrer_canary:
                    goto_kwargs["referer"] = (
                        "http://reqlore.invalid/?r=" + referrer_canary
                    )
                try:
                    page.goto(nav_url, **goto_kwargs)
                except Exception:                           # noqa: BLE001
                    return _collect_hits(page, canary)

                if "postMessage" in sources:
                    with contextlib.suppress(Exception):
                        page.evaluate(
                            "(c) => { window.postMessage(c, '*'); }",
                            sources["postMessage"],
                        )

                with contextlib.suppress(Exception):
                    page.wait_for_timeout(opts.settle_ms)

                if time.monotonic() > deadline:
                    return _collect_hits(page, canary)

                if opts.drive_events:
                    try:
                        page.evaluate(
                            _DRIVE_EVENTS_JS, int(opts.max_events),
                        )
                        page.wait_for_timeout(opts.settle_ms)
                    except Exception:                       # noqa: BLE001,S110  # Playwright evaluate raises arbitrary JS/browser errors; event-driving is best-effort, hits are collected regardless
                        pass

                return _collect_hits(page, canary)
            finally:
                with contextlib.suppress(Exception):
                    page.close()
        finally:
            with contextlib.suppress(Exception):
                browser.close()
    finally:
        with contextlib.suppress(Exception):
            pw_ctx.stop()


def _collect_hits(page: Any, canary: str) -> list[DOMHit]:
    """Pull ``window.__reqlore_hits``, map sink ids to the canonical
    catalogue, attach severity, and dedup."""
    try:
        raw = page.evaluate("() => window.__reqlore_hits || []")
    except Exception:                                       # noqa: BLE001
        return []
    if not isinstance(raw, list):
        return []
    out: list[DOMHit] = []
    seen: set[tuple[str, str, str]] = set()
    for rec in raw:
        if not isinstance(rec, dict):
            continue
        sink = str(rec.get("sink") or "")
        source = str(rec.get("source") or "")
        if not sink or not source:
            continue
        snippet = str(rec.get("snippet") or "")
        via = str(rec.get("via_event") or "")
        page_url = str(rec.get("page_url") or "")
        meta = SINK_INDEX.get(sink)
        severity = normalise_severity(meta["severity"] if meta else "medium")
        key = (sink, source, via)
        if key in seen:
            continue
        seen.add(key)
        out.append(DOMHit(
            sink=sink, source_label=source, canary=canary,
            severity=severity, snippet=snippet, via_event=via,
            page_url=page_url, canary_seen=True,
        ))
    return out


# ---------------------------------------------------------------------------
# Cross-confirm Phase 7 static findings.
# ---------------------------------------------------------------------------

# Map static-analyser sink labels (Phase 7 evidence text) onto the
# canonical DOM Hunter sink id set.
_STATIC_TO_HUNTER_SINKS: tuple[tuple[str, frozenset[str]], ...] = (
    ("innerHTML",         frozenset({"Element.innerHTML", "dom-mutation"})),
    ("outerHTML",         frozenset({"Element.outerHTML", "dom-mutation"})),
    ("document.writeln",  frozenset({"document.writeln"})),
    ("document.write",    frozenset({"document.write"})),
    ("eval",              frozenset({"eval"})),
    ("Function",          frozenset({"Function"})),
    ("setTimeout",        frozenset({"setTimeout(string)"})),
    ("setInterval",       frozenset({"setInterval(string)"})),
    ("insertAdjacentHTML", frozenset({"Element.insertAdjacentHTML"})),
    ("location.assign",   frozenset({"location.href"})),
    ("location.replace",  frozenset({"location.href"})),
    ("srcdoc",            frozenset({"HTMLIFrameElement.srcdoc"})),
)


def _runtime_sink_matches(static_sink_text: str, runtime_sink: str) -> bool:
    """True when a static-finding sink label maps to a runtime sink."""
    txt = static_sink_text.lower()
    if txt.startswith("setattribute"):
        return runtime_sink == "Element.setAttribute(on*)"
    for key, runtime_names in _STATIC_TO_HUNTER_SINKS:
        if key.lower() in txt and runtime_sink in runtime_names:
            return True
    return False


def _source_matches(static_source: str, runtime_source: str) -> bool:
    """True iff ``runtime_source`` (possibly comma-list) contains the
    static label."""
    if not runtime_source:
        return False
    if runtime_source == static_source:
        return True
    return static_source in runtime_source.split(",")


def cross_confirm_findings(
    static_findings: list[Finding],
    dynamic_hits: list[DOMHit],
) -> list[Finding]:
    """Return new findings with ``confidence="certain"`` when a runtime
    hit confirms a static source→sink flow. Idempotent; never mutates
    input."""
    from dataclasses import replace
    out: list[Finding] = []
    for f in static_findings:
        ev = f.evidence or ""
        src_part, _, sink_part = ev.partition(" -> ")
        src_label = src_part.split(" (line ")[0].strip()
        sink_label = sink_part.split(" (line ")[0].strip()
        promoted = any(
            _source_matches(src_label, h.source_label)
            and _runtime_sink_matches(sink_label, h.sink)
            for h in dynamic_hits
        )
        if promoted:
            new_evidence = ev
            if "[runtime confirmed]" not in new_evidence:
                new_evidence = new_evidence + " [runtime confirmed]"
            out.append(replace(f, confidence="certain",
                                evidence=new_evidence))
        else:
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Persistence — drop hits into the DOM Hunter store.
# ---------------------------------------------------------------------------

def persist_hits(storage: Any, hits: list[DOMHit]) -> list[int]:
    """Write each :class:`DOMHit` into the ``dom_hunter_findings`` table
    using the same dedup key the extension uses.

    Returns row ids (0 when a per-row insert failed). Safe to call with
    an empty list. Per-row failures are swallowed so a single bad row
    doesn't poison the batch.
    """
    if not hits or storage is None:
        return []
    ids: list[int] = []
    for h in hits:
        try:
            dk = dedupe_key(
                sink=h.sink, source=h.source_label,
                page_url=h.page_url,
                stack=("via_event=" + h.via_event) if h.via_event else "",
                canary_seen=h.canary_seen,
            )
            rid = storage.add_dom_hunter_finding(
                page_url=h.page_url, frame_url=h.page_url,
                sink=h.sink, source=h.source_label,
                severity=h.severity, canary_seen=h.canary_seen,
                value=h.snippet,
                stack=("via_event=" + h.via_event) if h.via_event else "",
                dedupe_key=dk,
            )
            ids.append(int(rid or 0))
        except Exception:                                   # noqa: BLE001
            ids.append(0)
    return ids


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _js_literal(value: Any) -> str:
    """Small, safe Python→JS literal renderer (string/bool/None/numeric/
    list/dict)."""
    if isinstance(value, str):
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_js_literal(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            _js_literal(str(k)) + ":" + _js_literal(v)
            for k, v in value.items()
        ) + "}"
    return "null"


SINKS = _dh.SINKS
SOURCES = _dh.SOURCES


__all__ = [
    "DOMHit",
    "DynamicOptions",
    "analyze_dynamic",
    "cross_confirm_findings",
    "persist_hits",
    "SINKS",
    "SOURCES",
]
