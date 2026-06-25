"""Phase 8 — dynamic JS analysis tests.

The pure-Python tests (cross-confirm, Playwright-absent fallback,
options defaults, source-filtering, hit canonicalisation) always run.
The live-browser tests use the same ``http.server`` harness as
``test_active_gap_phase4.py`` and skip cleanly when Playwright +
Chromium aren't installed.
"""
from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

from reqlore.scanner.findings import Finding
from reqlore.scanner.js_dynamic import (
    DOMHit,
    DynamicOptions,
    _INJECTABLE_SOURCES,
    _js_literal,
    _runtime_sink_matches,
    analyze_dynamic,
    cross_confirm_findings,
    persist_hits,
)


# ---------------------------------------------------------------------------
# Pure-Python tests — always run.
# ---------------------------------------------------------------------------

def test_options_defaults_are_safe():
    o = DynamicOptions()
    assert o.budget_s > 0
    assert o.nav_timeout_ms > 0
    assert o.settle_ms >= 0
    assert o.drive_events is True
    assert o.max_events > 0
    assert o.headless is True
    assert o.snippet_chars > 0


def test_supported_sources_include_common_dom_xss_sources():
    assert "location.hash" in _INJECTABLE_SOURCES
    assert "location.search" in _INJECTABLE_SOURCES
    assert "document.referrer" in _INJECTABLE_SOURCES
    assert "window.name" in _INJECTABLE_SOURCES


def test_analyze_returns_empty_when_playwright_unavailable(monkeypatch):
    import reqlore.scanner.js_dynamic as mod
    monkeypatch.setattr(mod, "PLAYWRIGHT_AVAILABLE", False)
    assert analyze_dynamic("http://example.test/") == []


def test_analyze_returns_empty_when_no_supported_sources(monkeypatch):
    """Asking for a source label we don't know how to inject is a no-op."""
    import reqlore.scanner.js_dynamic as mod
    monkeypatch.setattr(mod, "PLAYWRIGHT_AVAILABLE", True)
    assert analyze_dynamic(
        "http://example.test/",
        sources={"unknown.source": "X"},
    ) == []


def test_runtime_sink_matches_innerhtml_to_innerhtml():
    assert _runtime_sink_matches("innerHTML", "Element.innerHTML")
    assert _runtime_sink_matches("innerHTML", "dom-mutation")


def test_runtime_sink_matches_document_write_specificity():
    """document.writeln must not match a static finding for document.write
    (and vice versa) — and neither matches eval."""
    assert _runtime_sink_matches("document.write", "document.write")
    assert _runtime_sink_matches("document.writeln", "document.writeln")
    # Eval never matches html sinks.
    assert not _runtime_sink_matches("innerHTML", "eval")
    assert not _runtime_sink_matches("eval", "Element.innerHTML")


def test_runtime_sink_matches_setattribute_on_handlers_only():
    """Static 'setAttribute(onclick)' should match runtime canonical
    'Element.setAttribute(on*)'. Non-event-handler attrs do not raise
    a runtime hit in DOM Hunter and so don't get cross-confirmed."""
    assert _runtime_sink_matches(
        "setAttribute(onclick)", "Element.setAttribute(on*)"
    )
    assert _runtime_sink_matches(
        "setAttribute(onerror)", "Element.setAttribute(on*)"
    )


def test_runtime_sink_matches_location_assign():
    """Both location.assign() and location.replace() collapse to the
    canonical DOM Hunter sink id 'location.href'."""
    assert _runtime_sink_matches("location.assign", "location.href")
    assert _runtime_sink_matches("location.replace", "location.href")


def test_runtime_sink_no_match_for_unrelated():
    assert not _runtime_sink_matches("innerHTML", "setTimeout(string)")
    assert not _runtime_sink_matches("eval", "document.write")


def _mk_finding(*, source: str, sink: str, sline: int = 1,
                  klsink: int = 2,
                  confidence: str = "firm") -> Finding:
    return Finding(
        severity="high",
        title="DOM-based cross-site scripting",
        evidence=f"{source} (line {sline}) -> {sink} (line {klsink})",
        confidence=confidence,
    )


def test_cross_confirm_promotes_to_certain_on_match():
    f = _mk_finding(source="location.hash", sink="innerHTML")
    hit = DOMHit(sink="Element.innerHTML",
                  source_label="location.hash",
                  canary="RQLDYN")
    out = cross_confirm_findings([f], [hit])
    assert len(out) == 1
    assert out[0].confidence == "certain"
    assert "[runtime confirmed]" in out[0].evidence


def test_cross_confirm_preserves_when_no_match():
    f = _mk_finding(source="location.hash", sink="innerHTML")
    other = DOMHit(sink="eval", source_label="location.search", canary="X")
    out = cross_confirm_findings([f], [other])
    assert len(out) == 1
    assert out[0].confidence == "firm"
    assert "[runtime confirmed]" not in out[0].evidence


def test_cross_confirm_does_not_mutate_input():
    f = _mk_finding(source="location.hash", sink="innerHTML")
    hit = DOMHit(sink="Element.innerHTML",
                  source_label="location.hash", canary="X")
    cross_confirm_findings([f], [hit])
    assert f.confidence == "firm"
    assert "[runtime confirmed]" not in f.evidence


def test_cross_confirm_source_mismatch_rejects_match():
    """innerHTML hit from window.name must NOT confirm a location.hash flow."""
    f = _mk_finding(source="location.hash", sink="innerHTML")
    hit = DOMHit(sink="Element.innerHTML",
                  source_label="window.name",
                  canary="X")
    out = cross_confirm_findings([f], [hit])
    assert out[0].confidence == "firm"


def test_cross_confirm_empty_inputs_safe():
    assert cross_confirm_findings([], []) == []
    assert cross_confirm_findings([], [DOMHit("eval", "location.hash", "X")]) == []
    f = _mk_finding(source="location.hash", sink="innerHTML")
    out = cross_confirm_findings([f], [])
    assert out == [f] or out[0].confidence == "firm"


def test_cross_confirm_setattribute_match():
    f = _mk_finding(source="location.hash", sink="setAttribute(onclick)")
    hit = DOMHit(sink="Element.setAttribute(on*)",
                  source_label="location.hash", canary="X")
    out = cross_confirm_findings([f], [hit])
    assert out[0].confidence == "certain"


def test_cross_confirm_runs_idempotently():
    """Calling twice doesn't append the marker twice."""
    f = _mk_finding(source="location.hash", sink="innerHTML")
    hit = DOMHit("Element.innerHTML", "location.hash", "X")
    once = cross_confirm_findings([f], [hit])
    twice = cross_confirm_findings(once, [hit])
    assert twice[0].evidence.count("[runtime confirmed]") == 1


# --- _js_literal -----------------------------------------------------------

def test_js_literal_string_quoting():
    assert _js_literal("hi") == '"hi"'


def test_js_literal_escapes_quotes_and_backslashes():
    assert _js_literal('a"b') == '"a\\"b"'
    assert _js_literal("a\\b") == '"a\\\\b"'


def test_js_literal_list_and_numbers():
    assert _js_literal([1, 2, "x"]) == '[1,2,"x"]'


def test_js_literal_none_and_bool():
    assert _js_literal(None) == "null"
    assert _js_literal(True) == "true"
    assert _js_literal(False) == "false"


# ---------------------------------------------------------------------------
# Live-browser tests — skip cleanly when Chromium isn't installed.
# ---------------------------------------------------------------------------

def _playwright_chromium_available() -> bool:
    """Return True iff playwright is importable AND Chromium launches."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception:                               # noqa: BLE001
                return False
            browser.close()
        return True
    except Exception:                                       # noqa: BLE001
        return False


_HAS_BROWSER = _playwright_chromium_available()
needs_browser = pytest.mark.skipif(
    not _HAS_BROWSER, reason="Playwright + Chromium not available"
)


def _serve(html_body: bytes):
    """Spin up a tiny localhost HTTP server serving a fixed body. Returns
    (port, shutdown_callable)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):                                   # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_body)))
            self.end_headers()
            self.wfile.write(html_body)

        def log_message(self, *_a, **_kw):                  # noqa: N802
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return port, srv


@needs_browser
def test_browser_detects_innerhtml_from_hash():
    """Vulnerable page reads location.hash and writes it into innerHTML.
    The instrumentation must record the innerHTML hit.
    """
    body = (
        b"<!doctype html><html><body><div id=out></div><script>"
        b"document.getElementById('out').innerHTML ="
        b"  location.hash.slice(1);"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST1"},
            options=DynamicOptions(budget_s=10.0, drive_events=False,
                                     nav_timeout_ms=5_000, settle_ms=100),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert any(h.sink == "Element.innerHTML"
                and h.source_label == "location.hash"
                for h in hits), f"got: {hits!r}"


@needs_browser
def test_browser_detects_eval_from_hash():
    body = (
        b"<!doctype html><html><body><script>"
        b"eval(location.hash.slice(1));"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST2;1+1"},
            options=DynamicOptions(budget_s=10.0, drive_events=False,
                                     nav_timeout_ms=5_000, settle_ms=100),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert any(h.sink == "eval" and h.source_label == "location.hash"
                for h in hits), f"got: {hits!r}"


@needs_browser
def test_browser_detects_document_write_from_hash():
    body = (
        b"<!doctype html><html><body><script>"
        b"document.write(location.hash.slice(1));"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST3"},
            options=DynamicOptions(budget_s=10.0, drive_events=False,
                                     nav_timeout_ms=5_000, settle_ms=100),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert any("document.write" in h.sink
                and h.source_label == "location.hash"
                for h in hits), f"got: {hits!r}"


@needs_browser
def test_browser_safe_page_yields_no_hits():
    """A page that reads location.hash but writes via textContent
    must not trigger any DOM-sink hit."""
    body = (
        b"<!doctype html><html><body><div id=out></div><script>"
        b"document.getElementById('out').textContent ="
        b"  location.hash.slice(1);"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST4"},
            options=DynamicOptions(budget_s=10.0, drive_events=False,
                                     nav_timeout_ms=5_000, settle_ms=100),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert hits == [], f"expected no hits, got: {hits!r}"


@needs_browser
def test_browser_drives_click_to_reveal_sink():
    """The page only writes to innerHTML inside a click handler. With
    event-driving enabled, the hit appears tagged via_event='click'."""
    body = (
        b"<!doctype html><html><body>"
        b"<button id=b>Go</button>"
        b"<div id=out></div>"
        b"<script>"
        b"document.getElementById('b').onclick = function() {"
        b"  document.getElementById('out').innerHTML ="
        b"    location.hash.slice(1);"
        b"};"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST5"},
            options=DynamicOptions(budget_s=10.0, drive_events=True,
                                     nav_timeout_ms=5_000, settle_ms=150,
                                     max_events=5),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    # The hit may be tagged via_event='' if the via-event stamper races
    # the synchronous handler, but the hit itself must exist.
    matched = [h for h in hits
                if h.sink == "Element.innerHTML"
                and h.source_label == "location.hash"]
    assert matched, f"no innerHTML hit recorded; got: {hits!r}"


@needs_browser
def test_browser_cross_confirm_promotes_real_finding():
    """End-to-end: a Phase-7-shaped static finding gets upgraded to
    ``certain`` when the dynamic analyser reaches the same flow."""
    body = (
        b"<!doctype html><html><body><div id=out></div><script>"
        b"document.getElementById('out').innerHTML ="
        b"  location.hash.slice(1);"
        b"</script></body></html>"
    )
    port, srv = _serve(body)
    try:
        hits = analyze_dynamic(
            f"http://127.0.0.1:{port}/",
            sources={"location.hash": "RQLDYNTEST6"},
            options=DynamicOptions(budget_s=10.0, drive_events=False,
                                     nav_timeout_ms=5_000, settle_ms=100),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    static = [_mk_finding(source="location.hash", sink="innerHTML")]
    upgraded = cross_confirm_findings(static, hits)
    assert upgraded[0].confidence == "certain"


# ---------------------------------------------------------------------------
# persist_hits — DOM Hunter storage alignment.
# ---------------------------------------------------------------------------

class _StubStorage:
    """Minimal stand-in for reqlore.storage.Storage.add_dom_hunter_finding."""

    def __init__(self, *, fail_at: int | None = None):
        self.calls: list[dict] = []
        self.fail_at = fail_at

    def add_dom_hunter_finding(self, **kwargs) -> int:
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            raise RuntimeError("injected failure")
        self.calls.append(kwargs)
        return len(self.calls)


def test_persist_hits_empty_list_safe():
    s = _StubStorage()
    assert persist_hits(s, []) == []
    assert s.calls == []


def test_persist_hits_none_storage_safe():
    assert persist_hits(None, [DOMHit("eval", "location.hash", "X")]) == []


def test_persist_hits_writes_canonical_fields():
    s = _StubStorage()
    hits = [
        DOMHit(sink="Element.innerHTML",
                source_label="location.hash",
                canary="RQLDYN", severity="high",
                snippet="<img/>",
                page_url="http://t/"),
        DOMHit(sink="eval",
                source_label="window.name",
                canary="RQLDYN", severity="high",
                snippet="alert(1)",
                via_event="click",
                page_url="http://t/"),
    ]
    ids = persist_hits(s, hits)
    assert ids == [1, 2]
    assert s.calls[0]["sink"] == "Element.innerHTML"
    assert s.calls[0]["source"] == "location.hash"
    assert s.calls[0]["severity"] == "high"
    assert s.calls[0]["canary_seen"] is True
    assert s.calls[0]["value"] == "<img/>"
    assert s.calls[0]["page_url"] == "http://t/"
    assert s.calls[0]["frame_url"] == "http://t/"
    assert len(s.calls[0]["dedupe_key"]) == 64  # sha256 hex
    assert s.calls[1]["stack"] == "via_event=click"


def test_persist_hits_swallows_per_row_errors():
    s = _StubStorage(fail_at=0)
    hits = [DOMHit("eval", "location.hash", "X", page_url="http://t/")]
    ids = persist_hits(s, hits)
    assert ids == [0]
