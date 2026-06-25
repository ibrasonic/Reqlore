"""Phase 13 — JavaScript analysis pipeline integration tests.

Covers ``reqlore.scanner.js_pipeline`` end-to-end:

* Pure helpers (mode normalisation, content-type detection, inline
  script extraction).
* ``run_js_pipeline`` behaviour per mode, with injected analyser
  stubs so the tests don't need ``esprima`` or Playwright installed.
* ``ActiveOptions.js_analysis_mode`` validation.
* Scan-preset wiring (every named preset gets the right mode).
* ``ActiveScanner.run_on_project`` integration — counters,
  findings-bus record, defensive swallow on analyser failure.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from reqlore.scanner.active import ActiveOptions, ActiveScanResult
from reqlore.scanner.findings import Finding
from reqlore.scanner.js_pipeline import (
    DEFAULT_JS_ANALYSIS_MODE,
    JS_ANALYSIS_MODES,
    JSPipelineResult,
    extract_inline_scripts,
    is_html_response,
    is_javascript_response,
    run_js_pipeline,
)
from reqlore.scanner.presets import SCAN_PRESETS, apply_preset


# ---------------------------------------------------------------------------
# Helpers — minimal stand-ins for storage / history rows / DOM hits.
# ---------------------------------------------------------------------------

@dataclass
class _HistoryRow:
    id: int
    host: str
    method: str
    url: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _make_row(*, rid: int = 1,
              ct: str = "application/javascript",
              body: bytes = b"document.body.innerHTML = location.hash;",
              host: str = "x.y",
              url: str = "https://x.y/app.js") -> _HistoryRow:
    req = (b"GET " + url.encode() + b" HTTP/1.1\r\n"
           b"Host: " + host.encode() + b"\r\n\r\n")
    resp = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: " + ct.encode() + b"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
            + body)
    return _HistoryRow(
        id=rid, host=host, method="GET", url=url,
        status=200, req_blob=req, resp_blob=resp,
    )


class _Project:
    """Bare-minimum project stub satisfying ActiveScanner.run_on_project."""

    def __init__(self, rows: list[_HistoryRow]):
        self._rows = rows
        self.findings: list[dict] = []
        self.rule_runs: list[dict] = []

    def list_scope(self):
        return []

    def list_history(self, *, limit: int = 50, host: str | None = None):
        return list(self._rows[:limit])

    def is_suppressed(self, *, rule_id: str = "",
                      host: str = "", url: str = "") -> bool:
        return False

    def add_reproduction(self, **kwargs):
        return "tok"

    def add_finding(self, **kwargs) -> int:
        fid = len(self.findings) + 1
        self.findings.append({"id": fid, **kwargs})
        return fid

    def record_rule_run(self, **kwargs) -> None:
        self.rule_runs.append(kwargs)


# ---------------------------------------------------------------------------
# 1) Mode constants & normalisation.
# ---------------------------------------------------------------------------

class TestModeConstants:

    def test_canonical_set(self) -> None:
        assert JS_ANALYSIS_MODES == (
            "off", "static_only", "static_plus_confirm",
            "static_plus_dynamic",
        )

    def test_default_is_off(self) -> None:
        assert DEFAULT_JS_ANALYSIS_MODE == "off"


# ---------------------------------------------------------------------------
# 2) Content-type detection.
# ---------------------------------------------------------------------------

class TestIsJavaScriptResponse:

    @pytest.mark.parametrize("ct,expected", [
        ("application/javascript", True),
        ("application/javascript; charset=utf-8", True),
        ("text/javascript", True),
        ("application/x-javascript", True),
        ("application/ecmascript", True),
        ("text/ecmascript", True),
        ("APPLICATION/JAVASCRIPT", True),
        ("text/html", False),
        ("application/json", False),
        ("text/plain", False),
        ("image/png", False),
        ("", False),
    ])
    def test_content_type(self, ct: str, expected: bool) -> None:
        headers = [("Content-Type", ct)] if ct else []
        assert is_javascript_response(headers) is expected

    def test_no_content_type_header(self) -> None:
        assert is_javascript_response([("X-Other", "value")]) is False

    def test_empty_headers(self) -> None:
        assert is_javascript_response([]) is False


class TestIsHTMLResponse:

    @pytest.mark.parametrize("ct,expected", [
        ("text/html", True),
        ("text/html; charset=utf-8", True),
        ("application/xhtml+xml", True),
        ("application/javascript", False),
        ("application/json", False),
        ("", False),
    ])
    def test_content_type(self, ct: str, expected: bool) -> None:
        headers = [("Content-Type", ct)] if ct else []
        assert is_html_response(headers) is expected


# ---------------------------------------------------------------------------
# 3) Inline script extraction.
# ---------------------------------------------------------------------------

class TestExtractInlineScripts:

    def test_single_script(self) -> None:
        html = (b"<html><body>"
                b"<script>var x = 1;</script>"
                b"</body></html>")
        out = extract_inline_scripts(html)
        assert out == ["var x = 1;"]

    def test_multiple_scripts(self) -> None:
        html = ("<script>a()</script>foo"
                "<script>b()</script>").encode()
        assert extract_inline_scripts(html) == ["a()", "b()"]

    def test_external_script_skipped(self) -> None:
        html = b'<script src="/app.js"></script>'
        assert extract_inline_scripts(html) == []

    def test_json_island_skipped(self) -> None:
        html = (b'<script type="application/json">{"k": 1}</script>'
                b"<script>real()</script>")
        out = extract_inline_scripts(html)
        assert out == ["real()"]

    def test_template_script_skipped(self) -> None:
        html = (b'<script type="text/template">{{ name }}</script>'
                b"<script>code()</script>")
        out = extract_inline_scripts(html)
        assert out == ["code()"]

    def test_module_script_included(self) -> None:
        html = b'<script type="module">import x from "/x.js"</script>'
        out = extract_inline_scripts(html)
        assert out == ['import x from "/x.js"']

    def test_string_input(self) -> None:
        assert extract_inline_scripts("<script>z()</script>") == ["z()"]

    def test_empty_body_skipped(self) -> None:
        html = b"<script></script><script>x()</script>"
        assert extract_inline_scripts(html) == ["x()"]

    def test_no_scripts(self) -> None:
        assert extract_inline_scripts(b"<p>nothing</p>") == []

    def test_attribute_order_does_not_break_type_detection(self) -> None:
        html = (b'<script id="t" type="application/json">{}</script>'
                b'<script async type="text/javascript">js()</script>')
        out = extract_inline_scripts(html)
        assert out == ["js()"]

    def test_cap_enforced(self) -> None:
        # Build 50 inline scripts; the cap is 32.
        scripts = "".join(
            f"<script>fn{i}()</script>" for i in range(50)
        )
        out = extract_inline_scripts(scripts)
        assert len(out) == 32
        assert out[0] == "fn0()"
        assert out[-1] == "fn31()"

    def test_empty_input(self) -> None:
        assert extract_inline_scripts(b"") == []
        assert extract_inline_scripts("") == []


# ---------------------------------------------------------------------------
# 4) JSPipelineResult defaults.
# ---------------------------------------------------------------------------

class TestJSPipelineResultDefaults:

    def test_defaults(self) -> None:
        r = JSPipelineResult()
        assert r.static_findings == []
        assert r.dynamic_hits == []
        assert r.cross_confirmed_count == 0
        assert r.pages_analysed == 0


# ---------------------------------------------------------------------------
# 5) run_js_pipeline — mode='off'.
# ---------------------------------------------------------------------------

class TestRunJSPipelineOff:

    def test_off_short_circuits(self) -> None:
        called = []
        def stub(*a, **kw):
            called.append(1)
            return []
        r = run_js_pipeline(
            response_body=b"var x = 1;",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/", mode="off",
            static_analyzer=stub, dynamic_analyzer=stub,
        )
        assert isinstance(r, JSPipelineResult)
        assert r.static_findings == []
        assert called == []

    def test_unknown_mode_treated_as_off(self) -> None:
        called = []
        def stub(*a, **kw):
            called.append(1)
            return []
        r = run_js_pipeline(
            response_body=b"x()",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/", mode="lol_bogus",
            static_analyzer=stub,
        )
        assert called == []
        assert r.pages_analysed == 0


# ---------------------------------------------------------------------------
# 6) run_js_pipeline — mode='static_only'.
# ---------------------------------------------------------------------------

def _stub_static(source: str, *, host: str, url: str) -> list[Finding]:
    """Returns one finding per call so we can count invocations."""
    return [Finding(
        severity="high", title="stub", description="",
        host=host, url=url, evidence=f"len={len(source)}",
        confidence="firm",
    )]


class TestRunJSPipelineStaticOnly:

    def test_js_body_calls_static_once(self) -> None:
        r = run_js_pipeline(
            response_body=b"document.body.innerHTML = location.hash;",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/a.js",
            mode="static_only",
            static_analyzer=_stub_static,
        )
        assert len(r.static_findings) == 1
        assert r.pages_analysed == 1
        assert r.dynamic_hits == []
        assert r.cross_confirmed_count == 0

    def test_html_body_calls_static_per_inline_script(self) -> None:
        body = (b"<html><script>a()</script>"
                b"<script>b()</script></html>")
        r = run_js_pipeline(
            response_body=body,
            response_headers=[("Content-Type", "text/html")],
            host="x.y", url="https://x.y/",
            mode="static_only",
            static_analyzer=_stub_static,
        )
        assert len(r.static_findings) == 2
        assert r.pages_analysed == 1

    def test_non_js_content_type_skipped(self) -> None:
        called = []
        def stub(*a, **kw):
            called.append(1)
            return [Finding(severity="info", title="x", description="")]
        r = run_js_pipeline(
            response_body=b"<svg></svg>",
            response_headers=[("Content-Type", "image/svg+xml")],
            host="x.y", url="https://x.y/", mode="static_only",
            static_analyzer=stub,
        )
        assert called == []
        assert r.pages_analysed == 0

    def test_empty_body_skipped(self) -> None:
        called = []
        def stub(*a, **kw):
            called.append(1)
            return [Finding(severity="info", title="x", description="")]
        r = run_js_pipeline(
            response_body=b"",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/", mode="static_only",
            static_analyzer=stub,
        )
        assert called == []
        assert r.pages_analysed == 0

    def test_html_with_no_inline_scripts_yields_nothing(self) -> None:
        called = []
        def stub(*a, **kw):
            called.append(1)
            return [Finding(severity="info", title="x", description="")]
        r = run_js_pipeline(
            response_body=b"<html><p>hi</p></html>",
            response_headers=[("Content-Type", "text/html")],
            host="x.y", url="https://x.y/", mode="static_only",
            static_analyzer=stub,
        )
        assert called == []
        assert r.pages_analysed == 0


# ---------------------------------------------------------------------------
# 7) run_js_pipeline — mode='static_plus_confirm'.
# ---------------------------------------------------------------------------

class TestRunJSPipelineStaticPlusConfirm:

    def test_no_static_findings_skips_dynamic(self) -> None:
        def static_empty(source, *, host, url):
            return []
        called_dyn = []
        def stub_dyn(url, **kw):
            called_dyn.append(url)
            return [object()]
        r = run_js_pipeline(
            response_body=b"safe();",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/a.js",
            mode="static_plus_confirm",
            static_analyzer=static_empty,
            dynamic_analyzer=stub_dyn,
        )
        assert called_dyn == []
        assert r.dynamic_hits == []

    def test_static_findings_trigger_dynamic(self) -> None:
        called_dyn = []
        def stub_dyn(url, **kw):
            called_dyn.append(url)
            return [object(), object()]
        r = run_js_pipeline(
            response_body=b"document.body.innerHTML = location.hash;",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/a.js",
            mode="static_plus_confirm",
            static_analyzer=_stub_static,
            dynamic_analyzer=stub_dyn,
            cross_confirm=lambda f, h: f,
        )
        assert called_dyn == ["https://x.y/a.js"]
        assert len(r.dynamic_hits) == 2

    def test_cross_confirm_promotes_to_certain(self) -> None:
        def static_fn(source, *, host, url):
            return [Finding(
                severity="high", title="dom-xss",
                description="", host=host, url=url,
                evidence="x", confidence="firm",
            )]
        def stub_dyn(url, **kw):
            return [object()]
        def promote(static_findings, dynamic_hits):
            # Simulate cross_confirm_findings: clone and bump.
            out = []
            for f in static_findings:
                f2 = Finding(
                    severity=f.severity, title=f.title,
                    description=f.description,
                    host=f.host, url=f.url, evidence=f.evidence,
                    confidence="certain",
                )
                out.append(f2)
            return out
        r = run_js_pipeline(
            response_body=b"document.body.innerHTML = location.hash;",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/a.js",
            mode="static_plus_confirm",
            static_analyzer=static_fn,
            dynamic_analyzer=stub_dyn,
            cross_confirm=promote,
        )
        assert r.cross_confirmed_count == 1
        assert r.static_findings[0].confidence == "certain"


# ---------------------------------------------------------------------------
# 8) run_js_pipeline — mode='static_plus_dynamic'.
# ---------------------------------------------------------------------------

class TestRunJSPipelineStaticPlusDynamic:

    def test_dynamic_called_even_with_no_static_findings(self) -> None:
        called_dyn = []
        def stub_dyn(url, **kw):
            called_dyn.append(url)
            return []
        def empty_static(source, *, host, url):
            return []
        r = run_js_pipeline(
            response_body=b"benign();",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/a.js",
            mode="static_plus_dynamic",
            static_analyzer=empty_static,
            dynamic_analyzer=stub_dyn,
        )
        assert called_dyn == ["https://x.y/a.js"]
        assert r.dynamic_hits == []
        assert r.pages_analysed == 1


# ---------------------------------------------------------------------------
# 9) Defensive — analyser exceptions never escape.
# ---------------------------------------------------------------------------

class TestRunJSPipelineDefensive:

    def test_static_raises_returns_empty_findings(self) -> None:
        def broken(source, *, host, url):
            raise RuntimeError("boom")
        r = run_js_pipeline(
            response_body=b"x()",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/", mode="static_only",
            static_analyzer=broken,
        )
        assert r.static_findings == []
        assert r.pages_analysed == 1  # we did attempt the call

    def test_dynamic_raises_static_preserved(self) -> None:
        def broken_dyn(url, **kw):
            raise RuntimeError("playwright is unhappy")
        r = run_js_pipeline(
            response_body=b"document.body.innerHTML = location.hash;",
            response_headers=[("Content-Type", "application/javascript")],
            host="x.y", url="https://x.y/", mode="static_plus_dynamic",
            static_analyzer=_stub_static,
            dynamic_analyzer=broken_dyn,
        )
        assert len(r.static_findings) == 1
        assert r.dynamic_hits == []


# ---------------------------------------------------------------------------
# 10) ActiveOptions.js_analysis_mode validation.
# ---------------------------------------------------------------------------

class TestActiveOptionsJSValidation:

    @pytest.mark.parametrize("mode", list(JS_ANALYSIS_MODES))
    def test_accepts_every_canonical_mode(self, mode: str) -> None:
        opts = ActiveOptions(js_analysis_mode=mode)
        assert opts.js_analysis_mode == mode

    def test_rejects_unknown_mode(self) -> None:
        with pytest.raises(ValueError, match="js_analysis_mode"):
            ActiveOptions(js_analysis_mode="aggressive")

    def test_normalises_whitespace_and_case(self) -> None:
        opts = ActiveOptions(js_analysis_mode="  STATIC_ONLY  ")
        assert opts.js_analysis_mode == "static_only"

    def test_default_is_off(self) -> None:
        assert ActiveOptions().js_analysis_mode == "off"


# ---------------------------------------------------------------------------
# 11) Preset wiring — every named preset gets the right mode.
# ---------------------------------------------------------------------------

class TestPresetWiring:

    def test_lightweight_off(self) -> None:
        assert SCAN_PRESETS["lightweight"]["js_analysis_mode"] == "off"

    def test_fast_off(self) -> None:
        assert SCAN_PRESETS["fast"]["js_analysis_mode"] == "off"

    def test_balanced_static_plus_confirm(self) -> None:
        assert SCAN_PRESETS["balanced"]["js_analysis_mode"] == (
            "static_plus_confirm"
        )

    def test_deep_static_plus_dynamic(self) -> None:
        assert SCAN_PRESETS["deep"]["js_analysis_mode"] == (
            "static_plus_dynamic"
        )

    def test_apply_preset_propagates_to_active_options(self) -> None:
        for name, expected in (
            ("lightweight", "off"),
            ("fast", "off"),
            ("balanced", "static_plus_confirm"),
            ("deep", "static_plus_dynamic"),
        ):
            opts = apply_preset(name)
            assert opts.js_analysis_mode == expected, name

    def test_custom_preserves_base(self) -> None:
        base = ActiveOptions(js_analysis_mode="static_only")
        out = apply_preset("custom", base=base)
        assert out.js_analysis_mode == "static_only"


# ---------------------------------------------------------------------------
# 12) Scanner integration — ActiveScanner.run_on_project.
# ---------------------------------------------------------------------------

class TestScannerIntegration:

    def test_off_mode_leaves_counters_at_zero(self) -> None:
        from reqlore.scanner.active import ActiveScanner
        proj = _Project([_make_row()])
        scanner = ActiveScanner(checks=[])
        result = scanner.run_on_project(
            proj, options=ActiveOptions(js_analysis_mode="off"),
        )
        assert result.js_pages_analysed == 0
        assert result.js_static_findings == 0
        assert result.js_dynamic_hits == 0
        assert result.js_cross_confirmed == 0

    def test_static_only_records_finding_and_bumps_counters(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reqlore.scanner.active import ActiveScanner
        from reqlore.scanner import js_pipeline as pkg_mod

        def stub(source, *, host, url):
            return [Finding(
                severity="high", title="stub-dom-xss",
                description="", host=host, url=url,
                evidence="canary", confidence="firm",
            )]
        monkeypatch.setattr(
            pkg_mod, "_default_static_analyzer", stub,
        )
        proj = _Project([_make_row()])
        scanner = ActiveScanner(checks=[])
        result = scanner.run_on_project(
            proj,
            options=ActiveOptions(js_analysis_mode="static_only"),
        )
        assert result.js_pages_analysed == 1
        assert result.js_static_findings == 1
        assert result.findings_added == 1
        assert proj.findings
        f = proj.findings[0]
        assert f["rule_id"] == "js-static:dom-xss"
        assert f["severity"] == "high"
        assert f["title"] == "stub-dom-xss"

    def test_non_js_row_yields_no_pipeline_work(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reqlore.scanner.active import ActiveScanner
        from reqlore.scanner import js_pipeline as pkg_mod

        called = []
        def stub(source, *, host, url):
            called.append(1)
            return []
        monkeypatch.setattr(
            pkg_mod, "_default_static_analyzer", stub,
        )
        proj = _Project([_make_row(ct="image/png", body=b"\x89PNG")])
        scanner = ActiveScanner(checks=[])
        result = scanner.run_on_project(
            proj,
            options=ActiveOptions(js_analysis_mode="static_only"),
        )
        assert called == []
        assert result.js_pages_analysed == 0

    def test_pipeline_exception_does_not_break_scan(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reqlore.scanner.active import ActiveScanner
        from reqlore.scanner import js_pipeline as pkg_mod

        def broken(source, *, host, url):
            raise RuntimeError("kaboom")
        monkeypatch.setattr(
            pkg_mod, "_default_static_analyzer", broken,
        )
        proj = _Project([_make_row()])
        scanner = ActiveScanner(checks=[])
        result = scanner.run_on_project(
            proj,
            options=ActiveOptions(js_analysis_mode="static_only"),
        )
        # Scan completes. Pipeline swallowed the exception and the
        # static analyser returned 0 findings — but the page was
        # still counted as analysed.
        assert result.rows_scanned == 1
        assert result.js_static_findings == 0

    def test_html_row_with_inline_script_records_finding(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reqlore.scanner.active import ActiveScanner
        from reqlore.scanner import js_pipeline as pkg_mod

        def stub(source, *, host, url):
            return [Finding(
                severity="medium", title=f"len={len(source)}",
                description="", host=host, url=url,
                evidence="", confidence="firm",
            )]
        monkeypatch.setattr(
            pkg_mod, "_default_static_analyzer", stub,
        )
        body = (b"<html><body>"
                b"<script>document.body.innerHTML = location.hash;</script>"
                b"</body></html>")
        row = _make_row(ct="text/html", body=body,
                        url="https://x.y/page.html")
        proj = _Project([row])
        scanner = ActiveScanner(checks=[])
        result = scanner.run_on_project(
            proj,
            options=ActiveOptions(js_analysis_mode="static_only"),
        )
        assert result.js_pages_analysed == 1
        assert result.js_static_findings == 1


# ---------------------------------------------------------------------------
# 13) ActiveScanResult counter defaults.
# ---------------------------------------------------------------------------

class TestActiveScanResultDefaults:

    def test_js_counters_default_zero(self) -> None:
        r = ActiveScanResult()
        assert r.js_pages_analysed == 0
        assert r.js_static_findings == 0
        assert r.js_dynamic_hits == 0
        assert r.js_cross_confirmed == 0
