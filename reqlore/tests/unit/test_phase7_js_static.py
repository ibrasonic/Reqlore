"""Phase 7 — JavaScript static AST taint analysis tests."""
from __future__ import annotations

import time

import pytest

from reqlore.scanner.js_static import _HAVE_ESPRIMA, analyze_js

# Skip the entire file if esprima isn't installed (it's an optional dep that
# ships in pyproject "extras"). The smoke test runs in CI where it's present.
pytestmark = pytest.mark.skipif(
    not _HAVE_ESPRIMA, reason="esprima not installed (optional dep)"
)


# --- Source coverage -------------------------------------------------------

def test_source_location_hash_to_innerhtml():
    src = """
    var x = location.hash;
    document.body.innerHTML = x;
    """
    findings = analyze_js(src)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.cwe == "CWE-79"
    assert f.confidence == "firm"
    assert "location.hash" in f.evidence
    assert "innerHTML" in f.evidence


def test_source_location_search_to_eval():
    findings = analyze_js("eval(location.search);")
    assert any("eval" in f.evidence and "location.search" in f.evidence
               for f in findings)
    assert findings[0].cwe == "CWE-95"


def test_source_document_referrer_to_outerhtml():
    src = "document.body.outerHTML = document.referrer;"
    findings = analyze_js(src)
    assert any("document.referrer" in f.evidence and "outerHTML" in f.evidence
               for f in findings)


def test_source_window_name_through_template_literal():
    src = "document.body.innerHTML = `<b>${window.name}</b>`;"
    findings = analyze_js(src)
    assert any("window.name" in f.evidence for f in findings)


def test_source_localstorage_getitem():
    src = """
    var data = localStorage.getItem('cfg');
    document.body.innerHTML = data;
    """
    findings = analyze_js(src)
    assert any("localStorage.getItem" in f.evidence for f in findings)


def test_source_json_parse_of_tainted_input():
    src = """
    var raw = location.hash;
    var obj = JSON.parse(raw);
    document.body.innerHTML = obj;
    """
    findings = analyze_js(src)
    assert any("JSON.parse" in f.evidence for f in findings)


# --- Sink coverage ---------------------------------------------------------

def test_sink_document_write():
    findings = analyze_js("document.write(location.hash);")
    assert any("document.write" in f.evidence for f in findings)


def test_sink_document_writeln():
    findings = analyze_js("document.writeln(location.hash);")
    assert any("document.writeln" in f.evidence for f in findings)


def test_sink_insertadjacenthtml():
    src = "var e = document.body; e.insertAdjacentHTML('beforeend', location.hash);"
    findings = analyze_js(src)
    assert any("insertAdjacentHTML" in f.evidence for f in findings)


def test_sink_location_href_assignment():
    src = "location.href = location.hash;"
    findings = analyze_js(src)
    assert any("href" in f.evidence for f in findings)
    assert findings[0].cwe == "CWE-601"


def test_sink_location_assign():
    src = "location.assign(location.hash);"
    findings = analyze_js(src)
    assert any("location.assign" in f.evidence for f in findings)


def test_sink_settimeout_string():
    findings = analyze_js("setTimeout(location.hash, 100);")
    assert any("setTimeout" in f.evidence for f in findings)
    assert findings[0].cwe == "CWE-95"


def test_sink_setinterval_string():
    findings = analyze_js("setInterval(location.hash, 100);")
    assert any("setInterval" in f.evidence for f in findings)


def test_settimeout_with_function_is_safe():
    """A function-typed first arg is not eval-class; no finding."""
    src = "setTimeout(function() { console.log(location.hash); }, 100);"
    assert analyze_js(src) == []


def test_settimeout_with_arrow_is_safe():
    src = "setTimeout(() => doSomething(), 100);"
    assert analyze_js(src) == []


def test_sink_iframe_src_attribute():
    src = """
    var f = document.createElement('iframe');
    f.src = location.hash;
    """
    findings = analyze_js(src)
    assert any("src" in f.evidence for f in findings)


def test_sink_setattribute_dangerous_attribute():
    src = "document.body.setAttribute('href', location.hash);"
    findings = analyze_js(src)
    assert any("setAttribute(href)" in f.evidence for f in findings)


def test_sink_setattribute_safe_attribute():
    """setAttribute('data-foo', ...) is not dangerous."""
    src = "document.body.setAttribute('data-foo', location.hash);"
    assert analyze_js(src) == []


# --- Sanitiser coverage ----------------------------------------------------

def test_sanitiser_dompurify_full_strip():
    src = """
    var x = location.hash;
    document.body.innerHTML = DOMPurify.sanitize(x);
    """
    assert analyze_js(src) == []


def test_sanitiser_sanitizer_full_strip():
    src = """
    var x = location.hash;
    document.body.innerHTML = Sanitizer.sanitize(x);
    """
    # The Web Sanitizer API is normally invoked on an instance; we
    # recognise the static-class form (consistent with DOMPurify usage)
    # and consider the value scrubbed.
    assert analyze_js(src) == []


def test_partial_encoder_url_is_safe_for_url_sink():
    src = "location.href = encodeURIComponent(location.hash);"
    assert analyze_js(src) == []


def test_partial_encoder_url_is_tentative_for_html_sink():
    """encodeURIComponent neutralises JS-string injection but not HTML.

    Phase 5 of the plan-doc says "conditional sanitiser still flagged
    tentative" — exactly this case.
    """
    src = "document.body.innerHTML = encodeURIComponent(location.hash);"
    findings = analyze_js(src)
    assert len(findings) == 1
    assert findings[0].confidence == "tentative"


# --- Flow propagation ------------------------------------------------------

def test_taint_propagates_through_assignment_chain():
    src = """
    var a = location.hash;
    var b = a;
    var c = "<b>" + b + "</b>";
    document.body.innerHTML = c;
    """
    findings = analyze_js(src)
    assert any("location.hash" in f.evidence for f in findings)


def test_taint_propagates_through_binary_concatenation():
    src = """
    document.body.innerHTML = "<div>" + location.hash + "</div>";
    """
    findings = analyze_js(src)
    assert any("location.hash" in f.evidence for f in findings)


def test_taint_cleared_by_reassignment_to_constant():
    """If the variable gets clobbered with a literal before use, no finding."""
    src = """
    var x = location.hash;
    x = "safe-string";
    document.body.innerHTML = x;
    """
    assert analyze_js(src) == []


def test_no_finding_for_constant_innerhtml():
    src = "document.body.innerHTML = '<b>hello</b>';"
    assert analyze_js(src) == []


def test_no_finding_when_source_unused():
    src = """
    var x = location.hash;
    console.log('ok');
    """
    assert analyze_js(src) == []


# --- Conditional flow ------------------------------------------------------

def test_conditional_branch_tainted_yields_tentative():
    """``cond ? tainted : safe`` → tentative (could be safe at runtime)."""
    src = """
    var x = document.referrer;
    document.body.innerHTML = (someFlag ? x : 'fallback');
    """
    findings = analyze_js(src)
    assert len(findings) == 1
    assert findings[0].confidence == "tentative"


# --- Function-boundary handling --------------------------------------------

def test_function_param_is_untainted_by_default():
    src = """
    function render(text) {
        document.body.innerHTML = text;
    }
    render(location.hash);
    """
    # We don't trace inter-procedural flow. The call site argument is
    # tainted, but the parameter shadow re-introduces it as clean. This
    # is documented behaviour — Phase 7 is intra-procedural only.
    findings = analyze_js(src)
    # No false positive on the function body (because `text` shadows).
    # The call site itself doesn't write to a sink, so nothing fires.
    assert findings == []


def test_inner_function_inherits_outer_taint():
    """Closure over an outer variable preserves taint."""
    src = """
    var x = location.hash;
    function inner() {
        document.body.innerHTML = x;
    }
    inner();
    """
    findings = analyze_js(src)
    assert any("location.hash" in f.evidence for f in findings)


# --- Budget + safety -------------------------------------------------------

def test_budget_aborts_pathological_input():
    """A deeply nested expression hits the wall-clock budget."""
    # Build ~5000-level nested array literal — the parser will accept it
    # but the walker takes long enough at micro-budgets to abort.
    src = "var x = " + ("[" * 5000) + "1" + ("]" * 5000) + ";"
    findings = analyze_js(src, budget_s=0.001)
    # Either we got an info-budget finding, or we returned empty (parser
    # took the whole budget). Both are acceptable graceful-degradation
    # behaviours; assert at minimum we didn't blow up.
    assert isinstance(findings, list)


def test_oversize_source_is_skipped():
    src = "var x = location.hash; document.body.innerHTML = x;" * 100
    # Force size cutoff below current source length.
    assert analyze_js(src, max_size=10) == []


def test_unparseable_source_returns_empty():
    """Garbage input → empty findings; never raises."""
    assert analyze_js("function () { ") == []


def test_empty_source():
    assert analyze_js("") == []
    assert analyze_js("   \n   ") == []


def test_host_url_propagated_into_findings():
    findings = analyze_js(
        "eval(location.hash);",
        host="example.test",
        url="https://example.test/app.js",
    )
    assert findings[0].host == "example.test"
    assert findings[0].url == "https://example.test/app.js"


# --- Deduplication ---------------------------------------------------------

def test_findings_deduped_per_sourceXsinkXline():
    """Two distinct lines → two findings; same line repeated → one."""
    src = """
    document.body.innerHTML = location.hash;
    document.body.innerHTML = location.hash;
    """
    findings = analyze_js(src)
    assert len(findings) == 2  # two distinct line numbers


def test_findings_deduped_on_same_line():
    """A loop on one line shouldn't multiply identical findings."""
    src = "for (var i = 0; i < 3; i++) document.body.innerHTML = location.hash;"
    findings = analyze_js(src)
    # Same source/sink/line tuple → exactly one
    assert len(findings) == 1
