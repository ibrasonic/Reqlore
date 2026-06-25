"""Phase 23 — framework debug / admin page detection (body-marker passive)."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _DEBUG_PAGE_MARKERS,
    rule_framework_debug_pages,
)


@dataclass
class _Row:
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _req(method: str, url: str) -> bytes:
    return (f"{method} {url} HTTP/1.1\r\n\r\n").encode("latin-1")


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or [("Content-Type", "text/html")]
    head = f"HTTP/1.1 {status} OK\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _row(url="https://app.test/", host="app.test", status=200,
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host=host, url=url, method="GET", status=status,
        req_blob=_req("GET", url),
        resp_blob=_resp(status, resp_headers, resp_body),
    )


def _findings(row):
    return list(run_passive(row, rules=[rule_framework_debug_pages]))


# ---- positives ------------------------------------------------------------


def test_spring_actuator_env_flagged_as_critical():
    body = (b'{"activeProfiles":["prod"],"propertySources":['
            b'{"name":"applicationConfig","properties":{'
            b'"spring.datasource.password":{"value":"hunter2"}}}]}')
    f = _findings(_row(
        url="https://api.test/actuator/env",
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any("Spring Boot Actuator (/env)" in x.title for x in f)
    finding = next(x for x in f if "Actuator (/env)" in x.title)
    assert finding.severity == "critical"
    assert finding.cwe == "CWE-489"


def test_spring_heapdump_binary_marker_still_fires():
    # /heapdump is served as octet-stream → the rule must allow that one
    # marker to run even though _is_text_response would normally reject.
    body = b"JAVA PROFILE 1.0.2\n" + (b"\x00" * 200)
    f = _findings(_row(
        url="https://api.test/actuator/heapdump",
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert any("heapdump" in x.title for x in f)


def test_spring_heapdump_gzipped_binary_signature():
    body = b"\x1f\x8b\x08\x00" + (b"\x00" * 100)  # gzip magic
    f = _findings(_row(
        url="https://api.test/actuator/heapdump",
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert any("heapdump" in x.title for x in f)


def test_werkzeug_debugger_flagged_critical():
    body = (b'<title>Error // Werkzeug Debugger</title>'
            b'<script>WERKZEUG_DEBUG_PIN = "123-456-789";</script>')
    f = _findings(_row(resp_body=body))
    assert any("Werkzeug" in x.title for x in f)
    finding = next(x for x in f if "Werkzeug" in x.title)
    assert finding.severity == "critical"


def test_django_debug_true_page_flagged():
    body = (b'<p>You\'re seeing this error because you have '
            b'<code>DEBUG = True</code> in your Django settings file.</p>')
    f = _findings(_row(resp_body=body))
    assert any("Django DEBUG=True" in x.title for x in f)


def test_rails_error_template_flagged():
    body = (b'<h1>NoMethodError</h1>'
            b'<pre>undefined method `name\' for nil:NilClass</pre>')
    f = _findings(_row(resp_body=body))
    assert any("Rails error" in x.title for x in f)
    finding = next(x for x in f if "Rails error" in x.title)
    assert finding.severity == "critical"


def test_laravel_ignition_flagged():
    body = b'<title>Whoops! There was an error.</title>'
    f = _findings(_row(resp_body=body))
    assert any("Laravel Ignition" in x.title for x in f)


def test_symfony_profiler_flagged():
    body = b'<title>Symfony Profiler</title><div class="sf-toolbar">'
    f = _findings(_row(resp_body=body))
    assert any("Symfony" in x.title for x in f)


def test_aspnet_yellow_screen_flagged():
    body = (b'<title>Runtime Error</title>'
            b'<body><span><H1>Runtime Error</H1></span></body>')
    f = _findings(_row(resp_body=body))
    assert any("ASP.NET yellow-screen" in x.title for x in f)


def test_elmah_log_flagged_critical():
    body = b'<title>Error log for /</title><link href="elmah/main.css">'
    f = _findings(_row(resp_body=body))
    finding = next((x for x in f if "ELMAH" in x.title), None)
    assert finding is not None
    assert finding.severity == "critical"


def test_express_stack_trace_flagged():
    body = (b'<title>Error</title>'
            b'<pre>TypeError: Cannot read property &#39;foo&#39; of undefined'
            b'\n    at handler (/srv/app/routes.js:42:10)</pre>')
    f = _findings(_row(resp_body=body))
    assert any("Express" in x.title for x in f)


def test_phpinfo_flagged():
    body = b'<title>phpinfo()</title><h1 class="p">PHP Version 8.0.30'
    f = _findings(_row(resp_body=body))
    assert any("phpinfo" in x.title for x in f)


# ---- negatives ------------------------------------------------------------


def test_404_response_not_scanned():
    body = b'<title>phpinfo()</title>'  # would normally match
    f = _findings(_row(status=404, resp_body=body))
    assert f == []


def test_plain_html_with_word_debug_not_flagged():
    # Markers are signature-specific; a blog post that mentions "Django"
    # or "Werkzeug" must NOT fire the rule.
    body = (b'<article>My favourite Python web frameworks include Django, '
            b'Flask, and Werkzeug. Rails is great too.</article>')
    f = _findings(_row(resp_body=body))
    assert f == []


def test_binary_response_skipped_except_heapdump():
    # An octet-stream that doesn't contain the heapdump magic must yield
    # nothing — the binary-marker shortcut only fires for that one slug.
    body = b'<title>phpinfo()</title>' + (b'\x00' * 1000)
    f = _findings(_row(
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert f == []


def test_dedup_per_response_single_marker():
    # Even if the marker appears twice in the body, one finding fires.
    body = (b'<title>Whoops! There was an error.</title>'
            b'... lots of HTML ...'
            b'<title>Whoops! There was an error.</title>')
    f = _findings(_row(resp_body=body))
    laravel = [x for x in f if "Laravel" in x.title]
    assert len(laravel) == 1


def test_multiple_distinct_markers_yield_multiple_findings():
    body = (b'<title>phpinfo()</title>'
            b'<h1 class="p">PHP Version 8.0.30</h1>'
            b'... <title>Whoops! There was an error.</title> ...')
    f = _findings(_row(resp_body=body))
    titles = {x.title for x in f}
    assert any("phpinfo" in t for t in titles)
    assert any("Laravel" in t for t in titles)


# ---- registration & table integrity ----------------------------------------


def test_rule_runs_via_default_run_passive():
    body = b'<title>phpinfo()</title><h1 class="p">PHP Version 8.0.30'
    f = list(run_passive(_row(resp_body=body)))
    assert any("phpinfo" in x.title for x in f)


def test_debug_page_marker_table_invariants():
    valid_sev = {"info", "low", "medium", "high", "critical"}
    seen_slugs: set[str] = set()
    for entry in _DEBUG_PAGE_MARKERS:
        assert len(entry) == 5, entry
        slug, regex, framework, severity, summary = entry
        assert slug not in seen_slugs, f"duplicate slug {slug}"
        seen_slugs.add(slug)
        assert slug == slug.lower()
        # `regex` must be a compiled bytes pattern.
        assert hasattr(regex, "search")
        assert regex.pattern.__class__ is bytes
        assert framework
        assert severity in valid_sev
        assert len(summary) >= 40, slug
