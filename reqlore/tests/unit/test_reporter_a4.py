"""A.4 reporter tests: new fields (description/remediation/references/CVSS/rule_id),
reproduction curl synthesis, coverage section, classification banner, footer,
JSON exporter, SARIF exporter, and the new reporter_bp routes.
"""
from __future__ import annotations

import datetime as _dt
import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from reqlore.reporter import (
    DOCX_AVAILABLE,
    JSON_SCHEMA,
    SARIF_VERSION,
    build_json_export,
    build_sarif,
    render_docx,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
)
from reqlore.reporter._common import (
    coverage_rows,
    curl_from_reproduction,
    parse_raw_request,
    severity_counts,
    utc_now,
)
from reqlore.storage import Project

# ---------------- helpers ----------------

_NOW = _dt.datetime(2026, 6, 9, 12, 0, 0, tzinfo=_dt.UTC)


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path / "rep.rlr")


def _add_full_finding(p: Project, **overrides) -> int:
    raw_req = (
        b"POST /api/login HTTP/1.1\r\n"
        b"Host: vt.test\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Token: abc\r\n"
        b"\r\n"
        b'{"u":"admin"}'
    )
    raw_resp = b"HTTP/1.1 200 OK\r\n\r\nok"
    token = p.add_reproduction(
        request_blob=raw_req, response_blob=raw_resp,
        method="POST", url="https://vt.test/api/login",
        status=200, elapsed_ms=12,
    )
    kw = {
        "severity": "high",
        "title": "Reflected XSS in search",
        "host": "vt.test",
        "url": "https://vt.test/search?q=x",
        "evidence": "<script>alert(1)</script>",
        "payload": "<svg/onload=alert(1)>",
        "source": "manual",
        "rule_id": "manual:reflected-xss",
        "rule_version": 1,
        "description": "User input is reflected without escaping.",
        "remediation": "HTML-escape on output. Use a templating engine.",
        "references": ["https://owasp.org/www-community/attacks/xss/",
                     "https://cwe.mitre.org/data/definitions/79.html"],
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1,
        "reproduction_token": token,
    }
    kw.update(overrides)
    fid = p.add_finding(**kw)  # type: ignore[arg-type]  # kw is dynamically composed test fixture; runtime types match add_finding signature
    return fid


def _reproductions(p: Project, findings: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in findings:
        tok = f.get("reproduction_token")
        if tok and tok not in out:
            r = p.get_reproduction(tok)
            if r:
                out[tok] = r
    return out


# ---------------- _common helpers ----------------


def test_utc_now_passes_through_aware_datetime():
    aware = _dt.datetime(2025, 1, 1, 0, 0, 0, tzinfo=_dt.UTC)
    assert utc_now(aware) == aware


def test_utc_now_assumes_utc_for_naive():
    naive = _dt.datetime(2025, 1, 1, 0, 0, 0)
    assert utc_now(naive).tzinfo is _dt.UTC


def test_severity_counts_buckets_all_levels():
    counts = severity_counts([{"severity": "high"}, {"severity": "high"},
                               {"severity": "info"}])
    assert counts == {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 1}


def test_coverage_rows_filters_empty_rule_ids():
    rows = coverage_rows([
        {"rule_id": "passive:a", "fired": 1, "evaluated": 3},
        {"rule_id": "", "fired": 0, "evaluated": 1},
    ])
    assert rows == [{"rule_id": "passive:a", "fired": 1, "evaluated": 3}]


def test_parse_raw_request_extracts_method_path_headers_body():
    blob = (b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\n\r\nBODY")
    method, path, headers, body = parse_raw_request(blob)
    assert method == "POST"
    assert path == "/x"
    assert ("Content-Type", "text/plain") in headers
    assert body == b"BODY"


def test_curl_from_reproduction_drops_host_header_and_quotes():
    blob = (b"POST /api HTTP/1.1\r\nHost: h.test\r\n"
            b"Content-Type: application/json\r\nContent-Length: 5\r\n\r\nhello")
    curl = curl_from_reproduction({
        "url": "https://h.test/api", "method": "POST", "request_blob": blob,
    })
    assert curl.startswith("curl -i -X POST")
    assert "-H 'Content-Type: application/json'" in curl
    assert "-H 'Host" not in curl
    assert "-H 'Content-Length" not in curl
    assert "--data-binary hello" in curl
    assert curl.endswith("https://h.test/api")


def test_curl_from_reproduction_empty_when_no_url():
    assert curl_from_reproduction({"url": "", "request_blob": b""}) == ""


# ---------------- markdown renderer ----------------


def test_markdown_includes_all_new_finding_sections(project: Project):
    _add_full_finding(project)
    findings = project.list_findings()
    md = render_markdown(project.meta(), findings, now=_NOW,
                          reproductions=_reproductions(project, findings))
    assert "Generated (UTC): 2026-06-09T12:00:00+00:00" in md
    assert "Rule: `manual:reflected-xss`" in md
    assert "Source: manual" in md
    assert "CWE: CWE-79" in md
    assert "OWASP: A03:2021" in md
    assert "CVSS: 6.1" in md
    assert "**Description:**" in md
    assert "User input is reflected without escaping." in md
    assert "**Remediation:**" in md
    assert "HTML-escape on output." in md
    assert "**References:**" in md
    assert "- https://owasp.org/www-community/attacks/xss/" in md
    assert "**Reproduction:**" in md
    assert "curl -i -X POST" in md
    # Footer
    assert "_Generated by reqlore" in md


def test_markdown_classification_banner_renders(project: Project):
    _add_full_finding(project)
    md = render_markdown(project.meta(), project.list_findings(),
                          now=_NOW, classification="CONFIDENTIAL — CLIENT-X")
    assert "> **CONFIDENTIAL — CLIENT-X**" in md


def test_markdown_coverage_section_lists_rules(project: Project):
    _add_full_finding(project)
    project.record_rule_run(rule_id="passive:hsts-missing", fired=False,
                              host="vt.test", url="https://vt.test/")
    project.record_rule_run(rule_id="manual:reflected-xss", fired=True,
                              host="vt.test", url="https://vt.test/")
    md = render_markdown(
        project.meta(), project.list_findings(), now=_NOW,
        include_coverage=True, coverage=project.rule_run_summary(),
    )
    assert "## Coverage" in md
    assert "`manual:reflected-xss`" in md
    assert "`passive:hsts-missing`" in md
    # Header for table
    assert "| Rule | Fired | Evaluated |" in md


def test_markdown_omits_curl_when_no_reproduction(project: Project):
    project.add_finding(severity="low", title="t", host="h", url="https://h/",
                         evidence="e", source="scanner",
                         rule_id="passive:t", reproduction_token=None)
    md = render_markdown(project.meta(), project.list_findings(), now=_NOW)
    assert "**Reproduction:**" not in md


# ---------------- html renderer ----------------


def test_html_meta_generator_and_new_fields(project: Project):
    _add_full_finding(project)
    findings = project.list_findings()
    html = render_html(project.meta(), findings, now=_NOW,
                        reproductions=_reproductions(project, findings))
    assert '<meta name="generator" content="reqlore ' in html
    assert "<dt>Rule</dt><dd><code>manual:reflected-xss</code></dd>" in html
    assert "<dt>Source</dt><dd>manual</dd>" in html
    assert "<dt>CVSS</dt>" in html
    assert "<strong>Description</strong>" in html
    assert "<strong>Remediation</strong>" in html
    assert "<strong>References</strong>" in html
    assert "<strong>Reproduction</strong>" in html
    # curl is HTML-escaped
    assert "curl -i -X POST" in html
    # Footer
    assert "Generated by reqlore" in html
    # Still no JS / external links
    assert "<script" not in html
    assert "<link" not in html


def test_html_classification_banner_renders(project: Project):
    _add_full_finding(project)
    html = render_html(project.meta(), project.list_findings(),
                        now=_NOW, classification="CONFIDENTIAL")
    assert 'class="classification"' in html
    assert "CONFIDENTIAL" in html


def test_html_coverage_section(project: Project):
    _add_full_finding(project)
    project.record_rule_run(rule_id="passive:x", fired=False)
    html = render_html(
        project.meta(), project.list_findings(), now=_NOW,
        include_coverage=True, coverage=project.rule_run_summary(),
    )
    assert '<h2 id="coverage">Coverage</h2>' in html
    assert "<code>passive:x</code>" in html


# ---------------- docx renderer ----------------


@pytest.mark.skipif(not DOCX_AVAILABLE, reason="python-docx not installed")
def test_docx_contains_new_field_labels(project: Project):
    _add_full_finding(project)
    findings = project.list_findings()
    blob = render_docx(project.meta(), findings, now=_NOW,
                        include_coverage=True,
                        coverage=project.rule_run_summary(),
                        reproductions=_reproductions(project, findings),
                        classification="CONFIDENTIAL")
    assert blob[:2] == b"PK"
    # The docx is a zip with document.xml inside; pull the text.
    with zipfile.ZipFile(BytesIO(blob)) as z:
        body = z.read("word/document.xml").decode("utf-8", "replace")
    for needle in ("Description:", "Remediation:", "References:",
                    "Reproduction:", "CONFIDENTIAL",
                    "Rule: manual:reflected-xss",
                    "Generated by reqlore"):
        assert needle in body, needle


# ---------------- json exporter ----------------


def test_json_exporter_schema_and_fields(project: Project):
    _add_full_finding(project)
    out = build_json_export(project.meta(), project.list_findings(), now=_NOW)
    assert out["schema"] == JSON_SCHEMA == "reqlore.findings/1"
    assert out["generated_at"] == "2026-06-09T12:00:00+00:00"
    assert out["generator"].startswith("reqlore ")
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    for key in ("uuid", "severity", "rule_id", "source", "cwe", "owasp",
                "description", "remediation", "references", "cvss_score",
                "cvss_vector", "reproduction_token", "created_at",
                "updated_at"):
        assert key in f
    assert f["rule_id"] == "manual:reflected-xss"
    assert f["references"] == [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
    ]


def test_render_json_returns_valid_json(project: Project):
    _add_full_finding(project)
    body = render_json(project.meta(), project.list_findings(), now=_NOW)
    parsed = json.loads(body)
    assert parsed["schema"] == "reqlore.findings/1"


def test_json_exporter_coverage_and_classification(project: Project):
    _add_full_finding(project)
    project.record_rule_run(rule_id="passive:x", fired=False)
    out = build_json_export(
        project.meta(), project.list_findings(), now=_NOW,
        classification="CONFIDENTIAL",
        include_coverage=True, coverage=project.rule_run_summary(),
    )
    assert out["classification"] == "CONFIDENTIAL"
    assert any(r["rule_id"] == "passive:x" for r in out["coverage"])


# ---------------- sarif exporter ----------------


def test_sarif_top_level_shape(project: Project):
    _add_full_finding(project)
    out = build_sarif(project.meta(), project.list_findings(), now=_NOW)
    assert out["version"] == SARIF_VERSION == "2.1.0"
    assert out["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(out["runs"]) == 1
    run = out["runs"][0]
    assert run["tool"]["driver"]["name"] == "reqlore"
    assert run["tool"]["driver"]["rules"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "manual:reflected-xss"
    assert rule["properties"]["cwe"] == "CWE-79"
    assert "security" in rule["properties"]["tags"]
    assert run["results"][0]["ruleId"] == "manual:reflected-xss"
    # high -> error level
    assert run["results"][0]["level"] == "error"


def test_render_sarif_serialises_to_json(project: Project):
    _add_full_finding(project)
    body = render_sarif(project.meta(), project.list_findings(), now=_NOW)
    parsed = json.loads(body)
    assert parsed["version"] == "2.1.0"


def test_sarif_severity_levels_mapping(project: Project):
    project.add_finding(severity="info", title="i", host="h", url="https://h/",
                         evidence="a", rule_id="passive:i", source="scanner")
    project.add_finding(severity="medium", title="m", host="h", url="https://h/b",
                         evidence="b", rule_id="passive:m", source="scanner")
    out = build_sarif(project.meta(), project.list_findings(), now=_NOW)
    levels = {r["ruleId"]: r["level"] for r in out["runs"][0]["results"]}
    assert levels["passive:i"] == "note"
    assert levels["passive:m"] == "warning"
