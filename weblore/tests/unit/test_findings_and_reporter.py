"""Findings persistence, reporter formats, scanner end-to-end."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from weblore.reporter import (
    DOCX_AVAILABLE, render_html, render_markdown,
)
from weblore.scanner import Scanner
from weblore.storage import Project


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path / "p3.weblore")


def _add_history(p: Project, *, url: str, status: int = 200,
                  resp_headers: list[tuple[str, str]] = None,
                  resp_body: bytes = b"") -> int:
    resp_headers = resp_headers or []
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in resp_headers
    )
    raw_resp = head.encode("latin-1") + b"\r\n" + resp_body
    raw_req = b"GET " + url.encode() + b" HTTP/1.1\r\n\r\n"
    host = url.split("//", 1)[1].split("/", 1)[0]
    return p.add_history(
        host=host, method="GET", url=url, status=status,
        duration_ms=10, engine="httpx", raw_req=raw_req, raw_resp=raw_resp,
    )


def test_add_and_list_findings(project: Project):
    fid = project.add_finding(
        severity="high", title="Demo", host="x.test", url="https://x.test/",
        cwe="CWE-79", evidence="proof",
    )
    assert fid > 0
    rows = project.list_findings()
    assert len(rows) == 1
    assert rows[0]["title"] == "Demo"
    assert rows[0]["status"] == "open"


def test_finding_status_lifecycle(project: Project):
    fid = project.add_finding(severity="low", title="t")
    project.set_finding_status(fid, "triaged")
    assert project.get_finding(fid)["status"] == "triaged"
    project.set_finding_status(fid, "false_positive")
    assert project.get_finding(fid)["status"] == "false_positive"


def test_finding_status_rejects_bad_value(project: Project):
    fid = project.add_finding(severity="low", title="t")
    with pytest.raises(ValueError):
        project.set_finding_status(fid, "bogus")


def test_dedupe_suppresses_duplicates(project: Project):
    for _ in range(3):
        project.add_finding(
            severity="low", title="Same",
            host="x.test", url="https://x.test/", evidence="proof-A",
            dedupe_key="Same|x.test|https://x.test/|proof-A",
        )
    assert project.findings_count() == 1


def test_findings_summary_groups_open_only(project: Project):
    project.add_finding(severity="high", title="A")
    project.add_finding(severity="low", title="B")
    fid = project.add_finding(severity="critical", title="C")
    project.set_finding_status(fid, "false_positive")
    summary = project.findings_summary()
    assert summary["high"] == 1
    assert summary["low"] == 1
    # 'C' is not open any more, so it should not be counted.
    assert summary["critical"] == 0


def test_scanner_end_to_end_finds_missing_csp(project: Project):
    _add_history(
        project, url="https://x.test/",
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"<html></html>",
    )
    result = Scanner().scan_project(project)
    assert result.rows_scanned == 1
    assert result.findings_added > 0
    titles = {f["title"] for f in project.list_findings()}
    assert "Missing response header: Content-Security-Policy" in titles


def test_scanner_dedupes_across_repeated_runs(project: Project):
    _add_history(
        project, url="https://x.test/",
        resp_headers=[("Content-Type", "text/html")],
    )
    Scanner().scan_project(project)
    n1 = project.findings_count()
    Scanner().scan_project(project)
    n2 = project.findings_count()
    assert n1 == n2 > 0


def test_render_markdown_includes_severity_sections(project: Project):
    project.add_finding(severity="high", title="HighFinding",
                         host="x.test", url="https://x.test/", evidence="e1")
    project.add_finding(severity="info", title="InfoFinding",
                         host="x.test", url="https://x.test/", evidence="e2")
    md = render_markdown(project.meta(), project.list_findings())
    assert "# Weblore — Security Findings" in md
    assert "## High (1)" in md
    assert "## Info (1)" in md
    assert "HighFinding" in md
    assert "InfoFinding" in md


def test_render_html_is_self_contained(project: Project):
    project.add_finding(severity="critical", title="X",
                         host="h", url="https://h/", evidence="<script>")
    html = render_html(project.meta(), project.list_findings())
    assert html.startswith("<!doctype html>")
    # No external resources allowed in the report.
    assert "<link" not in html
    assert "<script" not in html  # raw '<script' (no JS, and the escaped evidence keeps the &lt; entity)
    # Evidence with HTML must be escaped.
    assert "&lt;script&gt;" in html
    # Severity badge for critical present.
    assert "Critical" in html


@pytest.mark.skipif(not DOCX_AVAILABLE, reason="python-docx not installed")
def test_render_docx_produces_valid_zip(project: Project):
    from weblore.reporter import render_docx
    project.add_finding(severity="high", title="t",
                         host="h", url="https://h/", evidence="e")
    blob = render_docx(project.meta(), project.list_findings())
    # .docx is a zip file — magic bytes 'PK'.
    assert blob[:2] == b"PK"
    assert len(blob) > 1000
