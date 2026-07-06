"""Report export: Markdown / HTML / DOCX / JSON / SARIF."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, Response, abort, g, render_template, request

from ...reporter import (
    DOCX_AVAILABLE,
    render_docx,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
)

bp = Blueprint("reporter", __name__)


@bp.route("/")
def index():
    return render_template("reporter/index.html",
                           docx_available=DOCX_AVAILABLE,
                           summary=g.project.findings_summary(),
                           total=g.project.findings_count())


def _reproductions_for(findings: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in findings:
        token = f.get("reproduction_token")
        if not token or token in out:
            continue
        repro = g.project.get_reproduction(token)
        if repro:
            out[token] = repro
    return out


@bp.route("/export.<fmt>")
def export(fmt: str):
    fmt = fmt.lower()
    sev = request.args.get("severity") or None
    status = request.args.get("status") or None
    include_coverage = request.args.get("coverage", "").lower() in ("1", "true", "yes", "on")
    classification = request.args.get("classification", "").strip()
    findings = g.project.list_findings(severity=sev, status=status, limit=10_000)
    meta = g.project.meta()
    coverage = g.project.rule_run_summary() if include_coverage else None
    coverage_by_host = (
        g.project.rule_run_summary_by_host() if include_coverage else None
    )
    reproductions = _reproductions_for(findings)
    common_kwargs: dict[str, Any] = {
        "classification": classification,
        "include_coverage": include_coverage,
        "coverage": coverage,
        "coverage_by_host": coverage_by_host,
        "reproductions": reproductions,
    }
    if fmt == "md":
        body = render_markdown(meta, findings, **common_kwargs)
        return Response(body, mimetype="text/markdown; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="reqlore-findings.md"'})
    if fmt == "html":
        body = render_html(meta, findings, **common_kwargs)
        return Response(body, mimetype="text/html; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="reqlore-findings.html"'})
    if fmt == "docx":
        if not DOCX_AVAILABLE:
            abort(400, description=(
                "python-docx is not installed. Install it with "
                "'pip install python-docx' and reload the page, or export as "
                "Markdown / HTML instead."
            ))
        docx_body: bytes = render_docx(meta, findings, **common_kwargs)
        return Response(docx_body, mimetype=(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ), headers={"Content-Disposition":
                    'attachment; filename="reqlore-findings.docx"'})
    if fmt == "json":
        body = render_json(meta, findings,
                            classification=classification,
                            include_coverage=include_coverage,
                            coverage=coverage,
                            coverage_by_host=coverage_by_host)
        return Response(body, mimetype="application/json; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="reqlore-findings.json"'})
    if fmt == "sarif":
        body = render_sarif(meta, findings)
        return Response(body, mimetype="application/sarif+json; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="reqlore-findings.sarif"'})
    abort(404)
