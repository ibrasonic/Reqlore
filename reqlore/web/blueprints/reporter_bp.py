"""Report export: Markdown / HTML / DOCX."""
from __future__ import annotations

from flask import Blueprint, Response, abort, g, render_template, request

from ...reporter import (
    DOCX_AVAILABLE, render_docx, render_html, render_markdown,
)

bp = Blueprint("reporter", __name__)


@bp.route("/")
def index():
    return render_template("reporter/index.html",
                           docx_available=DOCX_AVAILABLE,
                           summary=g.project.findings_summary(),
                           total=g.project.findings_count())


@bp.route("/export.<fmt>")
def export(fmt: str):
    fmt = fmt.lower()
    sev = request.args.get("severity") or None
    status = request.args.get("status") or None
    findings = g.project.list_findings(severity=sev, status=status, limit=10_000)
    meta = g.project.meta()
    if fmt == "md":
        body = render_markdown(meta, findings)
        return Response(body, mimetype="text/markdown; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="reqlore-findings.md"'})
    if fmt == "html":
        body = render_html(meta, findings)
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
        body = render_docx(meta, findings)
        return Response(body, mimetype=(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ), headers={"Content-Disposition":
                    'attachment; filename="reqlore-findings.docx"'})
    abort(404)
