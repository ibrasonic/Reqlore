"""Comparer — word + byte diff of two inputs or two history items."""
from __future__ import annotations

from flask import Blueprint, g, render_template, request

from ...a11y import byte_diff_summary, diff_lines, diff_summary

bp = Blueprint("comparer", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    form = {
        "a": "", "b": "",
        "from_a": request.args.get("from_a", ""),
        "from_b": request.args.get("from_b", ""),
        "view": "request",  # 'request' | 'response'
    }
    if request.method == "POST":
        for k in form:
            if k in request.form:
                form[k] = request.form[k]
    elif form["from_a"] or form["from_b"]:
        if form["from_a"]:
            try:
                row = g.project.get_history(int(form["from_a"]))
                if row:
                    form["a"] = (row.req_blob if form["view"] == "request"
                                  else row.resp_blob).decode("utf-8", errors="replace")
            except ValueError:
                pass
        if form["from_b"]:
            try:
                row = g.project.get_history(int(form["from_b"]))
                if row:
                    form["b"] = (row.req_blob if form["view"] == "request"
                                  else row.resp_blob).decode("utf-8", errors="replace")
            except ValueError:
                pass

    a = form["a"]; b = form["b"]
    summary = diff_summary(a, b).sentence("A", "B") if a or b else ""
    byte_summary = byte_diff_summary(a.encode("utf-8"), b.encode("utf-8")) if a or b else ""
    lines = diff_lines(a, b) if a or b else []
    return render_template(
        "comparer/index.html", form=form, summary=summary,
        byte_summary=byte_summary, lines=lines,
    )
