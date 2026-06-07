"""Match & Replace UI."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

bp = Blueprint("matchreplace", __name__)


WHERE_CHOICES = [
    ("req_header", "Request headers"),
    ("req_body", "Request body"),
    ("resp_header", "Response headers"),
    ("resp_body", "Response body"),
]


@bp.route("/", methods=["GET"])
def index():
    rules = g.project.list_mr()
    return render_template("matchreplace/index.html",
                           rules=rules, where_choices=WHERE_CHOICES)


@bp.route("/add", methods=["POST"])
def add():
    where = request.form.get("where", "req_header")
    pattern = request.form.get("pattern", "")
    replacement = request.form.get("replacement", "")
    is_regex = request.form.get("is_regex") == "1"
    host_regex = request.form.get("host_regex", "")
    comment = request.form.get("comment", "")
    if not pattern:
        flash("Pattern cannot be empty.", "err")
    else:
        g.project.add_mr(where=where, pattern=pattern, replacement=replacement,
                          is_regex=is_regex, host_regex=host_regex, comment=comment)
        flash("Rule added. It applies to proxy traffic immediately.", "ok")
    return redirect(url_for("matchreplace.index"))


@bp.route("/<int:mid>/toggle", methods=["POST"])
def toggle(mid: int):
    g.project.toggle_mr(mid)
    return redirect(url_for("matchreplace.index"))


@bp.route("/<int:mid>/delete", methods=["POST"])
def delete(mid: int):
    g.project.delete_mr(mid)
    flash("Rule deleted.", "ok")
    return redirect(url_for("matchreplace.index"))
