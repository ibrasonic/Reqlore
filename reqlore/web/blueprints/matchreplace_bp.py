"""Match & Replace UI."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ... import _safe_regex

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
        return redirect(url_for("matchreplace.index"))
    # L-12: validate user-supplied regexes at save time. Catching
    # ``regex.error`` here gives the operator immediate feedback in
    # the UI instead of a silent runtime failure inside the proxy
    # worker thread.
    if is_regex and not _safe_regex.is_valid_pattern(pattern):
        flash("Pattern is not a valid regular expression.", "err")
        return redirect(url_for("matchreplace.index"))
    if host_regex and not _safe_regex.is_valid_pattern(host_regex):
        flash("Host filter is not a valid regular expression.", "err")
        return redirect(url_for("matchreplace.index"))
    # M-14: warn (non-blocking) if the host filter is not anchored.
    # An unanchored ``example\.com`` matches ``evil-example.com.attacker``
    # too -- almost never what the operator intended.
    if host_regex and not (host_regex.startswith("^") or "$" in host_regex):
        flash(
            "Heads up: host filter is not anchored. Add ^ at the start "
            "and $ at the end to avoid matching attacker-controlled "
            "subdomains like evil-example.com.attacker.tld.",
            "warn",
        )
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
