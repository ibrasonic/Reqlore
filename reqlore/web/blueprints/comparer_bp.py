"""Comparer — word + byte diff of two inputs or two history items."""
from __future__ import annotations

from flask import Blueprint, g, render_template, request

from ...a11y import (byte_diff_summary, diff_lines, diff_summary,
                       pair_diff_lines)

bp = Blueprint("comparer", __name__)

_VIEWS = ("request", "response", "both")
_DEFAULT_VIEW = "request"


def _load_blob(hid_str: str, view: str) -> str:
    """Return the chosen view of a history row as text, or ``""``."""
    if not hid_str:
        return ""
    try:
        hid = int(hid_str)
    except ValueError:
        return ""
    row = g.project.get_history(hid)
    if not row:
        return ""
    if view == "request":
        return row.req_blob.decode("utf-8", errors="replace")
    if view == "response":
        return row.resp_blob.decode("utf-8", errors="replace")
    # both — concatenate with a clear separator
    req = row.req_blob.decode("utf-8", errors="replace")
    resp = row.resp_blob.decode("utf-8", errors="replace")
    return f"{req}\n\n--- response ---\n\n{resp}"


@bp.route("/", methods=["GET", "POST"])
def index():
    src = request.form if request.method == "POST" else request.args
    view = (src.get("view") or _DEFAULT_VIEW).strip().lower()
    if view not in _VIEWS:
        view = _DEFAULT_VIEW
    form = {
        "a": "", "b": "",
        "from_a": (src.get("from_a") or "").strip(),
        "from_b": (src.get("from_b") or "").strip(),
        "view": view,
    }
    if request.method == "POST":
        # Manual mode: keep whatever the user typed in the textareas.
        form["a"] = request.form.get("a", "")
        form["b"] = request.form.get("b", "")
    elif form["from_a"] or form["from_b"]:
        # From-history mode: derive A/B from the chosen view of each row.
        form["a"] = _load_blob(form["from_a"], view)
        form["b"] = _load_blob(form["from_b"], view)

    a = form["a"]; b = form["b"]
    has_input = bool(a or b)
    summary = diff_summary(a, b).sentence("A", "B") if has_input else ""
    byte_summary = byte_diff_summary(
        a.encode("utf-8"), b.encode("utf-8")) if has_input else ""
    raw_lines = diff_lines(a, b) if has_input else []
    # Pair the rows for the side-by-side renderer. Strip "same" runs so
    # the table only shows changes (the textareas above hold the full
    # context already).
    paired = [r for r in pair_diff_lines(raw_lines) if r[0] != "same"]
    return render_template(
        "comparer/index.html", form=form, summary=summary,
        byte_summary=byte_summary, paired=paired,
        views=_VIEWS, from_history=bool(form["from_a"] or form["from_b"]),
    )
