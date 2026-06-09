"""Comparer — word + byte diff of two inputs or two history items."""
from __future__ import annotations

from flask import Blueprint, g, redirect, render_template, request, url_for

from .._prg import PRGCache
from ...a11y import (byte_diff_summary, diff_lines, diff_summary,
                       pair_diff_lines)

bp = Blueprint("comparer", __name__)

_cache = PRGCache()

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


def _render(form: dict) -> str:
    """Render the diff page for a given form dict (a, b, from_a, from_b, view)."""
    a = form["a"]; b = form["b"]
    has_input = bool(a or b)
    summary = diff_summary(a, b).sentence("A", "B") if has_input else ""
    byte_summary = byte_diff_summary(
        a.encode("utf-8"), b.encode("utf-8")) if has_input else ""
    raw_lines = diff_lines(a, b) if has_input else []
    paired = [r for r in pair_diff_lines(raw_lines) if r[0] != "same"]
    return render_template(
        "comparer/index.html", form=form, summary=summary,
        byte_summary=byte_summary, paired=paired,
        views=_VIEWS, from_history=bool(form["from_a"] or form["from_b"]),
    )


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        view = (request.form.get("view") or _DEFAULT_VIEW).strip().lower()
        if view not in _VIEWS:
            view = _DEFAULT_VIEW
        form = {
            "a": request.form.get("a", ""),
            "b": request.form.get("b", ""),
            "from_a": (request.form.get("from_a") or "").strip(),
            "from_b": (request.form.get("from_b") or "").strip(),
            "view": view,
        }
        token = _cache.put(form)
        return redirect(url_for(".index", t=token))

    # GET — three sources of state, in priority order:
    # 1. ?t=<token>  → restore a POSTed manual comparison.
    # 2. ?from_a / ?from_b → derive A/B from history rows (already PRG-clean).
    # 3. neither     → empty form.
    src = request.args
    view = (src.get("view") or _DEFAULT_VIEW).strip().lower()
    if view not in _VIEWS:
        view = _DEFAULT_VIEW
    stashed = _cache.get(src.get("t"))
    if stashed:
        return _render(stashed)
    form = {
        "a": "", "b": "",
        "from_a": (src.get("from_a") or "").strip(),
        "from_b": (src.get("from_b") or "").strip(),
        "view": view,
    }
    if form["from_a"] or form["from_b"]:
        form["a"] = _load_blob(form["from_a"], view)
        form["b"] = _load_blob(form["from_b"], view)
    return _render(form)
