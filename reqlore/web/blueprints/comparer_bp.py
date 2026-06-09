"""Comparer — word + byte diff of two inputs or two history items."""
from __future__ import annotations

from flask import (
    Blueprint, Response, abort, g, redirect, render_template, request, url_for,
)

from .._prg import PRGCache
from ...a11y import (byte_diff_summary, diff_lines, diff_summary,
                       pair_diff_lines, unified_diff)

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


def _render(form: dict, *, token: str | None = None) -> str:
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
        token=token,
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
        return _render(stashed, token=src.get("t"))
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


@bp.route("/export.diff")
def export_diff():
    """Download the current comparison as a unified `.diff` patch file.

    Sources A and B from the same places ``index`` uses (PRG token, from-
    history params, or query a/b), so the export URL is stable for the
    lifetime of the cached token.
    """
    src = request.args
    view = (src.get("view") or _DEFAULT_VIEW).strip().lower()
    if view not in _VIEWS:
        view = _DEFAULT_VIEW
    a = b = ""
    label_a = "A"
    label_b = "B"
    fname_stem = "comparer"

    stashed = _cache.get(src.get("t"))
    if stashed:
        a = stashed.get("a", "")
        b = stashed.get("b", "")
        if stashed.get("from_a"):
            label_a = f"history-{stashed['from_a']}"
        if stashed.get("from_b"):
            label_b = f"history-{stashed['from_b']}"
        if stashed.get("from_a") and stashed.get("from_b"):
            fname_stem = (f"history-{stashed['from_a']}-vs-"
                          f"{stashed['from_b']}-{stashed.get('view', view)}")
    elif src.get("from_a") or src.get("from_b"):
        from_a = (src.get("from_a") or "").strip()
        from_b = (src.get("from_b") or "").strip()
        a = _load_blob(from_a, view)
        b = _load_blob(from_b, view)
        if from_a:
            label_a = f"history-{from_a}"
        if from_b:
            label_b = f"history-{from_b}"
        if from_a and from_b:
            fname_stem = f"history-{from_a}-vs-{from_b}-{view}"
    else:
        abort(404)

    patch = unified_diff(a, b, label_a=label_a, label_b=label_b)
    if not patch:
        # Identical inputs — give the operator a useful artefact rather
        # than an empty file (which would look like a server bug).
        patch = (f"--- {label_a}\n+++ {label_b}\n"
                  f"# No differences ({len(a)} bytes, identical).\n")
    resp = Response(patch, mimetype="text/x-diff; charset=utf-8")
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{fname_stem}.diff"'
    )
    return resp
