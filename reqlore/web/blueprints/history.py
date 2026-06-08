"""HTTP history list + detail."""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for, Response

from ...a11y import ResponseSummaryInput, summarise_response
from ...plugins import get_registry

bp = Blueprint("history", __name__)


@bp.route("/")
def index():
    q = request.args.get("q", "").strip() or None
    host = request.args.get("host", "").strip() or None
    method = request.args.get("method", "").strip().upper() or None
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 100
    rows = g.project.list_history(
        limit=per_page, offset=(page - 1) * per_page,
        host=host, q=q, method=method,
    )
    flagged = [(r, _flags(r.req_blob, r.resp_blob)) for r in rows]
    total = g.project.history_count()
    methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    return render_template("history/index.html",
                           rows=flagged, q=q or "", host=host or "",
                           method=method or "", methods=methods,
                           page=page, per_page=per_page, total=total)


@bp.route("/<int:hid>")
def show(hid: int):
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    req_text = _safe_text(row.req_blob)
    resp_text = _safe_text(row.resp_blob)

    # Parse response headers from the raw blob for the summariser
    headers, status_line, body = _split_http(row.resp_blob)
    summary = summarise_response(ResponseSummaryInput(
        status=row.status, reason="",
        headers=headers, body=body, duration_ms=row.duration_ms,
    ))
    plugin_copy_as = [h.name for h in get_registry().active_copy_as()]
    return render_template(
        "history/detail.html",
        row=row, req_text=req_text, resp_text=resp_text,
        summary=summary, status_line=status_line,
        plugin_copy_as=plugin_copy_as,
    )


@bp.route("/<int:hid>/copy-as/<name>")
def copy_as(hid: int, name: str):
    """Render the raw request through a plugin-supplied copy-as handler."""
    from flask import Response as FlaskResponse
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    handler = next((h for h in get_registry().active_copy_as()
                     if h.name == name), None)
    if not handler:
        abort(404)
    out = handler.render(row.req_blob)
    return FlaskResponse(out, mimetype="text/plain; charset=utf-8")


@bp.route("/<int:hid>/to-repeater", methods=["POST"])
def to_repeater(hid: int):
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    return redirect(url_for("repeater.index", from_history=hid))


@bp.route("/export.jsonl")
def export_jsonl():
    rows = g.project.list_history(limit=10000)

    def gen():
        for r in rows:
            yield json.dumps({
                "id": r.id, "ts": r.ts, "host": r.host, "method": r.method,
                "url": r.url, "status": r.status, "duration_ms": r.duration_ms,
                "engine": r.engine, "len_req": r.len_req, "len_resp": r.len_resp,
            }) + "\n"

    return Response(gen(), mimetype="application/x-ndjson")


@bp.route("/clear", methods=["POST"])
def clear():
    n = g.project.clear_history()
    flash(f"Cleared {n} history record{'s' if n != 1 else ''}.", "ok")
    return redirect(url_for(".index"))


def _safe_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _split_http(raw: bytes) -> tuple[list[tuple[str, str]], str, bytes]:
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return [], "", raw
    head, body = raw[:sep].decode("latin-1", errors="replace"), raw[sep + 4:]
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return headers, status_line, body


def _flags(req: bytes, resp: bytes) -> list[str]:
    """Plain-language short flags: auth, csrf, cors, set-cookie, sets-csp, redirect."""
    req_h, _, _ = _split_http(req)
    resp_h, _, _ = _split_http(resp)
    f: list[str] = []
    keys_req = {k.lower() for k, _ in req_h}
    if "authorization" in keys_req or "cookie" in keys_req:
        f.append("auth")
    if any("csrf" in k.lower() or "xsrf" in k.lower() for k, _ in req_h):
        f.append("csrf")
    resp_lower = {k.lower(): v for k, v in resp_h}
    if "set-cookie" in {k.lower() for k, _ in resp_h}:
        f.append("set-cookie")
    if "access-control-allow-origin" in resp_lower:
        f.append("cors")
    if "content-security-policy" in resp_lower:
        f.append("csp")
    if "location" in resp_lower:
        f.append("redirect")
    return f
