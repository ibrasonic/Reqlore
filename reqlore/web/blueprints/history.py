"""HTTP history list + detail."""
from __future__ import annotations

import json
import re

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, url_for

from ...a11y import ResponseSummaryInput, build_find_multi, summarise_response
from ...plugins import get_registry
from .._decode_helpers import (
    _current_encoding,
    _has_supported_encoding,
    _maybe_decode_blob,
    _split_http,
)
from ..send_targets import available_targets, bearer_token, parse_raw_request, target_label

bp = Blueprint("history", __name__)


# Whitelists for the per-column filter menus. Keeps a stray hand-edited
# query-string value from getting forwarded straight into the WHERE
# clause (defence in depth — the storage layer already binds with ?).
_KNOWN_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_STATUS_BUCKETS = ("1xx", "2xx", "3xx", "4xx", "5xx")
_STATUS_TOKEN_RE = re.compile(r"^[1-5]xx$|^[1-9]\d{2}$")


def _csv_param(name: str) -> list[str]:
    """Read a query-string value that may appear once-CSV (``?m=GET,POST``)
    or repeated (``?m=GET&m=POST``). Trim, drop empties, dedupe while
    preserving order."""
    seen: list[str] = []
    raw_values: list[str] = []
    for v in request.args.getlist(name):
        raw_values.extend(v.split(","))
    for v in raw_values:
        v = v.strip()
        if v and v not in seen:
            seen.append(v)
    return seen


def _int_param(name: str) -> int | None:
    raw = request.args.get(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _read_filters() -> dict:
    """Parse + validate every history filter from the query string into
    a single dict the template, blueprint and storage layer all consume.
    Unknown / malformed values are silently dropped — the URL is the
    user's UI, so we degrade gracefully rather than 400."""
    methods_csv = _csv_param("method")
    methods = [m.upper() for m in methods_csv if m.upper() in _KNOWN_METHODS]
    statuses = [s.lower() for s in _csv_param("status")
                if _STATUS_TOKEN_RE.match(s.strip().lower())]
    engines = _csv_param("engine")
    host = request.args.get("host", "").strip() or None
    host_mode = request.args.get("host_mode", "exact").strip().lower()
    if host_mode not in ("exact", "contains"):
        host_mode = "exact"
    q = request.args.get("q", "").strip() or None
    q_regex = request.args.get("q_re") == "1"
    return {
        "host": host,
        "host_mode": host_mode,
        "q": q,
        "q_regex": q_regex,
        "methods": methods,
        "statuses": statuses,
        "engines": engines,
        "len_min": _int_param("len_min"),
        "len_max": _int_param("len_max"),
        "dur_min": _int_param("dur_min"),
        "dur_max": _int_param("dur_max"),
    }


def _filter_kwargs_for_storage(f: dict) -> dict:
    """Storage filter kwargs derived from the parsed filter dict. Only
    the keys the storage methods accept — no ``host_mode`` / ``q_regex``
    leak when the storage layer doesn't use them."""
    return {
        "host": f["host"],
        "host_mode": f["host_mode"],
        "q": f["q"],
        "q_regex": f["q_regex"],
        "methods": f["methods"] or None,
        "statuses": f["statuses"] or None,
        "engines": f["engines"] or None,
        "len_min": f["len_min"],
        "len_max": f["len_max"],
        "dur_min": f["dur_min"],
        "dur_max": f["dur_max"],
    }


def _engines_seen(project) -> list[str]:
    """List of distinct engine values currently in the table — used by
    the Engine column's filter menu so the choices reflect what the
    operator has actually captured (rather than every engine Reqlore
    *can* drive)."""
    try:
        with project._cursor() as cur:  # noqa: SLF001 — internal helper, fine here
            rows = cur.execute(
                "SELECT engine, COUNT(*) c FROM http_history "
                "GROUP BY engine ORDER BY c DESC, engine ASC").fetchall()
        return [r[0] for r in rows]
    except Exception:  # noqa: BLE001 — never let the side menu 500 the page
        return []


@bp.route("/")
def index():
    f = _read_filters()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 100
    rows = g.project.list_history(
        limit=per_page, offset=(page - 1) * per_page,
        **_filter_kwargs_for_storage(f),
    )
    flagged = [(r, _flags(r.req_blob, r.resp_blob)) for r in rows]
    total = g.project.history_count()
    # Highest row id matching the current filters — used by the page's live
    # poll (latest.json) as the "since" cursor for new-request detection.
    max_id = max((r.id for r in rows), default=0)
    return render_template(
        "history/index.html",
        rows=flagged,
        f=f,
        methods_all=_KNOWN_METHODS,
        statuses_all=_STATUS_BUCKETS,
        engines_all=_engines_seen(g.project),
        page=page, per_page=per_page, total=total,
        max_id=max_id,
        plugin_apps_available=bool(get_registry().active_plugin_apps()),
        any_filter_active=any([
            f["host"], f["q"], f["methods"], f["statuses"], f["engines"],
            f["len_min"] is not None, f["len_max"] is not None,
            f["dur_min"] is not None, f["dur_max"] is not None,
        ]),
    )


@bp.route("/latest.json")
def latest():
    """Poll endpoint for the History page live indicator.

    Query params mirror the index filters so the new-request count reflects
    what the user is actually viewing. `since` is the highest row id the
    client already knows about.
    """
    f = _read_filters()
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        since = 0
    new_count, max_id = g.project.count_history_after(
        since, **_filter_kwargs_for_storage(f),
    )
    return Response(
        json.dumps({"new": new_count, "max_id": max_id, "since": since}),
        mimetype="application/json",
    )


@bp.route("/<int:hid>")
def show(hid: int):
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    # Only honour ?decode=1 when at least one side actually has a
    # Content-Encoding header we can act on — keeps the URL idempotent
    # for rows where the toggle isn't shown.
    has_encoded_body = (_has_supported_encoding(row.req_blob)
                        or _has_supported_encoding(row.resp_blob))
    # Default ON when the section is shown: most operators want to read
    # the body, not stare at a gzipped binary smear. Explicit `decode=0`
    # in the query string opts back into the raw view.
    decode_arg = request.args.get("decode")
    decode = has_encoded_body if decode_arg is None else has_encoded_body and decode_arg == "1"
    req_blob, req_decode_note = _maybe_decode_blob(row.req_blob, decode)
    resp_blob, resp_decode_note = _maybe_decode_blob(row.resp_blob, decode)
    req_text = _safe_text(req_blob)
    resp_text = _safe_text(resp_blob)
    req_encoding = _current_encoding(row.req_blob)
    resp_encoding = _current_encoding(row.resp_blob)

    # Parse response headers from the raw blob for the summariser
    headers, status_line, body = _split_http(row.resp_blob)
    summary = summarise_response(ResponseSummaryInput(
        status=row.status, reason="",
        headers=headers, body=body, duration_ms=row.duration_ms,
    ))
    plugin_copy_as = [h.name for h in get_registry().active_copy_as()]
    send_targets = available_targets(row.req_blob)
    plugin_apps_available = bool(get_registry().active_plugin_apps())

    # Server-side find-in-body. One shared Find form drives highlights
    # across both panes; each pane is marked up in place (no duplicated
    # combined block) so screen-reader users meet the matches in their
    # natural location instead of in a synthetic merged copy.
    find_body = build_find_multi(
        [("req", "request", req_text),
         ("resp", "response", resp_text)],
        form_prefix="body",
        q=request.args.get("body_find", ""),
        regex=request.args.get("body_re") == "1",
        region_label="exchange",
        action=url_for("history.show", hid=hid),
    )
    panes_by_prefix = {p["prefix"]: p for p in find_body["panes"]}

    return render_template(
        "history/detail.html",
        row=row, req_text=req_text, resp_text=resp_text,
        summary=summary, status_line=status_line,
        plugin_copy_as=plugin_copy_as,
        send_targets=send_targets,
        plugin_apps_available=plugin_apps_available,
        find_body=find_body,
        find_req=panes_by_prefix.get("req"),
        find_resp=panes_by_prefix.get("resp"),
        decode=decode,
        has_encoded_body=has_encoded_body,
        req_decode_note=req_decode_note,
        resp_decode_note=resp_decode_note,
        req_encoding=req_encoding,
        resp_encoding=resp_encoding,
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


@bp.route("/<int:hid>/send/<slug>", methods=["POST"])
def send_to(hid: int, slug: str):
    """Dispatch a recorded request to another tool.

    Mirrors the Intercept-detail ``/proxy/intercept/<iid>/send/<slug>``
    endpoint, but with no need to snapshot first because History rows
    already have a stable id every tool can hydrate from.
    """
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    parsed = parse_raw_request(row.req_blob)
    if slug == "repeater":
        target = url_for("repeater.index", from_history=hid)
    elif slug == "intruder":
        target = url_for("intruder.new", from_history=hid)
    elif slug == "sequencer":
        target = url_for("sequencer.capture_new", from_history=hid)
    elif slug == "comparer-a":
        target = url_for("comparer.index", from_a=hid)
    elif slug == "comparer":
        # Legacy slug used by send_targets.SEND_TARGETS ("comparer")
        # maps to side A; "comparer-b" is exposed separately.
        target = url_for("comparer.index", from_a=hid)
    elif slug == "comparer-b":
        target = url_for("comparer.index", from_b=hid)
    elif slug == "poc":
        target = url_for("poc.index", from_history=hid)
    elif slug == "jwt":
        target = url_for("jwt.index",
                         token=bearer_token(parsed.headers))
    elif slug == "decoder":
        target = url_for("decoder.index",
                         text=parsed.body.decode("utf-8", errors="replace"))
    elif slug == "plugin-app":
        target = url_for("plugins.send_to_chooser", from_history=hid)
    elif slug == "auth-matrix":
        target = url_for("auth_matrix.from_history", hid=hid)
    else:
        abort(404, description=f"Unknown send target: {slug!r}")
    flash(f"Sent history #{hid} to {target_label(slug)}.", "ok")
    return redirect(target)


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
