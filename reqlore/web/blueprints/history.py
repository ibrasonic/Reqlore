"""HTTP history list + detail."""
from __future__ import annotations

import gzip
import json
import zlib

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for, Response

from ...a11y import (ResponseSummaryInput, build_find_multi,
                     summarise_response)
from ...plugins import get_registry
from ..send_targets import (available_targets, bearer_token,
                              parse_raw_request, target_label)

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
    # Highest row id matching the current filters — used by the page's live
    # poll (latest.json) as the "since" cursor for new-request detection.
    max_id = max((r.id for r in rows), default=0)
    methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    return render_template("history/index.html",
                           rows=flagged, q=q or "", host=host or "",
                           method=method or "", methods=methods,
                           page=page, per_page=per_page, total=total,
                           max_id=max_id)


@bp.route("/latest.json")
def latest():
    """Poll endpoint for the History page live indicator.

    Query params mirror the index filters so the new-request count reflects
    what the user is actually viewing. `since` is the highest row id the
    client already knows about.
    """
    q = request.args.get("q", "").strip() or None
    host = request.args.get("host", "").strip() or None
    method = request.args.get("method", "").strip().upper() or None
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        since = 0
    new_count, max_id = g.project.count_history_after(
        since, host=host, q=q, method=method,
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
    decode = has_encoded_body and request.args.get("decode") == "1"
    req_blob, req_decode_note = _maybe_decode_blob(row.req_blob, decode)
    resp_blob, resp_decode_note = _maybe_decode_blob(row.resp_blob, decode)
    req_text = _safe_text(req_blob)
    resp_text = _safe_text(resp_blob)

    # Parse response headers from the raw blob for the summariser
    headers, status_line, body = _split_http(row.resp_blob)
    summary = summarise_response(ResponseSummaryInput(
        status=row.status, reason="",
        headers=headers, body=body, duration_ms=row.duration_ms,
    ))
    plugin_copy_as = [h.name for h in get_registry().active_copy_as()]
    send_targets = available_targets(row.req_blob)

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
        find_body=find_body,
        find_req=panes_by_prefix.get("req"),
        find_resp=panes_by_prefix.get("resp"),
        decode=decode,
        has_encoded_body=has_encoded_body,
        req_decode_note=req_decode_note,
        resp_decode_note=resp_decode_note,
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


def _decompress_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    enc = encoding.strip().lower()
    if not enc or enc == "identity":
        return body, ""
    if enc in ("gzip", "x-gzip"):
        return gzip.decompress(body), enc
    if enc == "deflate":
        try:
            return zlib.decompress(body), enc
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS), enc
    if enc == "br":
        import brotli  # type: ignore[import-not-found]
        return brotli.decompress(body), enc
    if enc == "zstd":
        import zstandard  # type: ignore[import-not-found]
        return zstandard.ZstdDecompressor().decompress(body), enc
    raise ValueError(f"unsupported Content-Encoding: {encoding!r}")


_SUPPORTED_ENCODINGS = {"gzip", "x-gzip", "deflate", "br", "zstd"}


def _has_supported_encoding(raw: bytes) -> bool:
    """True when the blob's headers list a Content-Encoding we can decode.
    Used to gate the Body-display toggle on the detail page so it only
    appears when it would actually do something."""
    if not raw:
        return False
    headers, _, _ = _split_http(raw)
    for k, v in headers:
        if k.lower() != "content-encoding":
            continue
        for piece in v.split(","):
            tok = piece.strip().lower()
            if tok and tok != "identity" and tok in _SUPPORTED_ENCODINGS:
                return True
    return False


def _maybe_decode_blob(raw: bytes, decode: bool) -> tuple[bytes, str]:
    """Return (blob_for_display, status_note). When ``decode`` is true and a
    supported ``Content-Encoding`` is present, the body is decompressed and
    the headers rewritten (``Content-Encoding`` removed,
    ``Content-Length`` updated). On failure the original blob is returned
    with a status_note explaining why."""
    if not decode or not raw:
        return raw, ""
    headers, status_line, body = _split_http(raw)
    enc_values = [v for k, v in headers if k.lower() == "content-encoding"]
    if not enc_values:
        return raw, ""
    encodings = [e.strip() for e in ",".join(enc_values).split(",") if e.strip()]
    out_body = body
    applied: list[str] = []
    for enc in reversed(encodings):
        try:
            out_body, applied_name = _decompress_body(out_body, enc)
            if applied_name:
                applied.append(applied_name)
        except (OSError, zlib.error, ValueError) as exc:
            return raw, f"decode failed ({enc}): {exc.__class__.__name__}"
        except ImportError:
            return raw, f"{enc} decoder not installed (pip install brotli zstandard)"
    new_headers: list[tuple[str, str]] = []
    for k, v in headers:
        kl = k.lower()
        if kl == "content-encoding":
            continue
        if kl == "content-length":
            new_headers.append((k, str(len(out_body))))
        else:
            new_headers.append((k, v))
    if not any(k.lower() == "content-length" for k, _ in new_headers):
        new_headers.append(("Content-Length", str(len(out_body))))
    head = status_line + "\r\n" + "\r\n".join(f"{k}: {v}" for k, v in new_headers)
    return head.encode("latin-1", errors="replace") + b"\r\n\r\n" + out_body, (
        " + ".join(applied) + f" → {len(out_body)} bytes"
    )


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
