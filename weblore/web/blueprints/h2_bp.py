"""HTTP/2 frame inspector + crafter blueprint."""
from __future__ import annotations

from flask import Blueprint, render_template, request

from ...h2_tool import (
    build_goaway, build_ping, build_rst_stream, build_settings,
    build_window_update, parse_frames, parse_hex, to_hex,
)

bp = Blueprint("h2", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    hex_text = request.form.get("hex", "")
    action = request.form.get("action", "")
    stream = None
    built_hex = ""
    builder_err = ""

    if action == "parse" and hex_text.strip():
        try:
            data = parse_hex(hex_text)
            stream = parse_frames(data)
        except Exception as exc:
            builder_err = f"parse failed: {exc}"

    if action == "build":
        try:
            built_hex = _build_from_form(request.form)
        except Exception as exc:
            builder_err = f"build failed: {exc}"

    return render_template("h2/index.html",
                            hex_text=hex_text, stream=stream,
                            built_hex=built_hex, builder_err=builder_err)


def _build_from_form(form) -> str:
    kind = form.get("frame", "settings")
    if kind == "settings":
        ack = form.get("ack") == "on"
        params: list[tuple[int, int]] = []
        # Up to six (id,value) pairs from the form.
        for n in range(1, 7):
            pid = form.get(f"sid{n}", "").strip()
            val = form.get(f"sval{n}", "").strip()
            if pid and val:
                params.append((int(pid), int(val)))
        data = build_settings(params, ack=ack)
    elif kind == "ping":
        opaque = (form.get("opaque", "weblore!") or "").encode()
        ack = form.get("ack") == "on"
        data = build_ping(opaque, ack=ack)
    elif kind == "goaway":
        last = int(form.get("last_stream_id", "0") or 0)
        code = int(form.get("error_code", "0") or 0)
        debug = (form.get("debug", "") or "").encode()
        data = build_goaway(last, code, debug)
    elif kind == "rst":
        sid = int(form.get("stream_id", "0") or 0)
        code = int(form.get("error_code", "8") or 8)
        data = build_rst_stream(sid, code)
    elif kind == "winupdate":
        sid = int(form.get("stream_id", "0") or 0)
        inc = int(form.get("increment", "65535") or 65535)
        data = build_window_update(sid, inc)
    else:
        raise ValueError(f"unknown frame kind {kind!r}")
    return to_hex(data)
