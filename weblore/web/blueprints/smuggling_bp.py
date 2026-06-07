"""Request-smuggling helpers blueprint.

UI flow: enter the target URL, pick a technique, optionally pick a
smuggled method/path; we render the raw HTTP/1.1 bytes for download.
Live "detect" is intentionally separate so users don't accidentally fire
payloads at a target during exploration.
"""
from __future__ import annotations

from flask import Blueprint, Response as FlaskResponse, render_template, request

from ...smuggling import PAYLOAD_BUILDERS

bp = Blueprint("smuggling", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    url = request.form.get("url", "")
    technique = request.form.get("technique", "cl.te")
    smuggled_method = request.form.get("smuggled_method", "GET")
    smuggled_path = request.form.get("smuggled_path", "/admin")
    payload = None
    raw_text = ""
    download = request.form.get("download") == "1"

    if request.method == "POST" and url.strip():
        builder = PAYLOAD_BUILDERS.get(technique.lower())
        if builder:
            payload = builder(url, smuggled_method=smuggled_method,
                                smuggled_path=smuggled_path)
            raw_text = payload.bytes_.decode("latin-1")
        if download and payload:
            return FlaskResponse(
                payload.bytes_, mimetype="application/octet-stream",
                headers={"Content-Disposition":
                          f'attachment; filename="weblore-{technique}.bin"'},
            )

    return render_template(
        "smuggling/index.html",
        url=url, technique=technique,
        smuggled_method=smuggled_method, smuggled_path=smuggled_path,
        payload=payload, raw_text=raw_text,
    )
