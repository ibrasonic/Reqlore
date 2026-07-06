"""PoC blueprint: generate CSRF + Clickjacking proofs of concept."""
from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    abort,
    g,
    render_template,
    request,
)

from ...poc import clickjacking_poc, csrf_fetch_poc, csrf_form_poc

bp = Blueprint("poc", __name__)


@bp.route("/")
def index():
    hid = request.args.get("from_history")
    row = g.project.get_history(int(hid)) if hid else None
    return render_template("poc/index.html", row=row, hid=hid)


@bp.route("/csrf/<int:hid>")
def csrf(hid: int):
    row = g.project.get_history(hid)
    if not row:
        abort(404)
    method, url, headers, body = _parse_request(row.req_blob, row.url, row.method)
    style = request.args.get("style", "form")
    if style == "fetch":
        poc = csrf_fetch_poc(method, url, headers, body)
    else:
        poc = csrf_form_poc(method, url, headers, body)
    return _download(poc.filename, poc.html)


@bp.route("/clickjacking", methods=["GET", "POST"])
def clickjacking():
    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        overlay = request.form.get("overlay") or "Click here to win!"
        if not url:
            abort(400, description="URL is required.")
        poc = clickjacking_poc(url, overlay_text=overlay)
        return _download(poc.filename, poc.html)
    return render_template("poc/clickjacking.html")


def _download(filename: str, html: str) -> Response:
    return Response(html, mimetype="text/html; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{filename}"'})


def _parse_request(raw: bytes, fallback_url: str,
                    fallback_method: str) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Extract method/url/headers/body from a raw HTTP request blob."""
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return fallback_method, fallback_url, [], b""
    head = raw[:sep].decode("latin-1", errors="replace")
    body = raw[sep + 4:]
    lines = head.split("\r\n")
    start = lines[0] if lines else ""
    parts = start.split(" ", 2)
    method = parts[0] if parts else fallback_method
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return method, fallback_url, headers, body
