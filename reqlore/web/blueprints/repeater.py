"""Repeater — load a request, edit, send, see response."""
from __future__ import annotations

import time
from dataclasses import asdict

from flask import (
    Blueprint, g, redirect, render_template, request, url_for,
)

from .._prg import PRGCache
from ...a11y import (
    ResponseSummaryInput, build_find_context, render_curl, render_fetch,
    render_httpx, render_raw_http, render_requests, summarise_response,
)
from ...engines import Request
from ...engines import curl_cffi_engine, h3_engine, httpx_engine, raw_engine

bp = Blueprint("repeater", __name__)

_cache = PRGCache()


_EMPTY_FORM = {
    "method": "GET", "url": "http://127.0.0.1/", "headers_text": "",
    "body": "", "engine": "httpx", "http_version": "1.1",
}


def _load_from_history(hid: int) -> dict:
    row = g.project.get_history(hid)
    if not row:
        return {}
    raw = row.req_blob
    method, url, headers, body = _parse_raw(raw, row.url, row.method)
    return {
        "method": method, "url": url,
        "headers_text": "\n".join(f"{k}: {v}" for k, v in headers),
        "body": body.decode("utf-8", errors="replace"),
        "engine": "httpx",
    }


def _parse_raw(raw: bytes, fallback_url: str, fallback_method: str):
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return fallback_method, fallback_url, [], raw
    head, body = raw[:sep].decode("latin-1", errors="replace"), raw[sep + 4:]
    lines = head.split("\r\n")
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ", 2)
    method = parts[0] if parts else fallback_method
    path = parts[1] if len(parts) > 1 else "/"
    headers: list[tuple[str, str]] = []
    host = ""
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip(); v = v.strip()
            headers.append((k, v))
            if k.lower() == "host":
                host = v
    # Reconstruct URL from path + Host
    scheme = "http"
    url = f"{scheme}://{host}{path}" if host else fallback_url
    return method, url, headers, body


@bp.route("/", methods=["GET", "POST"])
def index():
    form = dict(_EMPTY_FORM)
    resp_obj = None
    summary = ""
    render_blocks: dict[str, str] = {}

    if request.method == "GET":
        if tok := request.args.get("t"):
            stashed = _cache.get(tok)
            if stashed:
                form = stashed["form"]
                resp_obj = stashed["resp_obj"]
                summary = stashed["summary"]
                render_blocks = stashed["render_blocks"]
        elif hid := request.args.get("from_history"):
            try:
                form.update(_load_from_history(int(hid)))
            except ValueError:
                pass
        elif curl := request.args.get("from_curl"):
            form.update(_load_from_curl(curl))

    if request.method == "POST":
        action = request.form.get("action", "send")
        for k in form:
            if k in request.form:
                form[k] = request.form[k]

        # Body transforms short-circuit: no network, no history, just
        # stash the transformed form and redirect. We intentionally
        # do this BEFORE building Request so an empty/invalid URL doesn't
        # block the user from encoding a payload first.
        if action in ("urlencode_body", "urldecode_body"):
            from urllib.parse import unquote_plus
            if action == "urlencode_body":
                form["body"] = _smart_url_encode_body(form["body"])
            else:
                form["body"] = unquote_plus(form["body"])
            tok = _cache.put({
                "form": form, "resp_obj": None,
                "summary": "", "render_blocks": {},
            })
            return redirect(url_for(".index", t=tok))

        headers = _parse_header_block(form["headers_text"])
        req = Request(
            method=form["method"].strip().upper() or "GET",
            url=form["url"].strip(),
            headers=headers,
            body=form["body"].encode("utf-8"),
            http_version=form["http_version"],
        )
        if action == "send":
            engine = form["engine"]
            # Strip framing headers for normalising engines — they MUST
            # recompute Content-Length from the actual body bytes, otherwise
            # editing the body in the textarea triggers a protocol error
            # (e.g. httpx: "Too much data for declared Content-Length").
            # The raw engine is byte-exact by design and keeps them.
            if engine != "raw":
                send_headers = [
                    (k, v) for k, v in req.headers
                    if k.lower() not in ("content-length", "transfer-encoding")
                ]
                req = Request(
                    method=req.method, url=req.url, headers=send_headers,
                    body=req.body, http_version=req.http_version,
                )
            t0 = time.monotonic()
            try:
                if engine == "raw":
                    resp_obj = raw_engine.send(req, verify=False)
                elif engine == "h3":
                    resp_obj = h3_engine.send(req, verify=False)
                elif engine.startswith("curl-cffi"):
                    profile = (engine.split(":", 1)[1] if ":" in engine
                                else "chrome120")
                    resp_obj = curl_cffi_engine.send(req, profile=profile,
                                                      verify=False)
                else:
                    resp_obj = httpx_engine.send(req, verify=False)
            except Exception as exc:  # noqa: BLE001 - surface ANY engine error to the UI
                # Build a synthetic error response so the page renders the
                # failure inline instead of returning a Flask 500.
                from ...engines import Response as _Resp, Timings as _T
                resp_obj = _Resp(
                    status=0, reason="", headers=[], body=b"",
                    timings=_T(total_ms=int((time.monotonic() - t0) * 1000)),
                    engine=engine,
                    error=f"{type(exc).__name__}: {exc}",
                )
            duration = int((time.monotonic() - t0) * 1000)
            summary = summarise_response(ResponseSummaryInput(
                status=resp_obj.status, reason=resp_obj.reason,
                headers=resp_obj.headers, body=resp_obj.body,
                duration_ms=resp_obj.timings.total_ms or duration,
            ))
            # Save into history too
            raw_req = resp_obj.raw_request or _render_raw_bytes(req)
            raw_resp = _render_raw_response(resp_obj)
            try:
                from urllib.parse import urlsplit
                host = urlsplit(req.url).hostname or ""
            except Exception:  # noqa: BLE001
                host = ""
            g.project.add_history(
                host=host, method=req.method, url=req.url, status=resp_obj.status,
                duration_ms=resp_obj.timings.total_ms or duration,
                engine=f"repeater/{engine}",
                raw_req=raw_req, raw_resp=raw_resp,
            )
        elif action == "render":
            render_blocks = {
                "curl": render_curl(req.method, req.url, req.headers, req.body or None),
                "httpx": render_httpx(req.method, req.url, req.headers, req.body or None),
                "requests": render_requests(req.method, req.url, req.headers, req.body or None),
                "fetch": render_fetch(req.method, req.url, req.headers, req.body or None),
                "raw": render_raw_http(req.method, req.url, req.headers, req.body or None,
                                       req.http_version),
            }

        tok = _cache.put({
            "form": form, "resp_obj": resp_obj,
            "summary": summary, "render_blocks": render_blocks,
        })
        return redirect(url_for(".index", t=tok))

    return render_template(
        "repeater/index.html",
        form=form,
        resp=resp_obj, resp_dict=(asdict(resp_obj) if resp_obj else None),
        resp_headers_text=(_render_headers_text(resp_obj)
                           if resp_obj and not resp_obj.error else ""),
        summary=summary, render_blocks=render_blocks,
        find_resp_body=_build_resp_body_find_ctx(resp_obj),
    )


def _build_resp_body_find_ctx(resp_obj):
    """Return the find-in-text context for the response body, or None
    when there is no response to search.

    The Repeater response body is the high-value find target (the
    request side is editable so the textareas already let the user
    paste/inspect); searching here lets a screen-reader user locate a
    token in a large JSON or HTML payload without reading it line by
    line.
    """
    if not resp_obj or resp_obj.error:
        return None
    body_text = resp_obj.body.decode("utf-8", errors="replace")
    return build_find_context(
        body_text, prefix="resp-body",
        q=request.args.get("resp_body_find", ""),
        regex=request.args.get("resp_body_re") == "1",
        region_label="response body",
        action=url_for("repeater.index"),
    )


def _render_headers_text(resp) -> str:
    """Render the response head as ``HTTP/x.y status reason`` + one
    ``Name: value`` line per header. Single contiguous block so screen
    readers announce each header as a single line instead of one term/
    value pair, matching how the raw HTTP wire format and the History
    / Intercept detail views read.
    """
    head = f"HTTP/{resp.http_version} {resp.status} {resp.reason}\n"
    head += "".join(f"{k}: {v}\n" for k, v in resp.headers)
    return head


def _parse_header_block(s: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in (s or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out


def _smart_url_encode_body(body: str) -> str:
    """Encode form *values* when the body looks like ``k=v&k=v``.

    Form-shaped input (``username=alice&password=p``) keeps its ``&`` and
    outer ``=`` literal and only the values are percent-encoded — so a SQLi
    payload like ``' OR 1=1-- `` substituted into the username value gets
    encoded without breaking the field separators.

    Anything else (JSON, XML, plaintext) falls back to encoding the whole
    string, which is the safe default for non-form bodies.
    """
    from urllib.parse import quote_plus
    if not body:
        return body
    pairs: list[tuple[str, str]] = []
    for chunk in body.split("&"):
        if "=" not in chunk:
            return quote_plus(body, safe="")
        k, _, v = chunk.partition("=")
        # Keys must look like normal form field names — letters, digits,
        # and a small set of structural characters. Anything else means
        # the body probably isn't form-encoded.
        if not k or not all(ch.isalnum() or ch in "_-.[]" for ch in k):
            return quote_plus(body, safe="")
        pairs.append((k, v))
    return "&".join(f"{k}={quote_plus(v, safe='')}" for k, v in pairs)


def _render_raw_bytes(req: Request) -> bytes:
    from urllib.parse import urlsplit
    p = urlsplit(req.url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    head = f"{req.method} {path} HTTP/{req.http_version}\r\n"
    if not any(k.lower() == "host" for k, _ in req.headers):
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        head += f"Host: {host}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in req.headers) + "\r\n"
    return head.encode("latin-1", errors="replace") + (req.body or b"")


def _render_raw_response(resp) -> bytes:
    head = f"HTTP/{resp.http_version} {resp.status} {resp.reason}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in resp.headers) + "\r\n"
    return head.encode("latin-1", errors="replace") + (resp.body or b"")


def _load_from_curl(curl: str) -> dict:
    """Best-effort curl-to-form parser. Supports common -X / -H / -d / URL."""
    import shlex
    method = "GET"
    url = ""
    headers: list[tuple[str, str]] = []
    body = ""
    try:
        toks = shlex.split(curl, posix=True)
    except ValueError:
        toks = curl.split()
    i = 0
    if toks and toks[0] == "curl":
        i = 1
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request"):
            i += 1
            method = toks[i] if i < len(toks) else "GET"
        elif t in ("-H", "--header"):
            i += 1
            if i < len(toks) and ":" in toks[i]:
                k, v = toks[i].split(":", 1)
                headers.append((k.strip(), v.strip()))
        elif t in ("-d", "--data", "--data-raw", "--data-binary"):
            i += 1
            if i < len(toks):
                body = toks[i]
                if method == "GET":
                    method = "POST"
        elif t.startswith("http://") or t.startswith("https://"):
            url = t
        i += 1
    return {
        "method": method, "url": url,
        "headers_text": "\n".join(f"{k}: {v}" for k, v in headers),
        "body": body, "engine": "httpx",
    }
