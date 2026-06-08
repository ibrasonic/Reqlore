"""curl_cffi-based engine for JA3/JA4 TLS-fingerprint impersonation.

Opt-in via ``pip install reqlore[impersonate]``. When the library is
present, ``send()`` returns a normal Reqlore Response after sending the
request through curl_cffi.requests with a chosen browser profile
(``chrome120`` by default). Without the library, ``send()`` returns a
Response whose ``error`` describes the missing dep — never crashes.

This engine is intentionally NOT made default. It only matters when a
target fingerprints the TLS handshake.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import Request, Response, Timings

try:
    from curl_cffi import requests as _curl_requests   # type: ignore[import-not-found]
    CFFI_AVAILABLE = True
except Exception:
    CFFI_AVAILABLE = False


SUPPORTED_PROFILES = (
    "chrome120", "chrome119", "chrome116", "chrome110",
    "safari17_0", "safari15_5", "firefox109", "firefox102",
)


def send(req: Request, *, profile: str = "chrome120", timeout: float = 15.0,
          verify: bool = True) -> Response:
    if not CFFI_AVAILABLE:
        return Response(
            status=0, engine="curl-cffi",
            error="curl_cffi is not installed. "
                  "Run `pip install reqlore[impersonate]`.",
        )
    if profile not in SUPPORTED_PROFILES:
        profile = "chrome120"

    parsed = urlparse(req.url)
    headers_dict: dict[str, str] = {}
    for k, v in req.headers:
        if k.lower() in ("host", "content-length", "connection"):
            continue
        headers_dict[k] = v

    try:
        import time
        t0 = time.perf_counter()
        r = _curl_requests.request(
            req.method, req.url,
            headers=headers_dict, data=req.body or None,
            timeout=timeout, verify=verify, impersonate=profile,
            allow_redirects=False,
        )
        elapsed = int((time.perf_counter() - t0) * 1000)
        # curl_cffi.requests.Response.headers is a CaseInsensitiveDict.
        out_headers: list[tuple[str, str]] = []
        try:
            for k, v in r.headers.items():
                out_headers.append((str(k), str(v)))
        except Exception:
            pass
        body = r.content if isinstance(r.content, (bytes, bytearray)) else \
               (r.text.encode("utf-8", "replace") if r.text else b"")
        return Response(
            status=r.status_code,
            headers=out_headers,
            body=bytes(body),
            http_version="2" if "h2" in str(getattr(r, "http_version", "")) else "1.1",
            timings=Timings(total_ms=elapsed),
            engine=f"curl-cffi:{profile}",
        )
    except Exception as exc:
        return Response(status=0, engine=f"curl-cffi:{profile}",
                         error=f"curl_cffi transport error: {exc}")
