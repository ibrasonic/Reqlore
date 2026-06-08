"""httpx-backed engine — the default.

Handles HTTP/1.1 + HTTP/2, mTLS, proxies, redirects.
"""
from __future__ import annotations

import time

import httpx

from . import Request, Response, Timings


def send(
    req: Request,
    *,
    http2: bool | None = None,
    follow_redirects: bool = False,
    verify: bool | str = True,
    proxy: str | None = None,
    timeout: float = 30.0,
) -> Response:
    """Send `req` via httpx and return a normalised `Response`."""
    use_http2 = (req.http_version == "2") if http2 is None else http2

    headers = list(req.headers)

    client_kwargs: dict = {
        "http2": use_http2,
        "verify": verify,
        "timeout": timeout,
        "follow_redirects": follow_redirects,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    start = time.monotonic()
    try:
        with httpx.Client(**client_kwargs) as client:
            httpx_req = client.build_request(
                req.method.upper(),
                req.url,
                headers=headers,
                content=req.body if req.body else None,
            )
            t_send = time.monotonic()
            resp = client.send(httpx_req, stream=False)
            t_done = time.monotonic()

            timings = Timings(
                ttfb_ms=int((t_done - t_send) * 1000),
                total_ms=int((t_done - start) * 1000),
            )
            return Response(
                status=resp.status_code,
                reason=resp.reason_phrase,
                headers=list(resp.headers.items()),
                body=resp.content,
                http_version=resp.http_version.split("/")[-1] if resp.http_version else "1.1",
                timings=timings,
                engine="httpx",
            )
    except httpx.HTTPError as e:
        return Response(
            status=0,
            reason="",
            headers=[],
            body=b"",
            timings=Timings(total_ms=int((time.monotonic() - start) * 1000)),
            engine="httpx",
            error=f"{type(e).__name__}: {e}",
        )
