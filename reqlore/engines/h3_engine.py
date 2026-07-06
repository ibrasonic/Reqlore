"""HTTP/3 (QUIC) engine wrapper.

Only an availability probe + a thin synchronous wrapper around
``aioquic`` (optional). Full QUIC connection management is outside the
scope of an a11y-first tool — but exposing a "send this request over
H/3 if possible" affordance keeps the engine list complete.

If ``aioquic`` is missing, ``send()`` returns a ``Response`` whose
``error`` field explains how to opt in. The rest of the code never
crashes for missing the optional dep.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import Request, Response, Timings

try:
    import aioquic  # noqa: F401
    H3_AVAILABLE = True
except Exception:
    H3_AVAILABLE = False


def send(req: Request, *, timeout: float = 15.0,
          verify: bool = True) -> Response:
    """Send a single H/3 request and return a Response.

    The implementation is intentionally minimal: it spins up a one-shot
    asyncio loop, opens a QUIC connection, and reads the first response.
    Streaming / push / 0-RTT are not exposed in the UI.
    """
    if not H3_AVAILABLE:
        return Response(
            status=0, reason="H/3 unavailable",
            engine="h3",
            error=("aioquic is not installed. "
                    "Run `pip install reqlore[h3]` to enable HTTP/3."),
        )
    # Lazy imports so the optional dependency only loads on demand.
    import asyncio
    import ssl

    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    parsed = urlparse(req.url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    if not verify:
        cfg.verify_mode = ssl.CERT_NONE

    headers_h3 = [
        (b":method", req.method.encode()),
        (b":scheme", b"https"),
        (b":authority", host.encode()),
        (b":path", path.encode()),
    ]
    for k, v in req.headers:
        kl = k.lower()
        if kl in ("host", "connection", "transfer-encoding", "content-length"):
            continue
        headers_h3.append((kl.encode(), v.encode()))
    if req.body and not req.header("content-length"):
        headers_h3.append((b"content-length", str(len(req.body)).encode()))

    async def _go() -> Response:
        t0 = asyncio.get_event_loop().time()
        async with connect(host, port, configuration=cfg) as proto:
            h3 = H3Connection(proto._quic)
            stream_id = proto._quic.get_next_available_stream_id()
            h3.send_headers(stream_id, headers_h3, end_stream=not req.body)
            if req.body:
                h3.send_data(stream_id, req.body, end_stream=True)
            proto.transmit()

            status = 0
            resp_headers: list[tuple[str, str]] = []
            body_chunks: list[bytes] = []
            done = asyncio.Event()

            def _on_event(event):
                nonlocal status
                if isinstance(event, HeadersReceived):
                    for k, v in event.headers:
                        ks = k.decode()
                        if ks == ":status":
                            status = int(v)
                        elif not ks.startswith(":"):
                            resp_headers.append((ks, v.decode()))
                    if event.stream_ended:
                        done.set()
                elif isinstance(event, DataReceived):
                    body_chunks.append(event.data)
                    if event.stream_ended:
                        done.set()

            proto._quic_logger = None  # type: ignore[attr-defined]  # aioquic private attr for QLOG output
            proto._http = h3  # type: ignore[attr-defined]  # aioquic private slot for H3 client
            # Replace the http_event_received hook used by aioquic's H3 client.
            orig = proto._http_event_received if hasattr(proto, "_http_event_received") else None
            proto._http_event_received = _on_event  # type: ignore[attr-defined]
            try:
                await asyncio.wait_for(done.wait(), timeout=timeout)
            except TimeoutError:
                pass
            finally:
                if orig:
                    proto._http_event_received = orig  # type: ignore[attr-defined]

            return Response(
                status=status,
                headers=resp_headers,
                body=b"".join(body_chunks),
                http_version="3",
                timings=Timings(total_ms=int((asyncio.get_event_loop().time() - t0) * 1000)),
                engine="h3",
            )

    try:
        return asyncio.run(_go())
    except Exception as exc:
        return Response(status=0, engine="h3", error=f"h3 transport error: {exc}")
