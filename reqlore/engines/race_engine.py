"""Synchronized request-group engine for race-condition attacks.

Two transports, both firing N requests as close to simultaneously as the
protocol allows — the difference between a *moderate* race tester and a
*best-in-class* one:

* :func:`single_packet_h2` — the HTTP/2 **single-packet attack**
  (PortSwigger, 2023). All N requests share one TLS connection; each is
  primed on the wire minus its final ``DATA`` frame (``END_STREAM``
  withheld), then the N final frames are flushed in a **single**
  ``sendall`` — one TCP segment. The server therefore dequeues every
  request on the same event-loop tick, eliminating network jitter
  entirely: the requests arrive within microseconds of each other
  regardless of round-trip time. This is the strongest primitive there
  is for hitting a server-side race window.

* :func:`last_byte_sync_h1` — the HTTP/1.1 equivalent for origins that do
  not speak HTTP/2. Open N connections, send each request minus its final
  byte, gate every worker on a :class:`threading.Barrier`, then release
  the final byte on every socket back-to-back. Jitter is bound by the
  local socket loop (tens of microseconds) instead of N full round-trips.

:func:`send_group` picks the strongest available transport automatically:
single-packet when the origin negotiates HTTP/2 over ALPN, otherwise
last-byte-sync.

The module is deliberately transport-only. Payload rendering, result
persistence and finding emission stay in :mod:`reqlore.intruder`.
"""
from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import Request, Response
from .raw_engine import _build_raw, _parse_response

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import (
        DataReceived,
        ResponseReceived,
        StreamEnded,
        StreamReset,
    )

    H2_AVAILABLE = True
except Exception:  # pragma: no cover - h2 is a hard dependency
    H2_AVAILABLE = False


class RaceUnsupported(RuntimeError):
    """Raised when a transport cannot be used for the given target.

    Callers (notably :func:`send_group` in ``auto`` mode) treat this as a
    signal to fall back to a weaker-but-available transport rather than a
    hard failure.
    """


@dataclass
class RaceItem:
    """One request in a synchronized group and its outcome."""

    index: int
    request: Request
    response: Response | None = None
    send_offset_us: int = 0   # microseconds from group release to final flush
    recv_offset_us: int = 0   # microseconds from group release to full response
    error: str = ""


@dataclass
class RaceResult:
    """Outcome of a synchronized send group."""

    transport: str            # "single-packet" | "last-byte" | "none"
    items: list[RaceItem] = field(default_factory=list)
    release_window_us: int = 0   # spread between first and last final flush
    negotiated_alpn: str = ""
    note: str = ""


# --------------------------------------------------------------------------
# HTTP/2 single-packet
# --------------------------------------------------------------------------

_H2_STRIP = {
    "host", "connection", "keep-alive", "proxy-connection",
    "transfer-encoding", "upgrade",
}


def _authority(url: str) -> str:
    p = urlsplit(url)
    host = p.hostname or ""
    if p.port and p.port not in (80, 443):
        return f"{host}:{p.port}"
    return host


def _h2_headers(req: Request, authority: str) -> list[tuple[str, str]]:
    p = urlsplit(req.url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    scheme = p.scheme or "https"
    hdrs: list[tuple[str, str]] = [
        (":method", req.method.upper()),
        (":authority", authority),
        (":scheme", scheme),
        (":path", path),
    ]
    has_cl = False
    for k, v in req.headers:
        lk = k.lower()
        if lk in _H2_STRIP:
            continue
        if lk == "content-length":
            has_cl = True
        hdrs.append((lk, v))
    if req.body and not has_cl:
        hdrs.append(("content-length", str(len(req.body))))
    return hdrs


def _prime_and_release_frames(
    conn: H2Connection, requests: list[Request], authority: str,
) -> tuple[list[int], bytes, bytes]:
    """Build the two byte blobs of a single-packet attack.

    ``prime`` opens every stream and sends all but the final byte of each
    request with ``END_STREAM`` withheld. ``release`` carries the final
    byte (or an empty ``DATA`` frame for body-less requests) with
    ``END_STREAM`` set for every stream, so flushing it in one ``sendall``
    completes all N requests simultaneously.

    Pure with respect to the socket: operates only on ``conn``. This makes
    the single-packet framing unit-testable against a server-side
    ``H2Connection`` with no network.
    """
    stream_ids: list[int] = []
    for req in requests:
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        conn.send_headers(sid, _h2_headers(req, authority), end_stream=False)
        body = req.body or b""
        if len(body) > 1:
            conn.send_data(sid, body[:-1], end_stream=False)
    prime = conn.data_to_send()

    for sid, req in zip(stream_ids, requests, strict=True):
        body = req.body or b""
        last = body[-1:] if body else b""
        conn.send_data(sid, last, end_stream=True)
    release = conn.data_to_send()
    return stream_ids, prime, release


def _read_h2(
    conn: H2Connection, sock: socket.socket, stream_ids: list[int],
    items: list[RaceItem], timeout: float, t0: float,
) -> None:
    by_stream = {sid: i for i, sid in enumerate(stream_ids)}
    status: dict[int, int] = dict.fromkeys(stream_ids, 0)
    headers: dict[int, list[tuple[str, str]]] = {s: [] for s in stream_ids}
    body: dict[int, bytearray] = {s: bytearray() for s in stream_ids}
    pending = set(stream_ids)

    sock.settimeout(timeout)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        try:
            data = sock.recv(65536)
        except (TimeoutError, OSError):
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            sid = getattr(ev, "stream_id", None)
            if sid is None:
                continue
            if isinstance(ev, ResponseReceived):
                for k, v in ev.headers:
                    kk = k.decode() if isinstance(k, bytes) else k
                    vv = v.decode() if isinstance(v, bytes) else v
                    if kk == ":status":
                        with contextlib.suppress(ValueError):
                            status[sid] = int(vv)
                    elif not kk.startswith(":"):
                        headers[sid].append((kk, vv))
            elif isinstance(ev, DataReceived):
                body[sid] += ev.data
                if ev.flow_controlled_length:
                    conn.acknowledge_received_data(
                        ev.flow_controlled_length, sid)
            elif isinstance(ev, (StreamEnded, StreamReset)) and sid in pending:
                i = by_stream[sid]
                items[i].recv_offset_us = int((time.perf_counter() - t0) * 1e6)
                items[i].response = Response(
                    status=status[sid], headers=headers[sid],
                    body=bytes(body[sid]), http_version="2",
                    engine="race-h2",
                )
                pending.discard(sid)
        out = conn.data_to_send()
        if out:
            with contextlib.suppress(OSError):
                sock.sendall(out)

    for sid in pending:
        i = by_stream[sid]
        if items[i].response is None:
            items[i].error = "no response (timeout)"


def single_packet_h2(
    requests: list[Request], *, verify: bool = True, timeout: float = 15.0,
    settle_ms: int = 100,
) -> RaceResult:
    """Fire ``requests`` as one HTTP/2 single-packet group.

    Raises :class:`RaceUnsupported` if the target is not HTTPS or does not
    negotiate ``h2`` over ALPN, so ``auto`` mode can fall back.
    """
    if not H2_AVAILABLE:
        raise RaceUnsupported("h2 library not available")
    if not requests:
        return RaceResult(transport="single-packet")
    p = urlsplit(requests[0].url)
    if p.scheme != "https":
        raise RaceUnsupported("single-packet requires https (ALPN h2)")
    host = p.hostname or ""
    port = p.port or 443
    authority = _authority(requests[0].url)

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    items = [RaceItem(index=i, request=r) for i, r in enumerate(requests)]
    sock: socket.socket | None = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=host)
        if sock.selected_alpn_protocol() != "h2":
            raise RaceUnsupported("origin did not negotiate HTTP/2 over ALPN")

        conn = H2Connection(
            config=H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        stream_ids, prime, release = _prime_and_release_frames(
            conn, requests, authority)
        sock.sendall(prime)
        # Let the primed frames drain to the server before the sync flush.
        time.sleep(max(0, settle_ms) / 1000.0)

        t0 = time.perf_counter()
        sock.sendall(release)  # THE single packet — one syscall, one segment
        _read_h2(conn, sock, stream_ids, items, timeout, t0)
        return RaceResult(
            transport="single-packet", items=items, release_window_us=0,
            negotiated_alpn="h2",
        )
    except RaceUnsupported:
        raise
    except (OSError, ssl.SSLError) as exc:
        for it in items:
            if it.response is None and not it.error:
                it.error = f"{type(exc).__name__}: {exc}"
        return RaceResult(
            transport="single-packet", items=items, negotiated_alpn="h2",
            note=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()


# --------------------------------------------------------------------------
# HTTP/1.1 last-byte synchronization
# --------------------------------------------------------------------------

def _open_socket(
    req: Request, verify: bool, timeout: float,
) -> socket.socket:
    p = urlsplit(req.url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    sock: socket.socket = socket.create_connection((host, port), timeout=timeout)
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _read_h1(sock: socket.socket, timeout: float) -> Response:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            buf = sock.recv(65536)
        except (TimeoutError, OSError):
            break
        if not buf:
            break
        chunks.append(buf)
    return _parse_response(b"".join(chunks))


def last_byte_sync_h1(
    requests: list[Request], *, verify: bool = True, timeout: float = 15.0,
) -> RaceResult:
    """Fire ``requests`` via the HTTP/1.1 last-byte-sync technique.

    One connection and one worker thread per request. Every worker opens
    its connection and sends the request minus its final byte, then blocks
    on a shared barrier. When the last worker arrives, all are released
    together and flush their final byte back-to-back — the tightest
    synchronization achievable without HTTP/2 multiplexing.
    """
    n = len(requests)
    items = [RaceItem(index=i, request=r) for i, r in enumerate(requests)]
    if n == 0:
        return RaceResult(transport="last-byte")

    barrier = threading.Barrier(n)
    releases: list[float] = [0.0] * n

    def worker(i: int) -> None:
        req = requests[i]
        raw = _build_raw(req)
        head, last = (raw[:-1], raw[-1:]) if raw else (b"", b"")
        sock: socket.socket | None = None
        try:
            sock = _open_socket(req, verify, timeout)
            sock.sendall(head)
        except (OSError, ssl.SSLError) as exc:
            items[i].error = f"{type(exc).__name__}: {exc}"
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.abort()
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()
            return
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            items[i].error = items[i].error or "group aborted before release"
            with contextlib.suppress(OSError):
                sock.close()
            return
        t0 = time.perf_counter()
        try:
            sock.sendall(last)
            releases[i] = time.perf_counter()
            items[i].send_offset_us = int((releases[i] - t0) * 1e6)
            resp = _read_h1(sock, timeout)
            items[i].response = resp
            items[i].recv_offset_us = int((time.perf_counter() - t0) * 1e6)
        except (OSError, ssl.SSLError) as exc:
            items[i].error = f"{type(exc).__name__}: {exc}"
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    threads = [
        threading.Thread(target=worker, args=(i,), daemon=True)
        for i in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 5)

    fired = [r for r in releases if r > 0]
    window = int((max(fired) - min(fired)) * 1e6) if len(fired) > 1 else 0
    return RaceResult(transport="last-byte", items=items,
                      release_window_us=window)


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def send_group(
    requests: list[Request], *, mode: str = "auto", verify: bool = True,
    timeout: float = 15.0, settle_ms: int = 100,
) -> RaceResult:
    """Send ``requests`` as one synchronized group.

    ``mode``:
      * ``"single-packet"`` — force HTTP/2 single-packet (errors surface as
        per-item errors if the origin can't do h2).
      * ``"last-byte"`` — force HTTP/1.1 last-byte-sync.
      * ``"auto"`` (default) — single-packet when the origin is HTTPS and
        negotiates h2, otherwise last-byte-sync.
    """
    reqs = list(requests)
    if not reqs:
        return RaceResult(transport="none")
    if mode == "last-byte":
        return last_byte_sync_h1(reqs, verify=verify, timeout=timeout)
    if mode == "single-packet":
        return single_packet_h2(
            reqs, verify=verify, timeout=timeout, settle_ms=settle_ms)
    # auto
    if urlsplit(reqs[0].url).scheme == "https" and H2_AVAILABLE:
        with contextlib.suppress(RaceUnsupported):
            return single_packet_h2(
                reqs, verify=verify, timeout=timeout, settle_ms=settle_ms)
    return last_byte_sync_h1(reqs, verify=verify, timeout=timeout)
