"""Raw-socket engine for byte-exact requests.

Used when httpx's normalisation hides the bug:

* path traversal that requires literal `../` on the wire
* duplicate / out-of-order / malformed headers
* request smuggling (CL.TE, TE.CL)
* exact header casing / ordering preservation
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlsplit

from . import Request, Response, Timings


def _build_raw(req: Request) -> bytes:
    p = urlsplit(req.url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    headers = list(req.headers)
    if not any(k.lower() == "host" for k, _ in headers):
        host = p.hostname or ""
        if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
            host = f"{host}:{p.port}"
        headers.insert(0, ("Host", host))
    if req.body and not any(k.lower() == "content-length" for k, _ in headers):
        headers.append(("Content-Length", str(len(req.body))))
    if not any(k.lower() == "connection" for k, _ in headers):
        headers.append(("Connection", "close"))

    head = f"{req.method.upper()} {path} HTTP/{req.http_version}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    head += "\r\n"
    return head.encode("latin-1", errors="replace") + req.body


def _parse_response(raw: bytes) -> Response:
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return Response(status=0, body=raw, engine="raw",
                        error="malformed response (no header/body separator)")
    head, body = raw[:sep].decode("latin-1", errors="replace"), raw[sep + 4:]
    lines = head.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    version = parts[0].split("/")[-1] if "/" in parts[0] else "1.1"
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))

    # If Transfer-Encoding: chunked, de-chunk
    te = next((v for k, v in headers if k.lower() == "transfer-encoding"), "")
    if "chunked" in te.lower():
        body = _dechunk(body)

    return Response(
        status=status, reason=reason, headers=headers,
        body=body, http_version=version, engine="raw",
    )


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        crlf = body.find(b"\r\n", i)
        if crlf < 0:
            break
        try:
            size = int(body[i:crlf].split(b";", 1)[0], 16)
        except ValueError:
            break
        i = crlf + 2
        if size == 0:
            break
        out += body[i:i + size]
        i += size + 2
    return bytes(out)


def send(req: Request, *, timeout: float = 30.0, verify: bool = True) -> Response:
    p = urlsplit(req.url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    raw_req = _build_raw(req)

    start = time.monotonic()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw_req)
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            buf = sock.recv(65536)
            if not buf:
                break
            chunks.append(buf)
        raw_resp = b"".join(chunks)
        resp = _parse_response(raw_resp)
        resp.raw_request = raw_req
        resp.timings = Timings(total_ms=int((time.monotonic() - start) * 1000))
        return resp
    except (OSError, ssl.SSLError) as e:
        return Response(
            status=0, body=b"", engine="raw",
            raw_request=raw_req,
            timings=Timings(total_ms=int((time.monotonic() - start) * 1000)),
            error=f"{type(e).__name__}: {e}",
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
