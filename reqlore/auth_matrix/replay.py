"""Replay one history row under one session and decide the verdict.

This module is engine-agnostic: it takes a ``sender`` callable so
unit tests can swap in a deterministic stub. The default sender used
by the runner is :func:`reqlore.engines.httpx_engine.send`.

The replay flow is:

1. Parse the raw history request blob into a :class:`Request`.
2. Strip / overlay headers per the session (see
   :func:`reqlore.auth_matrix.sessions.apply_session_to_request`).
3. Optionally re-add a fresh CSRF token (skipped by default;
   operators can flip the toggle on a per-run basis).
4. Call the sender.
5. Normalise the response body + baseline body, compute similarity.
6. Decide the verdict.

The response and request blobs handed back to the storage layer are
size-capped so a single 10 MB binary download can't blow out the
project file.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..engines import Request, Response, Timings
from .normaliser import (
    Normaliser,
    body_similarity_pct,
    default_normaliser,
    normalise_body,
)
from .sessions import Session, apply_session_to_request
from .verdict import Verdict, decide_verdict

_MAX_BLOB_LEN = 64 * 1024     # 64 KiB cap on stored req/resp blobs
_BODY_SNIP_LEN = 4 * 1024     # 4 KiB snippet handed to verdict heuristics


SenderFn = Callable[[Request], Response]


@dataclass
class ReplayOutcome:
    """The full picture from one (history, session) replay.

    Stored largely as-is in :data:`auth_matrix_cells`, except for the
    blobs which are truncated to :data:`_MAX_BLOB_LEN`.
    """

    session_id: int
    history_id: int
    status: int
    body_len: int
    duration_ms: int
    similarity_pct: int
    verdict: Verdict
    request_blob: bytes = b""
    response_blob: bytes = b""
    error: str = ""
    response_headers: list[tuple[str, str]] = field(default_factory=list)


def _parse_raw_request(raw: bytes) -> Request:
    """Tolerant parse of a raw HTTP request blob into a Request.
    Never raises — malformed history rows should still produce a
    "tried to replay, got transport error" outcome rather than a
    runner crash."""
    if not raw:
        return Request(method="GET", url="/")
    sep = raw.find(b"\r\n\r\n")
    head = raw[:sep] if sep >= 0 else raw
    body = raw[sep + 4:] if sep >= 0 else b""
    try:
        lines = head.decode("latin-1", errors="replace").split("\r\n")
    except Exception:
        lines = []
    request_line = lines[0].split(" ", 2) if lines else []
    method = request_line[0] if request_line else "GET"
    path = request_line[1] if len(request_line) > 1 else "/"
    host = ""
    scheme_hint = "http"
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        if k.lower() == "host":
            host = v
        headers.append((k, v))

    if path.startswith("http://") or path.startswith("https://"):
        url = path
    elif host:
        # Without a Forwarded/X-Forwarded-Proto header we can't be
        # sure of the scheme; default to https when the original
        # request advertised a TLS-only Cookie attribute, else http.
        for k, v in headers:
            if k.lower() == "cookie" and "secure" in v.lower():
                scheme_hint = "https"
                break
        url = f"{scheme_hint}://{host}{path}"
    else:
        url = path
    return Request(
        method=method or "GET",
        url=url,
        headers=headers,
        body=body,
    )


def _serialise_request(req: Request) -> bytes:
    """Best-effort raw bytes representation of a Request for storage."""
    try:
        path = req.url
        if "://" in path:
            # Keep only the path+query for the request line — matches
            # the format add_history captures from the proxy.
            after_scheme = path.split("://", 1)[1]
            slash = after_scheme.find("/")
            path = after_scheme[slash:] if slash >= 0 else "/"
        head = f"{req.method} {path} HTTP/{req.http_version}\r\n"
        for k, v in req.headers:
            head += f"{k}: {v}\r\n"
        return head.encode("latin-1", errors="replace") + b"\r\n" + bytes(req.body or b"")
    except Exception:
        return b""


def _serialise_response(resp: Response) -> bytes:
    try:
        head = f"HTTP/{resp.http_version} {resp.status} {resp.reason}\r\n"
        for k, v in resp.headers:
            head += f"{k}: {v}\r\n"
        return head.encode("latin-1", errors="replace") + b"\r\n" + bytes(resp.body or b"")
    except Exception:
        return b""


def _truncate(blob: bytes, cap: int = _MAX_BLOB_LEN) -> bytes:
    if not blob:
        return b""
    if len(blob) <= cap:
        return blob
    marker = b"\r\n... [truncated] ...\r\n"
    return blob[:cap - len(marker)] + marker


def replay_history_with_session(
    *,
    raw_history_request: bytes,
    session: Session,
    sender: SenderFn,
    history_id: int = 0,
    baseline_status: int | None = None,
    baseline_body: bytes | str = b"",
    normaliser: Normaliser | None = None,
    similarity_floor: int = 80,
    privileged_floor: int = 90,
) -> ReplayOutcome:
    """Replay one history row under ``session`` and decide the verdict.

    ``baseline_body`` and ``baseline_status`` are the captured
    original response for this request. When omitted the verdict
    will be ``no-baseline``.
    """
    norm = normaliser if normaliser is not None else default_normaliser()
    req = _parse_raw_request(raw_history_request)
    new_headers = apply_session_to_request(req.headers, session)
    replayed = Request(
        method=req.method,
        url=req.url,
        headers=new_headers,
        body=req.body,
        http_version=req.http_version,
        extras=dict(req.extras),
    )

    try:
        resp = sender(replayed)
    except Exception as exc:  # last-ditch safety net
        resp = Response(
            status=0, reason="", headers=[], body=b"",
            timings=Timings(),
            engine="error",
            error=f"{type(exc).__name__}: {exc}",
        )

    baseline_text = normalise_body(baseline_body or b"", norm)
    candidate_text = normalise_body(resp.body or b"", norm)
    sim = body_similarity_pct(baseline_text, candidate_text)

    location = ""
    content_type = ""
    for k, v in resp.headers:
        low = k.lower()
        if low == "location" and not location:
            location = v
        elif low == "content-type" and not content_type:
            content_type = v
    body_snip = candidate_text[:_BODY_SNIP_LEN]

    verdict = decide_verdict(
        baseline_status=baseline_status,
        candidate_status=int(resp.status or 0),
        similarity_pct=sim,
        similarity_floor=similarity_floor,
        privileged_floor=privileged_floor,
        candidate_location=location,
        candidate_content_type=content_type,
        candidate_body_snip=body_snip,
        candidate_error=resp.error or "",
    )

    return ReplayOutcome(
        session_id=int(session.id or 0),
        history_id=int(history_id),
        status=int(resp.status or 0),
        body_len=len(resp.body or b""),
        duration_ms=int(resp.timings.total_ms if resp.timings else 0),
        similarity_pct=sim,
        verdict=verdict,
        request_blob=_truncate(_serialise_request(replayed)),
        response_blob=_truncate(_serialise_response(resp)),
        error=resp.error or "",
        response_headers=list(resp.headers),
    )
