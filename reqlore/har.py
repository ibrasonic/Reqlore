"""HAR 1.2 importer — pull browser-recorded sessions into a Reqlore project.

Reads a HAR file (JSON), iterates ``log.entries``, rebuilds raw request and
response bytes for each entry, and inserts a row into the project's history
table via :py:meth:`reqlore.storage.Project.add_history`.

This module is stdlib-only and never sends traffic.

Usage::

    from reqlore.har import import_har_file
    count = import_har_file(project, Path("session.har"))
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass
class HARImportResult:
    entries_seen: int = 0
    entries_imported: int = 0
    entries_skipped: int = 0
    first_history_id: int | None = None
    last_history_id: int | None = None
    errors: list[str] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


def parse_har(raw: bytes | str) -> dict[str, Any]:
    """Parse HAR text and return the top-level dict; raises ValueError on bad input."""
    text: str
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"HAR is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "log" not in data:
        raise ValueError("HAR is missing top-level 'log' key")
    log = data["log"]
    if not isinstance(log, dict) or "entries" not in log:
        raise ValueError("HAR log is missing 'entries'")
    return data


def _hdr_pairs(items: list[dict] | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for h in items or []:
        n = str(h.get("name", "")).strip()
        v = str(h.get("value", ""))
        if n:
            out.append((n, v))
    return out

# M-6: cap HAR base64 body decoding to 50 MiB so a hostile HAR cannot
# trigger an unbounded allocation when imported.
_MAX_HAR_BODY_BYTES = 50 * 1024 * 1024


def _decode_b64_capped(text: str) -> bytes:
    """Base64-decode ``text`` but refuse outputs larger than the cap."""
    # Each 4 base64 characters yields 3 bytes; this lets us short-circuit
    # without ever materialising a giant payload in memory.
    if len(text) // 4 * 3 > _MAX_HAR_BODY_BYTES:
        return text[:_MAX_HAR_BODY_BYTES].encode("utf-8", errors="replace")
    try:
        out = base64.b64decode(text)
    except Exception:
        return text.encode("utf-8", errors="replace")
    if len(out) > _MAX_HAR_BODY_BYTES:
        return out[:_MAX_HAR_BODY_BYTES]
    return out


def _body_bytes(post: dict | None) -> bytes:
    if not post:
        return b""
    text = post.get("text") or ""
    if isinstance(text, str):
        # Some HAR exporters base64-encode binary bodies; respect ``encoding``.
        if post.get("encoding") == "base64":
            return _decode_b64_capped(text)
        return text.encode("utf-8", errors="replace")
    return b""


def _resp_body_bytes(content: dict | None) -> bytes:
    if not content:
        return b""
    text = content.get("text") or ""
    if isinstance(text, str):
        if content.get("encoding") == "base64":
            return _decode_b64_capped(text)
        return text.encode("utf-8", errors="replace")
    return b""


def build_request_blob(method: str, url: str, http_version: str,
                       headers: list[tuple[str, str]], body: bytes) -> bytes:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    head = f"{method} {path} {http_version}\r\n"
    have_host = any(k.lower() == "host" for k, _ in headers)
    if not have_host and parts.netloc:
        head += f"Host: {parts.netloc}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1", errors="replace") + b"\r\n" + body


def build_response_blob(status: int, status_text: str, http_version: str,
                        headers: list[tuple[str, str]], body: bytes) -> bytes:
    head = f"{http_version} {status} {status_text}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1", errors="replace") + b"\r\n" + body


def import_har_data(project, data: dict[str, Any]) -> HARImportResult:
    """Insert each HAR entry as a history row. Pure function over a parsed HAR."""
    result = HARImportResult()
    entries = data["log"].get("entries") or []
    for i, entry in enumerate(entries):
        result.entries_seen += 1
        try:
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            method = (req.get("method") or "GET").upper()
            url = req.get("url") or ""
            if not url:
                result.entries_skipped += 1
                continue
            http_version = req.get("httpVersion") or "HTTP/1.1"
            req_headers = _hdr_pairs(req.get("headers"))
            req_body = _body_bytes(req.get("postData"))
            req_blob = build_request_blob(method, url, http_version,
                                          req_headers, req_body)

            resp_status = int(resp.get("status") or 0)
            resp_status_text = str(resp.get("statusText") or "")
            resp_http_version = resp.get("httpVersion") or "HTTP/1.1"
            resp_headers = _hdr_pairs(resp.get("headers"))
            resp_body = _resp_body_bytes(resp.get("content"))
            resp_blob = build_response_blob(resp_status, resp_status_text,
                                             resp_http_version, resp_headers,
                                             resp_body)

            host = urlsplit(url).netloc
            duration_ms = int(entry.get("time") or 0)
            hid = project.add_history(
                host=host, method=method, url=url, status=resp_status,
                duration_ms=duration_ms, engine="har",
                raw_req=req_blob, raw_resp=resp_blob,
                flags="imported", tags="har",
            )
            if result.first_history_id is None:
                result.first_history_id = hid
            result.last_history_id = hid
            result.entries_imported += 1
        except Exception as exc:  # pragma: no cover -- defensive
            result.entries_skipped += 1
            if result.errors is None:
                result.errors = []
            result.errors.append(f"entry {i}: {type(exc).__name__}: {exc}")
    return result


def import_har_file(project, path: Path) -> HARImportResult:
    raw = Path(path).read_bytes()
    data = parse_har(raw)
    return import_har_data(project, data)
