"""Shared helpers for the report renderers.

These are intentionally pure-Python and side-effect-free so they can be unit-
tested without spinning up a project or a Flask app.
"""
from __future__ import annotations

import datetime as _dt
import shlex
from collections.abc import Iterable

from .. import __version__ as _REQLORE_VERSION

SEV_ORDER = ("critical", "high", "medium", "low", "info")


def utc_now(now: _dt.datetime | None = None) -> _dt.datetime:
    """Return a UTC ``datetime`` for the report timestamp. Accepts an explicit
    ``now`` to make report generation deterministic in tests."""
    if now is not None:
        if now.tzinfo is None:
            return now.replace(tzinfo=_dt.UTC)
        return now.astimezone(_dt.UTC)
    return _dt.datetime.now(_dt.UTC)


def reqlore_version() -> str:
    return _REQLORE_VERSION


def severity_counts(findings: Iterable[dict]) -> dict[str, int]:
    out = dict.fromkeys(SEV_ORDER, 0)
    for f in findings:
        sev = f.get("severity", "info")
        out[sev] = out.get(sev, 0) + 1
    return out


def coverage_rows(rule_summary: Iterable[dict] | None) -> list[dict]:
    """Normalise rule-run summary rows for renderers. Each row is
    ``{"rule_id": str, "fired": int, "evaluated": int}``."""
    if not rule_summary:
        return []
    return [
        {
            "rule_id": r.get("rule_id", ""),
            "fired": int(r.get("fired", 0)),
            "evaluated": int(r.get("evaluated", 0)),
        }
        for r in rule_summary
        if r.get("rule_id")
    ]


def coverage_rows_by_host(rule_summary: Iterable[dict] | None) -> list[dict]:
    """Normalise per-host rule-run rows for the B.3 coverage view.

    Input rows look like ``{"rule_id", "host", "fired", "evaluated"}`` —
    typically from :meth:`Project.rule_run_summary_by_host`. Empty / missing
    host strings collapse to ``"(unknown)"`` so the renderers always have a
    non-empty label.
    """
    if not rule_summary:
        return []
    return [
        {
            "rule_id": r.get("rule_id", ""),
            "host": (r.get("host") or "").strip() or "(unknown)",
            "fired": int(r.get("fired", 0)),
            "evaluated": int(r.get("evaluated", 0)),
        }
        for r in rule_summary
        if r.get("rule_id")
    ]


def parse_raw_request(blob: bytes) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Best-effort parse of a raw HTTP/1.1 request blob.

    Returns ``(method, path, headers, body)``. ``method`` and ``path`` are
    empty strings if the request line could not be parsed.
    """
    if not blob:
        return "", "", [], b""
    head, sep, body = blob.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = blob.partition(b"\n\n")
    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    if not lines:
        return "", "", [], body
    try:
        request_line = lines[0].decode("ascii", "replace")
    except Exception:  # pragma: no cover - decode("ascii", "replace") shouldn't raise
        return "", "", [], body
    parts = request_line.split(" ")
    method = parts[0] if len(parts) >= 2 else ""
    path = parts[1] if len(parts) >= 2 else ""
    headers: list[tuple[str, str]] = []
    for raw in lines[1:]:
        if not raw:
            continue
        try:
            line = raw.decode("utf-8", "replace")
        except (UnicodeDecodeError, AttributeError):  # noqa: S112  # pragma: no cover  # skip malformed header line, continue with remaining headers
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return method, path, headers, body


def curl_from_reproduction(repro: dict | None) -> str:
    """Synthesise a single-line ``curl`` command from a reproduction record.

    Returns an empty string if there is nothing usable to reproduce.
    """
    if not repro:
        return ""
    url = repro.get("url") or ""
    method = (repro.get("method") or "GET").upper()
    blob = repro.get("request_blob") or b""
    _m, _p, headers, body = parse_raw_request(blob)
    if not url:
        return ""
    parts = ["curl", "-i", "-X", method]
    seen: set[str] = set()
    for name, value in headers:
        low = name.lower()
        if low in {"host", "content-length"}:
            continue
        if low in seen:
            continue
        seen.add(low)
        parts.extend(["-H", f"{name}: {value}"])
    if body:
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = body.decode("utf-8", "replace")
        parts.extend(["--data-binary", body_text])
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)
