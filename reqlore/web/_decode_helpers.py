"""HTTP blob decoding helpers shared by the History detail page and the
Proxy intercept detail page.

These functions used to live inside ``reqlore/web/blueprints/history.py``
where they were inlined alongside the ``show()`` route. They were
extracted here when the Proxy detail page grew the same Body-display
toggle, so both blueprints could call into one canonical implementation
(any future bug fix to Content-Encoding handling now benefits both
pages in lockstep).

Nothing here is Flask-aware on purpose: every function takes raw bytes
and returns either bytes or plain Python tuples. That keeps the module
trivially importable from anywhere without dragging request-context
imports along for the ride.
"""
from __future__ import annotations

import gzip
import zlib


_SUPPORTED_ENCODINGS = {"gzip", "x-gzip", "deflate", "br", "zstd"}


def _split_http(raw: bytes) -> tuple[list[tuple[str, str]], str, bytes]:
    """Split a raw HTTP blob into ``(headers, status_line, body)``.

    ``headers`` is a list of ``(name, value)`` tuples preserving the
    original order (so ``Set-Cookie`` repetitions survive). ``status_line``
    is the first line verbatim (request-line for requests, status-line
    for responses). ``body`` is the bytes after the first CRLF-CRLF; if
    no separator is found the whole blob is treated as body and the
    headers list is empty.
    """
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return [], "", raw
    head, body = raw[:sep].decode("latin-1", errors="replace"), raw[sep + 4:]
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return headers, status_line, body


def _decompress_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    """Decompress ``body`` according to a single Content-Encoding token.

    Returns ``(decompressed_bytes, applied_encoding)``. ``identity`` and
    empty encodings are passed through unchanged. Stacked encodings
    (e.g. ``gzip, deflate``) are caller-responsibility: split first and
    invoke this once per token in reverse order.

    Raises ``ValueError`` for unknown tokens, ``ImportError`` if the
    optional ``brotli`` / ``zstandard`` decoder isn't installed, and
    propagates ``zlib.error`` / ``OSError`` from the underlying codec
    on malformed input.
    """
    enc = encoding.strip().lower()
    if not enc or enc == "identity":
        return body, ""
    if enc in ("gzip", "x-gzip"):
        return gzip.decompress(body), enc
    if enc == "deflate":
        try:
            return zlib.decompress(body), enc
        except zlib.error:
            # Some servers send raw DEFLATE without zlib wrapper.
            return zlib.decompress(body, -zlib.MAX_WBITS), enc
    if enc == "br":
        import brotli  # type: ignore[import-not-found]
        return brotli.decompress(body), enc
    if enc == "zstd":
        import zstandard  # type: ignore[import-not-found]
        return zstandard.ZstdDecompressor().decompress(body), enc
    raise ValueError(f"unsupported Content-Encoding: {encoding!r}")


def _has_supported_encoding(raw: bytes) -> bool:
    """True when the blob's headers list a Content-Encoding we can decode.
    Used to gate the Body-display toggle on the detail pages so it only
    appears when it would actually do something."""
    if not raw:
        return False
    headers, _, _ = _split_http(raw)
    for k, v in headers:
        if k.lower() != "content-encoding":
            continue
        for piece in v.split(","):
            tok = piece.strip().lower()
            if tok and tok != "identity" and tok in _SUPPORTED_ENCODINGS:
                return True
    return False


def _current_encoding(raw: bytes) -> str:
    """Return the Content-Encoding header value verbatim (lower-cased,
    joined on '+' when stacked), or 'identity' when the body is plain.
    Used by the Body-display section so the help line can show the
    current state ("Response: gzip") even when the user has not yet
    asked for a decode."""
    if not raw:
        return "identity"
    headers, _, _ = _split_http(raw)
    parts: list[str] = []
    for k, v in headers:
        if k.lower() != "content-encoding":
            continue
        for piece in v.split(","):
            tok = piece.strip().lower()
            if tok and tok != "identity":
                parts.append(tok)
    return " + ".join(parts) if parts else "identity"


def _maybe_decode_blob(raw: bytes, decode: bool) -> tuple[bytes, str]:
    """Return ``(blob_for_display, status_note)``.

    When ``decode`` is true and a supported ``Content-Encoding`` is
    present, the body is decompressed and the headers rewritten
    (``Content-Encoding`` removed, ``Content-Length`` updated). On
    failure the original blob is returned with a ``status_note``
    explaining why (e.g. ``"decode failed (gzip): OSError"``) so the
    UI can surface the error inline instead of silently showing wrong
    bytes.

    Stacked encodings are applied in *reverse* order, matching how
    they were originally piled on (the rightmost listed encoding is
    the innermost wrap, so it must be undone first).
    """
    if not decode or not raw:
        return raw, ""
    headers, status_line, body = _split_http(raw)
    enc_values = [v for k, v in headers if k.lower() == "content-encoding"]
    if not enc_values:
        return raw, ""
    encodings = [e.strip() for e in ",".join(enc_values).split(",") if e.strip()]
    out_body = body
    applied: list[str] = []
    for enc in reversed(encodings):
        try:
            out_body, applied_name = _decompress_body(out_body, enc)
            if applied_name:
                applied.append(applied_name)
        except (OSError, zlib.error, ValueError) as exc:
            return raw, f"decode failed ({enc}): {exc.__class__.__name__}"
        except ImportError:
            return raw, f"{enc} decoder not installed (pip install brotli zstandard)"
    new_headers: list[tuple[str, str]] = []
    for k, v in headers:
        kl = k.lower()
        if kl == "content-encoding":
            continue
        if kl == "content-length":
            new_headers.append((k, str(len(out_body))))
        else:
            new_headers.append((k, v))
    if not any(k.lower() == "content-length" for k, _ in new_headers):
        new_headers.append(("Content-Length", str(len(out_body))))
    head = status_line + "\r\n" + "\r\n".join(f"{k}: {v}" for k, v in new_headers)
    return head.encode("latin-1", errors="replace") + b"\r\n\r\n" + out_body, (
        " + ".join(applied) + f" \u2192 {len(out_body)} bytes"
    )
