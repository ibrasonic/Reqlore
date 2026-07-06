"""Phase 5 — unified insertion-point engine for the active scanner.

Burp's active scanner walks every request through a single iterator that
yields **insertion points** — places a payload can be substituted. Each
insertion point carries enough metadata (type, name, current value,
content-type) to drive a rule's mutation and rebuild the request without
the rule re-parsing the wire format.

Pre-Phase-5 reqlore inlined the parse/mutate logic inside every active
check (``ctx.query_pairs()`` + ``_replace_query_value`` in 19 places,
each subtly different). That duplicated work and made it hard to add new
insertion-point families (JSON values vs keys, XML attributes, path
segments, header names, cookie nested encoders) without touching every
rule.

This module ships an additive engine — existing checks continue to use
their inline helpers, and new (Phase 6+) rules can opt into
:func:`iter_insertion_points` for free.

Design notes:

- Pure functions; no I/O, no globals beyond the in-module constants.
- Every iterator yields ``InsertionPoint`` dataclasses — never mutates
  the source context.
- :func:`mutate` rebuilds a :class:`reqlore.engines.Request` from a
  point + a new value, scrubbing hop-by-hop headers (httpx re-derives
  ``Host`` / ``Content-Length`` etc. on the wire).
- Nested-encoding detection is depth-capped at
  :data:`_MAX_NESTED_DEPTH` (3 by default) so a zip-bomb-style payload
  can't recurse forever.
- :class:`InsertionPointCache` is keyed on
  ``(rule_id, ip_type, name, content_type)`` so identical points across
  history rows aren't probed twice in the same audit.

Threat model:

- The engine never trusts the row blob — every decode path is wrapped
  and silently skips on failure (returns ``[]`` rather than raising).
- Base64 / hex / JSON decoding is bounded by
  :data:`_MAX_NESTED_DEPTH`; values larger than
  :data:`_MAX_VALUE_BYTES` are skipped (DoS guard).
- ``mutate`` only emits the four kinds it knows about. An unknown type
  raises ``ValueError`` — a check can't accidentally synthesise a
  malformed wire request.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse as up
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Literal

from ..engines import Request

# ---------------------------------------------------------------------------
# Constants

_MAX_NESTED_DEPTH = 3
"""Max levels of nested decoding (e.g. base64 → urlencoded → json)."""

_MAX_VALUE_BYTES = 64 * 1024
"""Reject candidate values larger than this before attempting decode."""

_DEFAULT_PER_ROW_CAP = 200
"""Default :class:`InsertionPointCache` cap applied per history row."""

# Header names the engine treats as Burp-style "user-injectable" headers.
# We do **not** include ``Host`` / ``Cookie`` / ``Authorization`` here
# (those have dedicated insertion-point types or are owned by other
# parts of the scanner; we don't want to double-cover and double-charge
# the probe budget).
_INJECTABLE_HEADER_NAMES = (
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
)


IPType = Literal[
    "query",          # URL ?key=value
    "form",           # application/x-www-form-urlencoded body
    "cookie",         # Cookie: header value
    "header",         # injectable HTTP header (UA, Referer, X-Forwarded-*, …)
    "json-value",     # JSON body — a string value at a flat path
    "json-key",       # JSON body — a key name at a flat path
    "xml-value",      # XML body — element text
    "xml-attr",       # XML body — attribute value
    "path-segment",   # URL path /<seg>/…
    "path-filename",  # URL path basename (last segment after final /)
    "param-name",     # query / form parameter NAME (not value)
    "body",           # entire raw body (XXE-style whole-body replacement)
    "multipart-value",     # multipart/form-data — text part value
    "multipart-filename",  # multipart/form-data — filename
]


NestedEncoding = Literal[
    "none",
    "base64",
    "hex",
    "url",
    "json",
]


# ---------------------------------------------------------------------------
# Data class


@dataclass(frozen=True)
class InsertionPoint:
    """A single mutable position in a request.

    ``name`` is the parameter / header / element name (for ``body``
    and ``path-filename`` it's the literal ``""`` / ``"filename"``
    string respectively). ``value`` is the **decoded** current value
    — if ``nested_encoding`` is non-``"none"`` the value has already
    been through that decoder so a rule can mutate the payload
    directly without re-encoding it.

    ``location`` is the Burp-style location label most active rules
    already use (``"query"`` / ``"form"`` / ``"header"`` / ``"cookie"``
    / ``"json"`` / ``"xml"`` / ``"path"`` / ``"body"`` /
    ``"multipart"``).
    """

    ip_type: IPType
    name: str
    value: str
    location: str
    content_type: str = ""
    nested_encoding: NestedEncoding = "none"
    # ``path`` is a JSON-pointer-like dotted path inside the parsed
    # tree, used by ``json-value`` / ``xml-attr`` so two distinct
    # locations with the same leaf name stay distinguishable. Empty
    # for flat insertion points.
    path: str = ""


# ---------------------------------------------------------------------------
# Iterators


def _ct_of(headers: Iterable[tuple[str, str]]) -> str:
    for k, v in headers:
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def _iter_query(url: str) -> Iterator[InsertionPoint]:
    parts = url.split("?", 1)
    if len(parts) < 2 or not parts[1]:
        return
    for chunk in parts[1].split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        else:
            k, v = chunk, ""
        try:
            dk = up.unquote(k)
            dv = up.unquote(v)
        except (UnicodeDecodeError, ValueError):  # noqa: S112  # skip malformed URL-encoded query pair, continue with remaining pairs
            continue
        yield InsertionPoint(
            ip_type="query", name=dk, value=dv, location="query",
        )
        # Param-name is its own point — Burp's "parameter-name attack"
        # surface. Yielded after the value so default iteration order
        # is still value-first.
        yield InsertionPoint(
            ip_type="param-name", name=dk, value=dk, location="query",
        )


def _iter_form(body: bytes, ct: str) -> Iterator[InsertionPoint]:
    if "x-www-form-urlencoded" not in ct or not body:
        return
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return
    for chunk in text.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        else:
            k, v = chunk, ""
        try:
            dk = up.unquote(k)
            dv = up.unquote(v)
        except (UnicodeDecodeError, ValueError):  # noqa: S112  # skip malformed URL-encoded form pair, continue with remaining pairs
            continue
        yield InsertionPoint(
            ip_type="form", name=dk, value=dv,
            location="form", content_type=ct,
        )
        yield InsertionPoint(
            ip_type="param-name", name=dk, value=dk,
            location="form", content_type=ct,
        )


def _iter_cookies(headers: Iterable[tuple[str, str]]) -> Iterator[InsertionPoint]:
    for k, v in headers:
        if k.lower() != "cookie":
            continue
        for chunk in (v or "").split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" in chunk:
                ck, cv = chunk.split("=", 1)
            else:
                ck, cv = chunk, ""
            yield InsertionPoint(
                ip_type="cookie", name=ck.strip(), value=cv.strip(),
                location="cookie",
            )


def _iter_headers(headers: Iterable[tuple[str, str]]) -> Iterator[InsertionPoint]:
    seen: set[str] = set()
    for k, v in headers:
        lk = k.lower()
        # Catch standard injectable headers + any custom X-*.
        is_injectable = lk in _INJECTABLE_HEADER_NAMES or lk.startswith("x-")
        if not is_injectable:
            continue
        # ``Host`` is *not* injectable here (separate Host-header rule).
        if lk in ("host", "cookie", "authorization"):
            continue
        # Yield only the first occurrence per name (deterministic).
        if lk in seen:
            continue
        seen.add(lk)
        yield InsertionPoint(
            ip_type="header", name=k, value=v or "", location="header",
        )


def _walk_json(node, prefix: str = "") -> Iterator[tuple[str, str, str]]:
    """Yield ``(path, kind, value)`` triples where ``kind`` is
    ``"value"`` or ``"key"``. Only string-valued leaves and dict keys
    are emitted — numbers/booleans/None are skipped to keep the
    insertion-point list focused on injection-relevant text."""
    if isinstance(node, dict):
        for k, v in node.items():
            child = f"{prefix}.{k}" if prefix else k
            yield (child, "key", k)
            yield from _walk_json(v, child)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_json(v, f"{prefix}[{i}]")
    elif isinstance(node, str):
        yield (prefix, "value", node)


def _iter_json(body: bytes, ct: str) -> Iterator[InsertionPoint]:
    if "json" not in ct or not body:
        return
    try:
        decoded = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return
    for path, kind, val in _walk_json(decoded):
        if kind == "key":
            yield InsertionPoint(
                ip_type="json-key", name=path, value=val,
                location="json", content_type=ct, path=path,
            )
        else:
            yield InsertionPoint(
                ip_type="json-value", name=path, value=val,
                location="json", content_type=ct, path=path,
            )


# ---- XML — element text and attribute values via a small regex pass.
#
# We deliberately avoid pulling in ``defusedxml`` or ``lxml`` just for
# enumeration: a recorded request body may be a partial / malformed XML
# fragment, and lxml's strictness rejects too many real-world payloads.
# The regex below is *enumeration only* — mutation uses byte
# replacement, never a serialiser, so we never need a parsed tree.

_XML_ELEMENT_TEXT_RE = re.compile(
    rb"<([A-Za-z_][A-Za-z0-9_:\-]*)([^>/]*)>([^<>]+)</\1>",
)
_XML_ATTR_RE = re.compile(
    rb"""([A-Za-z_][A-Za-z0-9_:\-]*)\s*=\s*"([^"<]*)"|"""
    rb"""([A-Za-z_][A-Za-z0-9_:\-]*)\s*=\s*'([^'<]*)'""",
)


def _iter_xml(body: bytes, ct: str) -> Iterator[InsertionPoint]:
    if not body or ("xml" not in ct and not body.lstrip().startswith(b"<?xml")):
        return
    text = body
    for m in _XML_ELEMENT_TEXT_RE.finditer(text):
        try:
            elem = m.group(1).decode("ascii")
            val = m.group(3).decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):  # noqa: S112  # skip XML element whose tag name isn't ASCII, continue with remaining matches
            continue
        yield InsertionPoint(
            ip_type="xml-value", name=elem, value=val,
            location="xml", content_type=ct, path=elem,
        )
    for m in _XML_ATTR_RE.finditer(text):
        try:
            attr = (m.group(1) or m.group(3) or b"").decode("ascii")
            val = (m.group(2) or m.group(4) or b"").decode(
                "utf-8", errors="replace",
            )
        except (UnicodeDecodeError, AttributeError):  # noqa: S112  # skip XML attribute whose name isn't ASCII, continue with remaining matches
            continue
        if not attr:
            continue
        yield InsertionPoint(
            ip_type="xml-attr", name=attr, value=val,
            location="xml", content_type=ct, path=attr,
        )


def _iter_path(url: str) -> Iterator[InsertionPoint]:
    pr = up.urlparse(url)
    path = pr.path or "/"
    segments = [s for s in path.split("/") if s]
    if not segments:
        return
    # Each segment is an insertion point; the last segment is also
    # exposed as ``path-filename`` for file-based fuzzing (extension
    # swap, classic Burp ``Path-filename`` insertion).
    for i, seg in enumerate(segments):
        yield InsertionPoint(
            ip_type="path-segment", name=str(i), value=seg,
            location="path", path=str(i),
        )
    yield InsertionPoint(
        ip_type="path-filename", name="filename",
        value=segments[-1], location="path",
    )


def iter_insertion_points(
    *,
    url: str,
    method: str,
    headers: list[tuple[str, str]],
    body: bytes,
    kinds: Iterable[IPType] | None = None,
) -> list[InsertionPoint]:
    """Walk every insertion point in a recorded request.

    Returns a list (not a generator) so callers can ``len()`` it for
    the dry-run estimate without consuming the iterator. The order is
    deterministic: query → form → cookie → header → json → xml →
    path → multipart.

    ``kinds`` (optional) restricts to a subset of :data:`IPType`
    values.
    """
    want: set[str] | None = set(kinds) if kinds is not None else None
    ct = _ct_of(headers)
    out: list[InsertionPoint] = []

    def _take(it: Iterable[InsertionPoint]) -> None:
        for ip in it:
            if want is not None and ip.ip_type not in want:
                continue
            out.append(ip)

    _take(_iter_query(url))
    _take(_iter_form(body, ct))
    _take(_iter_cookies(headers))
    _take(_iter_headers(headers))
    _take(_iter_json(body, ct))
    _take(_iter_xml(body, ct))
    _take(_iter_path(url))
    # Entire-body insertion is exposed once per request (XXE, raw JSON
    # full-body replacements, etc.) — only when there's actually a body
    # to replace.
    if body and (want is None or "body" in want):
        try:
            decoded_body = body.decode("utf-8", errors="replace")
        except Exception:
            decoded_body = ""
        out.append(InsertionPoint(
            ip_type="body", name="", value=decoded_body,
            location="body", content_type=ct,
        ))
    return out


# ---------------------------------------------------------------------------
# Nested-encoding detection


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def detect_nested_encoding(value: str, *, depth: int = 0) -> NestedEncoding:
    """Best-effort guess at how a value is wrapped.

    Returns the *outermost* encoding only — chains (base64 → json) are
    out of scope here; callers wanting full chain detection should
    iterate with :func:`peel_encoding`.
    """
    if not value or len(value.encode("utf-8", errors="replace")) > _MAX_VALUE_BYTES:
        return "none"
    if depth >= _MAX_NESTED_DEPTH:
        return "none"
    # URL-encoded? %XX sequences and at least one decodable byte.
    if "%" in value:
        try:
            dec = up.unquote(value)
            if dec != value:
                return "url"
        except (UnicodeDecodeError, ValueError):  # noqa: S110  # expected when value contains malformed percent-escapes; not URL-encoded then
            pass
    # JSON?
    s = value.lstrip()
    if s.startswith("{") or s.startswith("["):
        try:
            json.loads(value)
            return "json"
        except (ValueError, UnicodeDecodeError):
            pass
    # Base64? Length multiple of 4 (with padding), valid charset, ≥12 chars.
    if (len(value) >= 12 and len(value) % 4 == 0
            and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value)):
        try:
            base64.b64decode(value, validate=True)
            return "base64"
        except (binascii.Error, ValueError):
            pass
    # Hex? Even length, hex charset, ≥8 chars.
    if len(value) >= 8 and len(value) % 2 == 0 and _HEX_RE.fullmatch(value):
        return "hex"
    return "none"


def peel_encoding(value: str) -> tuple[str, list[NestedEncoding]]:
    """Repeatedly strip outer encodings up to :data:`_MAX_NESTED_DEPTH`
    levels. Returns ``(decoded_value, [layers])`` where ``layers[0]``
    is the outermost encoding and ``layers[-1]`` is the deepest.

    Used by rules that want to mutate the *inner* payload (e.g.
    base64-in-cookie SQLi). Never raises — on a decode failure the
    function returns whatever has been peeled so far.
    """
    layers: list[NestedEncoding] = []
    cur = value
    for _ in range(_MAX_NESTED_DEPTH):
        enc = detect_nested_encoding(cur, depth=len(layers))
        if enc == "none":
            break
        try:
            if enc == "url":
                cur = up.unquote(cur)
            elif enc == "base64":
                cur = base64.b64decode(cur, validate=True).decode(
                    "utf-8", errors="replace",
                )
            elif enc == "hex":
                cur = bytes.fromhex(cur).decode("utf-8", errors="replace")
            elif enc == "json":
                cur = json.dumps(json.loads(cur))
        except Exception:
            break
        layers.append(enc)
    return cur, layers


# ---------------------------------------------------------------------------
# Mutation


def _scrub_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Mirror of ``active._scrub_headers``; duplicated here so this
    module has no upward import dependency on ``active``."""
    drop = {"host", "content-length", "transfer-encoding", "connection"}
    return [(k, v) for k, v in headers if k.lower() not in drop]


def _replace_query_value(url: str, key: str, new: str) -> str:
    pr = up.urlparse(url)
    pairs = up.parse_qsl(pr.query, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, new))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((key, new))
    return up.urlunparse(pr._replace(query=up.urlencode(out, doseq=True)))


def _replace_query_key(url: str, old_key: str, new_key: str) -> str:
    pr = up.urlparse(url)
    pairs = up.parse_qsl(pr.query, keep_blank_values=True)
    out = [(new_key if k == old_key else k, v) for k, v in pairs]
    return up.urlunparse(pr._replace(query=up.urlencode(out, doseq=True)))


def _replace_path_segment(url: str, index: int, new: str) -> str:
    pr = up.urlparse(url)
    segments = (pr.path or "/").split("/")
    # Path looks like ``["", "a", "b", "c"]`` for ``/a/b/c``; non-empty
    # segments live at indexes 1..len-1.
    non_empty = [i for i, s in enumerate(segments) if s]
    if not (0 <= index < len(non_empty)):
        return url
    segments[non_empty[index]] = up.quote(new, safe="")
    return up.urlunparse(pr._replace(path="/".join(segments)))


def _replace_path_filename(url: str, new: str) -> str:
    pr = up.urlparse(url)
    parts = (pr.path or "/").rsplit("/", 1)
    if len(parts) == 2:
        parts[1] = up.quote(new, safe="")
        return up.urlunparse(pr._replace(path="/".join(parts)))
    return url


def _replace_cookie_value(headers: list[tuple[str, str]],
                            name: str, new: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k, v in headers:
        if k.lower() != "cookie":
            out.append((k, v))
            continue
        chunks = []
        replaced = False
        for chunk in (v or "").split(";"):
            stripped = chunk.strip()
            if not stripped:
                continue
            if "=" in stripped:
                ck, _cv = stripped.split("=", 1)
            else:
                ck = stripped
            if ck.strip() == name and not replaced:
                chunks.append(f"{name}={new}")
                replaced = True
            else:
                chunks.append(stripped)
        if not replaced:
            chunks.append(f"{name}={new}")
        out.append((k, "; ".join(chunks)))
    return out


def _replace_header_value(headers: list[tuple[str, str]],
                            name: str, new: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in headers:
        if not replaced and k.lower() == name.lower():
            out.append((k, new))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, new))
    return out


def _replace_form_value(body: bytes, key: str, new: str) -> bytes:
    if not body:
        return up.urlencode([(key, new)]).encode("utf-8")
    new_bytes = up.quote_from_bytes(new.encode("utf-8"), safe="").encode("ascii")
    key_b = up.quote_from_bytes(key.encode("utf-8"), safe="").encode("ascii")
    out_chunks: list[bytes] = []
    replaced = False
    for chunk in body.split(b"&"):
        if replaced or not chunk:
            out_chunks.append(chunk)
            continue
        kpart, sep, _ = chunk.partition(b"=")
        try:
            decoded_key = up.unquote_to_bytes(kpart).decode("utf-8")
        except UnicodeDecodeError:
            decoded_key = kpart.decode("latin-1", errors="replace")
        if decoded_key == key:
            out_chunks.append(key_b + b"=" + new_bytes if sep else key_b)
            replaced = True
        else:
            out_chunks.append(chunk)
    if not replaced:
        out_chunks.append(key_b + b"=" + new_bytes)
    return b"&".join(out_chunks)


def _replace_json_value(body: bytes, path: str, new: str) -> bytes:
    try:
        tree = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    # Walk the dotted path. ``foo.bar[0].baz`` → ``foo`` → ``bar`` → 0 → ``baz``.
    tokens = _split_json_path(path)
    if not tokens:
        return body
    node = tree
    for tok in tokens[:-1]:
        try:
            node = node[tok]
        except (KeyError, IndexError, TypeError):
            return body
    last = tokens[-1]
    try:
        node[last] = new
    except (TypeError, IndexError):
        return body
    return json.dumps(tree, separators=(",", ":")).encode("utf-8")


def _split_json_path(path: str) -> list:
    """``foo.bar[0].baz`` → ``["foo", "bar", 0, "baz"]``."""
    tokens: list = []
    buf = ""
    i = 0
    while i < len(path):
        c = path[i]
        if c == ".":
            if buf:
                tokens.append(buf)
                buf = ""
        elif c == "[":
            if buf:
                tokens.append(buf)
                buf = ""
            j = path.find("]", i)
            if j == -1:
                return []
            try:
                tokens.append(int(path[i + 1:j]))
            except ValueError:
                return []
            i = j
        else:
            buf += c
        i += 1
    if buf:
        tokens.append(buf)
    return tokens


def mutate(
    *,
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes,
    point: InsertionPoint,
    new_value: str,
) -> Request:
    """Build a mutated :class:`Request` from a base request + an
    insertion point + a new value.

    Pure function: never mutates its arguments. Unknown ``ip_type``
    raises ``ValueError`` so a bug in a rule can't silently produce a
    wire-malformed request.
    """
    scrubbed = _scrub_headers(headers)
    if point.ip_type == "query":
        return Request(
            method=method,
            url=_replace_query_value(url, point.name, new_value),
            headers=list(scrubbed), body=body,
        )
    if point.ip_type == "form":
        return Request(
            method=method, url=url, headers=list(scrubbed),
            body=_replace_form_value(body, point.name, new_value),
        )
    if point.ip_type == "cookie":
        return Request(
            method=method, url=url,
            headers=_replace_cookie_value(scrubbed, point.name, new_value),
            body=body,
        )
    if point.ip_type == "header":
        return Request(
            method=method, url=url,
            headers=_replace_header_value(scrubbed, point.name, new_value),
            body=body,
        )
    if point.ip_type == "json-value":
        return Request(
            method=method, url=url, headers=list(scrubbed),
            body=_replace_json_value(body, point.path or point.name, new_value),
        )
    if point.ip_type == "json-key":
        # Renaming a key is intentionally not supported — Burp's
        # parameter-name attack on JSON keys is rare in practice and
        # raises round-trip ambiguity (duplicate keys). Raise so a
        # buggy rule doesn't silently no-op.
        raise ValueError("json-key mutation not implemented")
    if point.ip_type == "xml-value":
        # Replace the inner text of the first matching element. Byte
        # replacement keeps the rest of the document byte-identical.
        pat = re.compile(
            rb"<" + re.escape(point.name.encode("ascii"))
            + rb"([^>/]*)>([^<>]+)</" + re.escape(point.name.encode("ascii")) + rb">",
        )
        nv = new_value.encode("utf-8", errors="replace")
        new_body = pat.sub(rb"<" + point.name.encode("ascii")
                              + rb"\1>" + nv + rb"</"
                              + point.name.encode("ascii") + rb">",
                              body, count=1)
        return Request(
            method=method, url=url, headers=list(scrubbed), body=new_body,
        )
    if point.ip_type == "xml-attr":
        # Replace the first occurrence of ``name="…"`` or ``name='…'``.
        attr = re.escape(point.name.encode("ascii"))
        pat = re.compile(attr + rb"""(\s*=\s*)(?:"([^"]*)"|'([^']*)')""")
        nv = new_value.encode("utf-8", errors="replace").replace(b'"', b"&quot;")
        new_body = pat.sub(
            point.name.encode("ascii") + b'="' + nv + b'"', body, count=1,
        )
        return Request(
            method=method, url=url, headers=list(scrubbed), body=new_body,
        )
    if point.ip_type == "path-segment":
        return Request(
            method=method,
            url=_replace_path_segment(url, int(point.name), new_value),
            headers=list(scrubbed), body=body,
        )
    if point.ip_type == "path-filename":
        return Request(
            method=method,
            url=_replace_path_filename(url, new_value),
            headers=list(scrubbed), body=body,
        )
    if point.ip_type == "param-name":
        # Param-name mutation is location-aware: query vs form
        # rebuild a different wire artefact.
        if point.location == "query":
            return Request(
                method=method,
                url=_replace_query_key(url, point.name, new_value),
                headers=list(scrubbed), body=body,
            )
        if point.location == "form":
            # Reuse the form helper to delete the old key + add the
            # new one; do this in two steps so we don't have to grow
            # the public surface.
            tmp = _replace_form_value(body, point.name, "")
            # Now strip the empty placeholder and insert the new key.
            new_body = tmp.replace(
                up.quote_from_bytes(point.name.encode("utf-8"),
                                       safe="").encode("ascii") + b"=",
                up.quote_from_bytes(new_value.encode("utf-8"),
                                       safe="").encode("ascii") + b"=",
                1,
            )
            return Request(
                method=method, url=url, headers=list(scrubbed), body=new_body,
            )
        raise ValueError(f"param-name on unsupported location {point.location}")
    if point.ip_type == "body":
        return Request(
            method=method, url=url, headers=list(scrubbed),
            body=new_value.encode("utf-8", errors="replace"),
        )
    raise ValueError(f"unknown insertion-point type: {point.ip_type}")


# ---------------------------------------------------------------------------
# Cache


@dataclass
class InsertionPointCache:
    """Per-audit-run cache of which insertion points have already been
    probed by which rule. Keyed on
    ``(rule_id, ip_type, name, content_type)`` so identical points
    that recur across many history rows (think: a session cookie or
    a CSRF token on every POST) are only audited once per rule.

    The cache is **append-only** within an audit; an active rule
    checks ``seen(...)`` before claiming a probe slot and calls
    ``mark(...)`` after the probe is sent. ``cap`` defaults to 200 to
    bound memory in pathological corpora.
    """

    cap: int = _DEFAULT_PER_ROW_CAP
    _seen: set[tuple[str, str, str, str]] = field(default_factory=set)
    _evictions: int = 0
    # Phase 11 — frequency telemetry. ``_probes`` counts every time a
    # rule sent at least one probe against a given insertion point,
    # and ``_fires`` counts every time that pairing actually produced
    # a finding. The consolidation layer uses
    # ``probes - fires`` to decide whether a point should drop to
    # lightweight mode (Burp's "insertion point seen N times without
    # firing → skip the intrusive tier" heuristic).
    _probes: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    _fires: dict[tuple[str, str, str, str], int] = field(default_factory=dict)

    def key(self, *, rule_id: str, point: InsertionPoint) -> tuple[str, str, str, str]:
        return (rule_id, point.ip_type, point.name, point.content_type)

    def seen(self, *, rule_id: str, point: InsertionPoint) -> bool:
        return self.key(rule_id=rule_id, point=point) in self._seen

    def mark(self, *, rule_id: str, point: InsertionPoint) -> bool:
        """Reserve a slot. Returns ``False`` if the cap is exhausted
        — the caller should skip the probe and surface a
        ``"insertion_point_cap"`` reason in coverage telemetry."""
        if len(self._seen) >= self.cap:
            self._evictions += 1
            return False
        self._seen.add(self.key(rule_id=rule_id, point=point))
        return True

    @property
    def evictions(self) -> int:
        return self._evictions

    def __len__(self) -> int:
        return len(self._seen)

    # ---------------- Phase 11 — probe / fire counters ----------------

    def record_probe(self, *, rule_id: str, point: InsertionPoint) -> None:
        """Increment the probe counter for this ``(rule_id, point)``.
        Called *every* time the rule actually transmits a probe (not
        just when it claims the cache slot)."""
        k = self.key(rule_id=rule_id, point=point)
        self._probes[k] = self._probes.get(k, 0) + 1

    def record_fire(self, *, rule_id: str, point: InsertionPoint) -> None:
        """Increment the fire counter for this ``(rule_id, point)``.
        Called when a probe against this point produced a finding."""
        k = self.key(rule_id=rule_id, point=point)
        self._fires[k] = self._fires.get(k, 0) + 1

    def probe_count(self, *, rule_id: str, point: InsertionPoint) -> int:
        return self._probes.get(self.key(rule_id=rule_id, point=point), 0)

    def fire_count(self, *, rule_id: str, point: InsertionPoint) -> int:
        return self._fires.get(self.key(rule_id=rule_id, point=point), 0)


# ---------------------------------------------------------------------------
# Payload-relocation matrix


# Burp's matrix: which (from, to) pairs make sense for relocation. We
# expose this as a constant so rules / Phase-6 checks can drive
# cross-location probing (e.g. SQLi from query to body) without
# rebuilding the parser code.
RELOCATION_MATRIX: tuple[tuple[str, str], ...] = (
    ("query", "form"),
    ("query", "cookie"),
    ("form", "query"),
    ("form", "cookie"),
    ("cookie", "query"),
    ("cookie", "form"),
)


def relocate(
    *,
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes,
    name: str,
    value: str,
    from_loc: str,
    to_loc: str,
) -> Request:
    """Move a single ``name=value`` pair from ``from_loc`` to
    ``to_loc``. The original copy is **left in place** — Burp's
    relocation attack is additive (test whether the destination
    endpoint also honours the param), not destructive. Callers that
    want the source removed should do so explicitly.

    Raises ``ValueError`` for any pair not in :data:`RELOCATION_MATRIX`.
    """
    if (from_loc, to_loc) not in RELOCATION_MATRIX:
        raise ValueError(
            f"relocation {from_loc} -> {to_loc} not in matrix"
        )
    scrubbed = _scrub_headers(headers)
    new_url = url
    new_headers = list(scrubbed)
    new_body = body
    if to_loc == "query":
        # Append; never overwrite a pre-existing key.
        new_url = _append_query(new_url, name, value)
    elif to_loc == "form":
        ct = _ct_of(scrubbed)
        if "x-www-form-urlencoded" not in ct:
            # Force the content-type; otherwise the destination has
            # no parser for the relocated pair.
            new_headers = _replace_header_value(
                new_headers, "Content-Type",
                "application/x-www-form-urlencoded",
            )
        new_body = _append_form(new_body, name, value)
    elif to_loc == "cookie":
        new_headers = _append_cookie(new_headers, name, value)
    return Request(
        method=method, url=new_url, headers=new_headers, body=new_body,
    )


def _append_query(url: str, key: str, value: str) -> str:
    pr = up.urlparse(url)
    pairs = up.parse_qsl(pr.query, keep_blank_values=True)
    pairs.append((key, value))
    return up.urlunparse(pr._replace(query=up.urlencode(pairs, doseq=True)))


def _append_form(body: bytes, key: str, value: str) -> bytes:
    pair = up.urlencode([(key, value)]).encode("utf-8")
    if not body:
        return pair
    return body + b"&" + pair


def _append_cookie(headers: list[tuple[str, str]], name: str,
                    value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    appended = False
    for k, v in headers:
        if not appended and k.lower() == "cookie":
            sep = "; " if v else ""
            out.append((k, f"{v}{sep}{name}={value}"))
            appended = True
        else:
            out.append((k, v))
    if not appended:
        out.append(("Cookie", f"{name}={value}"))
    return out
