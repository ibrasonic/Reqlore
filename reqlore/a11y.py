"""Accessibility helpers.

Pure functions for contrast, plain-language summaries, and "Copy as ..."
renderers. No I/O. Heavily unit-tested.
"""
from __future__ import annotations

import bisect
import difflib
import re
from collections.abc import Iterable
from dataclasses import dataclass

# ---------- WCAG contrast (relative luminance per WCAG 2.1) ----------

def _channel(c: int) -> float:
    s = c / 255.0
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    r, g, b = rgb
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast_ratio(fg: tuple[int, int, int], bg: tuple[int, int, int]) -> float:
    lf, lb = relative_luminance(fg), relative_luminance(bg)
    lighter, darker = max(lf, lb), min(lf, lb)
    return (lighter + 0.05) / (darker + 0.05)


def hex_to_rgb(s: str) -> tuple[int, int, int]:
    s = s.lstrip("#")
    if len(s) == 3:
        s = "".join(c * 2 for c in s)
    return int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)


def wcag_pass(fg: str, bg: str, *, large_text: bool = False) -> tuple[bool, float]:
    ratio = contrast_ratio(hex_to_rgb(fg), hex_to_rgb(bg))
    threshold = 3.0 if large_text else 4.5
    return ratio >= threshold, ratio


def wcag_aaa_pass(fg: str, bg: str, *, large_text: bool = False) -> tuple[bool, float]:
    """WCAG 2.1 SC 1.4.6 Contrast (Enhanced): 7.0 normal / 4.5 large."""
    ratio = contrast_ratio(hex_to_rgb(fg), hex_to_rgb(bg))
    threshold = 4.5 if large_text else 7.0
    return ratio >= threshold, ratio


def wcag_ui_component_pass(fg: str, bg: str) -> tuple[bool, float]:
    """WCAG 2.1 SC 1.4.11 Non-text Contrast: 3.0 minimum for UI parts."""
    ratio = contrast_ratio(hex_to_rgb(fg), hex_to_rgb(bg))
    return ratio >= 3.0, ratio


# ---------- Plain-language summary of an HTTP response ----------

@dataclass
class ResponseSummaryInput:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    duration_ms: int


_REFLECT_CANDIDATE = re.compile(rb"[A-Za-z0-9_\-]{3,32}")


def _header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    target = name.lower()
    for k, v in headers:
        if k.lower() == target:
            return v
    return None


def _all_headers(headers: Iterable[tuple[str, str]], name: str) -> list[str]:
    target = name.lower()
    return [v for k, v in headers if k.lower() == target]


def summarise_response(r: ResponseSummaryInput, *, reflected: list[str] | None = None) -> str:
    bits: list[str] = []
    bits.append(f"HTTP {r.status} {r.reason}".strip())
    size = len(r.body)
    size_str = f"{size} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
    ctype = _header(r.headers, "content-type") or "no content type"
    bits.append(f"{size_str} {ctype.split(';')[0]}")
    bits.append(f"took {r.duration_ms} ms")

    cookies = len(_all_headers(r.headers, "set-cookie"))
    if cookies:
        bits.append(f"sets {cookies} cookie{'s' if cookies != 1 else ''}")

    # Notable security headers
    notable = []
    for h in ("strict-transport-security", "content-security-policy",
              "x-frame-options", "x-content-type-options"):
        if _header(r.headers, h):
            notable.append(h)
    missing = [h for h in ("content-security-policy", "x-content-type-options")
               if _header(r.headers, h) is None]
    if missing:
        bits.append("missing " + ", ".join(missing))

    body_lc = r.body[:65536].lower()
    if b"<script" in body_lc:
        bits.append("body contains script tags")
    if reflected:
        bits.append("reflects parameter " + ", ".join(reflected))

    return "; ".join(bits) + "."


# ---------- "Copy as ..." renderers ----------

def _sh_quote(s: str) -> str:
    if not s:
        return "''"
    if re.match(r"^[A-Za-z0-9_@%+=:,./-]+$", s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def render_curl(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
) -> str:
    parts = ["curl", "-sS", "-i", "-X", method]
    for k, v in headers:
        if k.lower() in ("content-length",):
            continue
        parts += ["-H", _sh_quote(f"{k}: {v}")]
    if body:
        try:
            body_text = body.decode("utf-8")
            parts += ["--data-raw", _sh_quote(body_text)]
        except UnicodeDecodeError:
            parts += ["--data-binary", "@-"]
    parts.append(_sh_quote(url))
    return " ".join(parts)


def render_httpx(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
) -> str:
    h = "[" + ", ".join(f"({k!r}, {v!r})" for k, v in headers) + "]"
    body_kw = ""
    if body:
        try:
            body_kw = f", content={body.decode('utf-8')!r}"
        except UnicodeDecodeError:
            body_kw = f", content={body!r}"
    return (
        f"import httpx\n"
        f"r = httpx.request({method!r}, {url!r}, headers={h}{body_kw})\n"
        f"print(r.status_code, len(r.content))"
    )


def render_requests(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
) -> str:
    headers_dict = "{" + ", ".join(f"{k!r}: {v!r}" for k, v in headers) + "}"
    data_kw = ""
    if body:
        try:
            data_kw = f", data={body.decode('utf-8')!r}"
        except UnicodeDecodeError:
            data_kw = f", data={body!r}"
    return (
        f"import requests\n"
        f"r = requests.request({method!r}, {url!r}, headers={headers_dict}{data_kw})\n"
        f"print(r.status_code, len(r.content))"
    )


def render_fetch(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
) -> str:
    h_obj = "{" + ", ".join(f"{k!r}: {v!r}" for k, v in headers) + "}"
    body_kw = ""
    if body:
        try:
            body_kw = f", body: {body.decode('utf-8')!r}"
        except UnicodeDecodeError:
            body_kw = f", body: new Uint8Array({list(body)})"
    return f"fetch({url!r}, {{ method: {method!r}, headers: {h_obj}{body_kw} }})"


def render_raw_http(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes | None,
    http_version: str = "1.1",
) -> str:
    from urllib.parse import urlsplit

    p = urlsplit(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{method} {path} HTTP/{http_version}"]
    if not any(k.lower() == "host" for k, _ in headers):
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        lines.append(f"Host: {host}")
    lines.extend(f"{k}: {v}" for k, v in headers)
    raw = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        try:
            raw += body.decode("utf-8")
        except UnicodeDecodeError:
            raw += f"<{len(body)} binary bytes>"
    return raw


# ---------- Diff helpers (Comparer module) ----------

@dataclass
class DiffSummary:
    added: int
    removed: int
    changed: int
    same: int

    def sentence(self, label_a: str = "A", label_b: str = "B") -> str:
        parts = []
        if self.added:
            parts.append(f"{self.added} line{'s' if self.added != 1 else ''} only in {label_b}")
        if self.removed:
            parts.append(f"{self.removed} line{'s' if self.removed != 1 else ''} only in {label_a}")
        if self.changed:
            parts.append(f"{self.changed} line{'s' if self.changed != 1 else ''} changed")
        if not parts:
            return "No differences."
        return "; ".join(parts) + f"; {self.same} lines unchanged."


def diff_summary(a: str, b: str) -> DiffSummary:
    """Plain-language line diff summary, screen-reader friendly."""
    sm = difflib.SequenceMatcher(a=a.splitlines(), b=b.splitlines(), autojunk=False)
    added = removed = changed = same = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        la, lb = i2 - i1, j2 - j1
        if tag == "equal":
            same += la
        elif tag == "insert":
            added += lb
        elif tag == "delete":
            removed += la
        elif tag == "replace":
            changed += max(la, lb)
    return DiffSummary(added=added, removed=removed, changed=changed, same=same)


def diff_lines(a: str, b: str) -> list[tuple[str, int | None, int | None, str]]:
    """Per-line diff: list of (tag, line_no_a, line_no_b, text).

    tag in {"same", "add", "del", "chg"}. Line numbers are 1-based or None.
    """
    out: list[tuple[str, int | None, int | None, str]] = []
    al = a.splitlines()
    bl = b.splitlines()
    sm = difflib.SequenceMatcher(a=al, b=bl, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                out.append(("same", i1 + k + 1, j1 + k + 1, al[i1 + k]))
        elif tag == "insert":
            for k in range(j2 - j1):
                out.append(("add", None, j1 + k + 1, bl[j1 + k]))
        elif tag == "delete":
            for k in range(i2 - i1):
                out.append(("del", i1 + k + 1, None, al[i1 + k]))
        elif tag == "replace":
            for k in range(i2 - i1):
                out.append(("del", i1 + k + 1, None, al[i1 + k]))
            for k in range(j2 - j1):
                out.append(("add", None, j1 + k + 1, bl[j1 + k]))
    return out


def pair_diff_lines(
    lines: list[tuple[str, int | None, int | None, str]],
) -> list[tuple[str, int | None, str, int | None, str]]:
    """Re-shape :func:`diff_lines` output into side-by-side rows.

    Input rows are flat — a ``replace`` opcode appears as several ``del``
    rows followed by several ``add`` rows. This helper pairs each block
    of consecutive dels/adds into ``chg`` rows so the UI can render one
    line per change instead of two.

    Each output row is ``(tag, la, a_text, lb, b_text)`` where ``tag`` is
    one of ``"same" | "add" | "del" | "chg"``. Missing sides use ``None``
    for the line number and ``""`` for the text.
    """
    out: list[tuple[str, int | None, str, int | None, str]] = []
    i, n = 0, len(lines)
    while i < n:
        tag, la, lb, text = lines[i]
        if tag == "same":
            out.append(("same", la, text, lb, text))
            i += 1
            continue
        if tag in ("del", "add"):
            dels: list[tuple[str, int | None, int | None, str]] = []
            adds: list[tuple[str, int | None, int | None, str]] = []
            while i < n and lines[i][0] == "del":
                dels.append(lines[i])
                i += 1
            while i < n and lines[i][0] == "add":
                adds.append(lines[i])
                i += 1
            for k in range(max(len(dels), len(adds))):
                d = dels[k] if k < len(dels) else None
                a = adds[k] if k < len(adds) else None
                if d is not None and a is not None:
                    out.append(("chg", d[1], d[3], a[2], a[3]))
                elif d is not None:
                    out.append(("del", d[1], d[3], None, ""))
                else:
                    assert a is not None
                    out.append(("add", None, "", a[2], a[3]))
            continue
        # Unknown tag — emit as-is on A side, defensively.
        out.append((tag, la, text, lb, text))
        i += 1
    return out


def byte_diff_summary(a: bytes, b: bytes) -> str:
    """One-sentence byte-level summary."""
    if a == b:
        return "Identical (both empty)." if not a else f"Identical ({len(a)} bytes)."
    if len(a) == len(b):
        n = sum(1 for x, y in zip(a, b, strict=False) if x != y)
        return f"Same length ({len(a)} bytes); {n} byte{'s' if n != 1 else ''} differ."
    return (f"A is {len(a)} bytes, B is {len(b)} bytes "
            f"(delta {len(b) - len(a):+d}).")


def unified_diff(a: str, b: str, *, label_a: str = "A", label_b: str = "B",
                  context: int = 3) -> str:
    """Return a standard unified-diff patch for ``a`` vs ``b``.

    Thin wrapper around :func:`difflib.unified_diff` that normalises the
    output for downloads: trailing newline guaranteed, no trailing
    whitespace per line, and identical inputs yield ``""`` (so callers
    can decide whether to surface a "no changes" notice instead of
    serving an empty file).
    """
    import difflib
    al = a.splitlines()
    bl = b.splitlines()
    lines = list(difflib.unified_diff(
        al, bl, fromfile=label_a, tofile=label_b,
        lineterm="", n=max(0, context),
    ))
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


# ---------- JWT plain-language summary ----------

def summarise_jwt(header: dict, payload: dict) -> str:
    alg = header.get("alg", "unknown")
    typ = header.get("typ", "JWT")
    bits = [f"{typ} signed with {alg}"]
    if "kid" in header:
        bits.append(f"key id {header['kid']!r}")
    if "iss" in payload:
        bits.append(f"issued by {payload['iss']!r}")
    if "sub" in payload:
        bits.append(f"subject {payload['sub']!r}")
    if "aud" in payload:
        bits.append(f"audience {payload['aud']!r}")
    if "exp" in payload:
        import time as _t
        delta = int(payload["exp"]) - int(_t.time())
        bits.append(f"expires in {delta} seconds" if delta > 0
                    else f"expired {-delta} seconds ago")
    if alg.lower() == "none":
        bits.append("warning: alg=none means no signature is verified")
    return "; ".join(bits) + "."


# ---------- Find-in-text (server-side body search) ----------
#
# Server-side find lets screen-reader and keyboard-only users locate a
# substring inside a long request or response body without having to
# read it linearly. Browser Ctrl+F cannot search inside an editable
# <textarea> (intercept-detail), so the same pattern doubles as the
# only AAA-clean way to point at content there too.
#
# Design notes (see docs/ACCESSIBILITY.md):
#   * Pure function; the view layer collects the query, calls
#     `find_in_text`, then passes the result + `find_segments` to a
#     Jinja macro that emits the form, a role="status" sentence, a
#     skip-list of in-page anchors, and a read-only <pre> with each
#     hit wrapped in <mark id="{prefix}-mN">.
#   * Case-insensitive always; regex opt-in.
#   * Hard cap on matches so a one-character query against a huge
#     body cannot blow up the rendered page.

@dataclass(frozen=True)
class FindMatch:
    """One match returned by :func:`find_in_text`.

    `index` is 1-based and contiguous over the returned matches (so
    template anchors `#prefix-m1`, `#prefix-m2` ... line up with the
    skip-list ordinals a screen reader announces).
    """
    index: int
    start: int
    end: int
    line_no: int
    line_text: str


@dataclass(frozen=True)
class FindResult:
    """Outcome of one find call.

    `truncated` is True when at least one further match exists past
    the `max_matches` cap so the UI can advise the user to narrow the
    query instead of silently hiding hits. `error` is set (and matches
    is empty) when a regex query failed to compile.
    """
    q: str
    regex: bool
    matches: tuple[FindMatch, ...]
    truncated: bool
    error: str | None


@dataclass(frozen=True)
class FindSegment:
    """One run of text in a marked-up body, suitable for template loops.

    `kind` is ``'text'`` for unmatched runs and ``'match'`` for hits;
    `index` is the 1-based match ordinal for match segments (None
    otherwise).
    """
    kind: str
    text: str
    index: int | None


def find_in_text(
    text: str,
    q: str,
    *,
    regex: bool = False,
    max_matches: int = 500,
) -> FindResult:
    """Locate `q` inside `text` and return per-match metadata.

    Matching is always case-insensitive. With ``regex=False`` the query
    is treated as a literal substring (``re.escape``). With
    ``regex=True`` it is compiled as a Python regular expression; on
    `re.error` the returned result carries the error message and an
    empty match tuple.

    Zero-width regex matches are skipped to avoid empty ``<mark>``
    blocks and infinite loops at one offset.
    """
    if not q:
        return FindResult(q="", regex=regex, matches=(),
                          truncated=False, error=None)
    try:
        pat = re.compile(q if regex else re.escape(q), re.IGNORECASE)
    except re.error as exc:
        return FindResult(q=q, regex=regex, matches=(),
                          truncated=False, error=str(exc))

    # Pre-compute line start offsets so each match -> line lookup is
    # O(log n) instead of O(n).
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def _line_at(off: int) -> tuple[int, str]:
        idx = bisect.bisect_right(line_starts, off) - 1
        start = line_starts[idx]
        end = (line_starts[idx + 1] - 1
               if idx + 1 < len(line_starts) else len(text))
        return idx + 1, text[start:end]

    out: list[FindMatch] = []
    truncated = False
    for m in pat.finditer(text):
        if m.start() == m.end():
            continue
        if len(out) >= max_matches:
            truncated = True
            break
        ln, line_text = _line_at(m.start())
        out.append(FindMatch(
            index=len(out) + 1,
            start=m.start(), end=m.end(),
            line_no=ln, line_text=line_text,
        ))
    return FindResult(q=q, regex=regex, matches=tuple(out),
                      truncated=truncated, error=None)


def find_segments(
    text: str,
    matches: tuple[FindMatch, ...] | list[FindMatch],
) -> list[FindSegment]:
    """Split `text` into alternating plain / matched segments.

    The template iterates the result and emits either ``{{ seg.text }}``
    (Jinja auto-escapes) or ``<mark id="prefix-mN">{{ seg.text }}</mark>``
    for matches.
    """
    out: list[FindSegment] = []
    cursor = 0
    for m in matches:
        if cursor < m.start:
            out.append(FindSegment(kind="text",
                                   text=text[cursor:m.start], index=None))
        out.append(FindSegment(kind="match",
                               text=text[m.start:m.end], index=m.index))
        cursor = m.end
    if cursor < len(text):
        out.append(FindSegment(kind="text",
                               text=text[cursor:], index=None))
    return out


def find_status_sentence(result: FindResult, *, region: str = "body") -> str:
    """Return a one-sentence summary suitable for a ``role="status"`` line.

    Empty string when no query has been submitted (so the template can
    skip the region entirely).
    """
    if not result.q:
        return ""
    if result.error:
        return f'Regex error in {region}: {result.error}.'
    n = len(result.matches)
    quoted = f'"{result.q}"'
    if n == 0:
        return f"No matches for {quoted} in {region}."
    if result.truncated:
        return (f"Stopped after {n} matches for {quoted} in {region}; "
                f"refine your search to see them all.")
    word = "match" if n == 1 else "matches"
    return f"{n} {word} for {quoted} in {region}."


def build_find_context(
    text: str,
    *,
    prefix: str,
    q: str,
    regex: bool,
    region_label: str,
    action: str,
) -> dict:
    """Bundle everything the `_find.html` macros need into one dict.

    Views call this once per searchable region. `prefix` namespaces the
    URL params (``{prefix}_find``, ``{prefix}_re``) and the HTML mark
    IDs (``{prefix}-mN``) so a single page can host independent search
    regions without ID or query-string collisions.
    """
    result = find_in_text(text, q, regex=regex)
    segments = find_segments(text, result.matches) if result.q else []
    return {
        "prefix": prefix,
        "q": q or "",
        "regex": bool(regex),
        "result": result,
        "segments": segments,
        "status": find_status_sentence(result, region=region_label),
        "region_label": region_label,
        "action": action,
    }


def build_find_multi(
    panes_input: list,
    *,
    form_prefix: str,
    q: str,
    regex: bool,
    region_label: str,
    action: str,
) -> dict:
    """Multi-pane variant of :func:`build_find_context`.

    One shared search query highlights matches across several
    separately-displayed panes (e.g. Request + Response on the History
    page, Evidence + Payload on the Scanner page). The caller provides
    a list of ``(prefix, region_label, text)`` tuples — empty texts
    are skipped. Each pane gets its own anchor namespace
    (``{pane_prefix}-mN``) so the jump list can link into the correct
    pane and the template can render highlights in-place rather than
    in a duplicated combined block.

    Returns a dict shaped for the ``find_jumps`` / ``find_pane_pre``
    macros plus a ``form`` sub-ctx compatible with ``find_form``.
    """
    panes = []
    total = 0
    truncated = False
    first_error = ""
    for prefix, label, text in panes_input:
        if not text:
            continue
        result = find_in_text(text, q, regex=regex)
        segments = find_segments(text, result.matches) if result.q else []
        panes.append({
            "prefix": prefix,
            "region_label": label,
            "text": text,
            "result": result,
            "segments": segments,
            "matches": result.matches,
        })
        total += len(result.matches)
        truncated = truncated or result.truncated
        if result.error and not first_error:
            first_error = result.error

    if not q:
        status = ""
    elif first_error:
        status = f"Regex error in {region_label}: {first_error}."
    elif total == 0:
        status = f'No matches for "{q}" in {region_label}.'
    elif truncated:
        status = (f'Stopped after {total} matches for "{q}" in {region_label}; '
                  f"refine your search to see them all.")
    else:
        word = "match" if total == 1 else "matches"
        status = f'{total} {word} for "{q}" in {region_label}.'

    return {
        "form": {
            "prefix": form_prefix,
            "q": q or "",
            "regex": bool(regex),
            "action": action,
            "region_label": region_label,
        },
        "panes": panes,
        "q": q or "",
        "regex": bool(regex),
        "status": status,
        "total": total,
        "truncated": truncated,
        "error": first_error,
    }
