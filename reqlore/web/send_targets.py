"""Shared metadata for the "Send to <tool>" menu used by both the
Intercept-detail page (held flows) and the History-detail page
(recorded flows).

The menu has a single source of truth so the access-key letters and
ordering stay identical between the two surfaces — important for
muscle memory and for the keyboard map documented in
``help_bp.KEYMAP``.

Each target is rendered as a single button with an ``accesskey``
attribute. The access-key modifier the operator presses depends on
their browser:

* Chrome / Edge / new-Brave: ``Alt+<letter>``
* Firefox: ``Alt+Shift+<letter>``
* macOS Safari / any browser on macOS: ``Ctrl+Alt+<letter>``

Letters chosen to be mnemonic, unique on the page, and to avoid
``Alt+D`` which focuses the browser's address bar on every major
browser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# Order is the order shown in the UI.
# (slug, label, accesskey)
SEND_TARGETS: list[tuple[str, str, str]] = [
    ("repeater", "Repeater",          "r"),
    ("intruder", "Intruder",          "i"),
    ("comparer", "Comparer (side A)", "m"),
    ("poc",      "PoC builder",       "b"),
    ("jwt",      "JWT workbench",     "j"),
    ("decoder",  "Decoder",           "o"),
]


@dataclass
class ParsedRequest:
    method: str
    path: str
    host: str
    headers: list[tuple[str, str]]
    body: bytes


def parse_raw_request(raw: bytes) -> ParsedRequest:
    """Best-effort parse of a raw HTTP request blob.

    Never raises — falls back to safe defaults if the blob is
    malformed, so the menu can always render.
    """
    sep = raw.find(b"\r\n\r\n")
    head = raw[:sep] if sep >= 0 else raw
    body = raw[sep + 4:] if sep >= 0 else b""
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    rl = lines[0].split(" ", 2) if lines else []
    method = rl[0] if rl else "GET"
    path = rl[1] if len(rl) > 1 else "/"
    host = ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            headers.append((k, v))
            if k.lower() == "host":
                host = v
    return ParsedRequest(method=method, path=path, host=host,
                         headers=headers, body=body)


_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def bearer_token(headers: list[tuple[str, str]]) -> str:
    """Return the JWT-shaped string from any ``Authorization: Bearer``
    header, or ``""`` if none / not JWT-shaped.
    """
    for k, v in headers:
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            tok = v.split(" ", 1)[1].strip()
            if _JWT_RE.match(tok):
                return tok
    return ""


def underline_first(text: str, ch: str) -> str:
    """Wrap the first case-insensitive occurrence of ``ch`` in ``text``
    in ``<u>…</u>``. Mirrors how desktop menus draw their mnemonics.
    Returns plain text if no match.
    """
    i = text.lower().find(ch.lower())
    if i < 0:
        return text
    return f"{text[:i]}<u>{text[i]}</u>{text[i + 1:]}"


def available_targets(req_blob: bytes) -> list[dict]:
    """Build the menu list for a request blob.

    Filters out targets that wouldn't have anything useful to do:

    * **JWT** only appears when an ``Authorization: Bearer <jwt>``
      header is present.
    * **Decoder** only appears when there's a body to decode.
    """
    parsed = parse_raw_request(req_blob)
    bearer = bearer_token(parsed.headers)
    out: list[dict] = []
    for slug, label, key in SEND_TARGETS:
        if slug == "jwt" and not bearer:
            continue
        if slug == "decoder" and not parsed.body:
            continue
        out.append({
            "slug": slug,
            "label": label,
            "key": key,
            "html": underline_first(f"Send to {label}", key),
        })
    return out


def target_label(slug: str) -> str:
    """Pretty label for a slug; ``slug`` itself if unknown."""
    return next((label for s, label, _ in SEND_TARGETS if s == slug), slug)
