"""Auth Matrix session identities — the columns of the matrix.

A :class:`Session` is a *named* set of credentials the operator can
replay history requests under. The substitution applied to a raw
HTTP request depends on the session ``kind``:

============== =============================================================
``kind``       Substitution
============== =============================================================
``cookie``     Replace the ``Cookie`` header with the payload string.
``bearer``     Replace the ``Authorization`` header with
               ``Bearer <payload>`` (payload stripped of any leading
               scheme).
``header``     Payload is one ``Name: Value`` line — replace that
               specific header.
``multi``      Payload is multiple ``Name: Value`` lines — replace each
               named header in order.
``anon``       Strip every header that authenticates the request
               (Cookie / Authorization / X-API-Key / etc.).
============== =============================================================

The :class:`Session` dataclass is encryption-aware: ``payload`` is
the *plaintext* operator input held only in memory. The on-disk
representation lives in the ``auth_matrix_sessions.payload_blob``
column and is encrypted with the project key. CRUD on the
:class:`reqlore.storage.Project` handles the round-trip transparently.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Literal


SessionKind = Literal["cookie", "bearer", "header", "multi", "anon"]
SESSION_KINDS: tuple[SessionKind, ...] = (
    "cookie", "bearer", "header", "multi", "anon",
)

# Header names we always strip when applying an ``anon`` session, or
# when overlaying any other kind (so a leftover Authorization can't
# silently keep authenticating after a Cookie swap). Lower-cased.
_AUTH_HEADERS_STRIP = frozenset({
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
})


@dataclass
class Session:
    """One row of :data:`auth_matrix_sessions`.

    ``id == 0`` means "not yet persisted". ``payload`` is the
    plaintext credential material; never serialise this directly.
    """

    name: str
    kind: SessionKind
    payload: str = ""
    id: int = 0
    source: str = ""           # "history" | "manual" | "macro:<name>"
    source_hid: int | None = None
    created_at: int = 0
    last_used_at: int = 0
    active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Session.name must be a non-empty string")
        if self.kind not in SESSION_KINDS:
            raise ValueError(
                f"Session.kind must be one of {SESSION_KINDS}, got {self.kind!r}"
            )
        if self.created_at == 0:
            self.created_at = int(time.time())

    def is_authless(self) -> bool:
        """True for the ``anon`` identity, regardless of payload."""
        return self.kind == "anon"


def _parse_header_lines(text: str) -> list[tuple[str, str]]:
    """Parse "Name: Value" lines into a header list. Malformed lines
    are skipped silently (operator typo shouldn't crash the run)."""
    out: list[tuple[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name:
            out.append((name, value))
    return out


def build_substitution(session: Session) -> list[tuple[str, str]]:
    """Return the headers a session contributes, as a list of
    ``(Name, Value)`` pairs.

    The list is ordered (multi-line ``multi`` sessions preserve order)
    and may be empty for the ``anon`` kind. Caller is responsible for
    stripping incompatible headers first via
    :func:`apply_session_to_request`.
    """
    payload = (session.payload or "").strip()
    if session.kind == "anon":
        return []
    if session.kind == "cookie":
        return [("Cookie", payload)] if payload else []
    if session.kind == "bearer":
        token = payload
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        return [("Authorization", f"Bearer {token}")] if token else []
    if session.kind == "header":
        pairs = _parse_header_lines(payload)
        return pairs[:1]
    if session.kind == "multi":
        return _parse_header_lines(payload)
    return []  # unknown kind — defensive


def apply_session_to_request(
    headers: Iterable[tuple[str, str]],
    session: Session,
    *,
    strip_default_auth: bool = True,
) -> list[tuple[str, str]]:
    """Apply ``session`` to ``headers`` and return the new list.

    The order is preserved as much as possible: stripped headers
    leave a hole, new headers are appended at the end. Replacements
    overwrite an existing header *in place* — this matters for
    proxies that key cookies by line position.

    ``strip_default_auth=True`` (the default) removes every header in
    :data:`_AUTH_HEADERS_STRIP` *unless* the session is going to put
    one back via its substitution. This avoids "ghost auth" where an
    Authorization header from the captured request leaks past a
    Cookie-only session swap.
    """
    sub = build_substitution(session)
    sub_names = {name.lower() for name, _ in sub}

    # First pass: walk existing headers, replacing or dropping.
    out: list[tuple[str, str]] = []
    consumed: set[str] = set()
    for name, value in headers:
        low = name.lower()
        if low in sub_names:
            # Replace with the session's value, preserving the case
            # of whichever side the operator typed (session wins).
            for sname, svalue in sub:
                if sname.lower() == low and sname.lower() not in consumed:
                    out.append((sname, svalue))
                    consumed.add(sname.lower())
                    break
            continue
        if strip_default_auth and low in _AUTH_HEADERS_STRIP:
            # Strip — session is anon or simply overlays nothing here.
            continue
        out.append((name, value))

    # Second pass: append any session headers that weren't already
    # present in the original request.
    for sname, svalue in sub:
        if sname.lower() not in consumed:
            out.append((sname, svalue))
            consumed.add(sname.lower())
    return out


# -- Capture from a history row -------------------------------------

def _header_value(
    headers: Iterable[tuple[str, str]], name: str,
) -> str:
    target = name.lower()
    for k, v in headers:
        if k.lower() == target:
            return v
    return ""


def capture_session_from_history(
    *,
    name: str,
    history_id: int,
    headers: Iterable[tuple[str, str]],
    kind_hint: SessionKind | None = None,
) -> Session:
    """Build a :class:`Session` from a captured request's headers.

    ``kind_hint`` lets the operator pin the shape; when omitted we
    pick the most specific one we can detect:

    1. ``Authorization: Bearer …`` -> ``bearer``
    2. ``Authorization: <other>``  -> ``header`` (whole line)
    3. ``Cookie: …``               -> ``cookie``
    4. Otherwise                   -> ``anon`` (the request was
       already unauthenticated, save it anyway so the operator can
       use it as a baseline column).
    """
    headers = list(headers)
    auth = _header_value(headers, "Authorization").strip()
    cookie = _header_value(headers, "Cookie").strip()

    kind: SessionKind
    payload: str
    if kind_hint is not None:
        kind = kind_hint
        if kind == "bearer":
            token = auth
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            payload = token
        elif kind == "cookie":
            payload = cookie
        elif kind == "header":
            payload = (
                f"Authorization: {auth}" if auth else
                (f"Cookie: {cookie}" if cookie else "")
            )
        elif kind == "multi":
            lines = []
            if auth:
                lines.append(f"Authorization: {auth}")
            if cookie:
                lines.append(f"Cookie: {cookie}")
            payload = "\n".join(lines)
        else:
            payload = ""
    else:
        if auth.lower().startswith("bearer "):
            kind = "bearer"
            payload = auth[7:].strip()
        elif auth:
            kind = "header"
            payload = f"Authorization: {auth}"
        elif cookie:
            kind = "cookie"
            payload = cookie
        else:
            kind = "anon"
            payload = ""

    return Session(
        name=name,
        kind=kind,
        payload=payload,
        source="history",
        source_hid=int(history_id) if history_id else None,
    )


def session_already_present(
    session: Session,
    raw_request: bytes,
) -> bool:
    """True if ``raw_request`` already carries this session's
    auth markers — i.e. the captured request was *already*
    authenticated under this session.

    Used by the passive shadow worker to avoid the "compare admin
    against itself" false-positive bypass-suspect: replaying an
    admin-authenticated request under the admin session is by
    definition expected to succeed identically.

    Detection is best-effort and conservative — we return True only
    when we can prove the markers are present. Behaviour by kind:

    * ``anon`` — True iff the request had no
      Authorization / Cookie / X-API-Key / etc. (i.e. it was
      already an anon request).
    * ``cookie`` — True iff the request's Cookie header value
      contains every ``name=value`` pair from the session payload.
    * ``bearer`` — True iff the request's Authorization header is
      ``Bearer <token>`` with the same token.
    * ``header`` / ``multi`` — True iff every session header
      appears verbatim in the request.
    """
    head = raw_request.split(b"\r\n\r\n", 1)[0]
    try:
        lines = head.decode("latin-1", errors="replace").split("\r\n")
    except Exception:
        return False
    req_headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        req_headers.append((k.strip(), v.strip()))

    if session.kind == "anon":
        for name, _ in req_headers:
            if name.lower() in _AUTH_HEADERS_STRIP:
                return False
        return True

    if session.kind == "cookie":
        req_cookie = _header_value(req_headers, "Cookie")
        payload = (session.payload or "").strip()
        if not payload:
            return False
        # Each "name=value;" pair in the payload must appear in the
        # request's cookie header. Use loose substring matching so
        # cookie order doesn't matter.
        for chunk in payload.split(";"):
            chunk = chunk.strip()
            if chunk and chunk not in req_cookie:
                return False
        return True

    if session.kind == "bearer":
        req_auth = _header_value(req_headers, "Authorization").strip()
        token = (session.payload or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if not token:
            return False
        return req_auth.lower() == f"bearer {token}".lower()

    if session.kind in ("header", "multi"):
        sub = build_substitution(session)
        if not sub:
            return False
        for name, value in sub:
            if _header_value(req_headers, name).strip() != value.strip():
                return False
        return True

    return False
