"""Phase 10 — auth-aware scan + session handling.

This module gives the active scanner a way to keep an authenticated
session alive across a long run. It builds on the existing macro
primitive (:mod:`reqlore.macros`): the operator records a login macro
once; the scanner replays it at scan start, harvests session cookies
+ optional CSRF tokens from the macro's responses, and keeps the
session warm by re-running the macro whenever a cheap *validity probe*
reports that the session has expired.

The design has four explicit goals:

1. **Composition over re-implementation.** Macros already know how to
   issue HTTP requests, substitute variables, and capture values from
   responses. ``AuthSession`` is purely a higher-level orchestrator on
   top of :func:`reqlore.macros.run`.

2. **Per-run isolation.** Every ``AuthSession`` instance carries its
   own cookie jar + CSRF cache, so two parallel scans cannot bleed
   session state into each other.

3. **Credentials never leave memory.** :class:`AuthCredentials` is an
   in-memory-only container with a redacting ``__repr__``. The class
   refuses to be JSON-serialised; if a caller tries to persist it
   they'll get a clear error rather than a silent secret leak.

4. **No mandatory new dependencies.** We deliberately do NOT
   introduce a per-project encryption module just to store secrets at
   rest, because *we don't store the secrets at rest*. The macro
   definition (which may contain credentials as variables) lives in
   the existing ``project_state`` table exactly as it did before
   Phase 10 — that is the operator's choice to make when they author
   the macro, and Phase 10 doesn't change that boundary.

Public surface:

- :class:`AuthCredentials` — secrets container.
- :class:`AuthSessionConfig` — declarative knobs (macro id,
  validity-probe URL, revalidation period, CSRF token names).
- :class:`AuthSession` — runtime state machine.
- :func:`build_auth_session_from_state` — convenience helper that
  loads a stored macro by id and constructs the session.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from ..engines import Request, Response, httpx_engine
from ..macros import Macro, MacroRun, run as run_macro

__all__ = [
    "AuthCredentials",
    "AuthSessionConfig",
    "AuthSession",
    "AuthSessionStats",
    "build_auth_session_from_state",
    "harvest_cookies_from_set_cookie",
]


# ---------------------------------------------------------------------------
# Credentials.
# ---------------------------------------------------------------------------

class AuthCredentials:
    """In-memory-only secret container.

    Holds a flat mapping of variable name -> value (e.g.
    ``{"username": "alice", "password": "<secret>"}``) that gets
    merged into the macro's variable scope before the macro runs.

    Hardening:

    - ``__repr__`` / ``__str__`` never reveal the values; they show
      the count of stored keys.
    - There is no ``to_json`` / ``__getstate__``; an attempt to
      pickle or JSON-encode raises ``TypeError``.
    - The internal dict is a copy — mutating the argument the caller
      passed in does not affect the credential store, and the
      ``values()`` accessor returns a defensive copy.
    """

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values: dict[str, str] = {}
        if values:
            for k, v in dict(values).items():
                if v is None:
                    continue
                self._values[str(k)] = str(v)

    def __repr__(self) -> str:
        return f"AuthCredentials(<{len(self._values)} redacted>)"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._values

    def keys(self) -> Iterable[str]:
        """Names only — never values."""
        return tuple(self._values.keys())

    def values(self) -> dict[str, str]:
        """Defensive copy of the underlying map. Callers should hold
        this dict only as long as needed."""
        return dict(self._values)

    # Pickling / JSON refusal -------------------------------------------------

    def __reduce__(self):
        raise TypeError(
            "AuthCredentials refuses to pickle to avoid leaking "
            "secrets to disk."
        )

    def __getstate__(self):
        raise TypeError(
            "AuthCredentials refuses to serialise to avoid leaking "
            "secrets to disk."
        )


# ---------------------------------------------------------------------------
# Config.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthSessionConfig:
    """Declarative knobs for an authenticated scan.

    Fields:

    - ``macro_id`` — id of the macro to run for login. The macro is
      loaded from the project's macro store at session construction
      time.
    - ``credentials`` — optional :class:`AuthCredentials` whose
      key/value pairs are merged into the macro's variable scope
      before each run. Lets the same macro definition be reused
      across many credential pairs without re-saving the macro.
    - ``session_cookie_names`` — cookie names to harvest from each
      macro step's ``Set-Cookie`` response header. Empty tuple means
      "harvest every cookie the server set". Cookies are injected
      into every subsequent probe as a single combined ``Cookie:``
      header.
    - ``extra_session_headers`` — names of response headers to copy
      verbatim into every subsequent probe (e.g.
      ``("Authorization",)`` for a bearer token surfaced by a JSON
      capture step that writes it back as a header).
    - ``validity_probe_url`` / ``validity_probe_method`` / ``...`` —
      a cheap unauthenticated-looking-from-the-outside request used
      to ask the target "am I still logged in?". A response whose
      status is in ``validity_failure_statuses`` *or* whose
      ``Location`` contains any of ``validity_failure_location_substrings``
      is treated as a session-expired signal.
    - ``revalidate_every_n_probes`` — how often to fire the validity
      probe between scan probes. 0 disables periodic revalidation
      (only the up-front login runs).
    - ``csrf_token_names`` — form field names whose value should be
      refreshed from the *referrer / row URL* immediately before a
      probe is sent. Empty tuple disables CSRF refresh.
    - ``csrf_token_ttl_seconds`` — soft cache TTL for harvested CSRF
      tokens, so we don't re-fetch the form page on every probe.
    """

    macro_id: int
    credentials: AuthCredentials | None = None
    session_cookie_names: tuple[str, ...] = ()
    extra_session_headers: tuple[str, ...] = ()
    validity_probe_url: str | None = None
    validity_probe_method: str = "GET"
    validity_failure_statuses: tuple[int, ...] = (401, 403)
    validity_failure_location_substrings: tuple[str, ...] = (
        "login", "signin", "sign-in", "auth",
    )
    revalidate_every_n_probes: int = 25
    csrf_token_names: tuple[str, ...] = ()
    csrf_token_ttl_seconds: float = 60.0

    def __post_init__(self) -> None:  # validation
        if self.macro_id < 1:
            raise ValueError(
                f"AuthSessionConfig.macro_id must be >= 1; "
                f"got {self.macro_id!r}"
            )
        if self.revalidate_every_n_probes < 0:
            raise ValueError(
                "AuthSessionConfig.revalidate_every_n_probes must "
                "be >= 0"
            )
        if self.csrf_token_ttl_seconds < 0:
            raise ValueError(
                "AuthSessionConfig.csrf_token_ttl_seconds must be "
                ">= 0"
            )


# ---------------------------------------------------------------------------
# Stats.
# ---------------------------------------------------------------------------

@dataclass
class AuthSessionStats:
    """Counters exported so the run summary can show how busy the
    auth machinery was."""

    macro_runs: int = 0           # total times the login macro fired
    macro_failures: int = 0       # macro runs that ended with a non-2xx step
    session_recoveries: int = 0   # validity probe failed → macro re-ran
    validity_probes: int = 0      # total validity probes fired
    csrf_token_refetches: int = 0 # form parent pages fetched for CSRF
    csrf_token_swaps: int = 0     # probe bodies actually rewritten


# ---------------------------------------------------------------------------
# Cookie helpers.
# ---------------------------------------------------------------------------

_SET_COOKIE_KV_RE = re.compile(r"\s*([^=;\s]+)\s*=\s*([^;]*)")
_INPUT_VALUE_RE = re.compile(
    r"""<input\b[^>]*\bname\s*=\s*["']?(?P<name>[A-Za-z0-9_\-:.]+)["']?"""
    r"""[^>]*\bvalue\s*=\s*["'](?P<value>[^"']*)["']""",
    re.IGNORECASE,
)
_META_CSRF_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']?(?P<name>[A-Za-z0-9_\-:.]+)["']?"""
    r"""[^>]*\bcontent\s*=\s*["'](?P<value>[^"']*)["']""",
    re.IGNORECASE,
)


def harvest_cookies_from_set_cookie(
    set_cookie_value: str, *, only: tuple[str, ...] = (),
) -> dict[str, str]:
    """Extract ``name=value`` pairs from a ``Set-Cookie`` header value.

    Handles both single-cookie strings and the comma-separated
    multi-cookie form that some response shims produce. Returns only
    the first occurrence of each cookie name.

    If ``only`` is non-empty, only cookies whose name appears in it
    are returned (case-insensitive).
    """
    if not set_cookie_value:
        return {}
    allow_all = not only
    allowed_lower = {n.lower() for n in only}
    out: dict[str, str] = {}
    # Split on ", " between cookies — but only when followed by what
    # looks like a cookie name. Naive splits break on attribute
    # values that legitimately contain commas (Expires=...).
    pieces = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", set_cookie_value)
    for piece in pieces:
        head = piece.split(";", 1)[0]
        m = _SET_COOKIE_KV_RE.match(head)
        if not m:
            continue
        name = m.group(1)
        value = m.group(2)
        if not allow_all and name.lower() not in allowed_lower:
            continue
        if name not in out:
            out[name] = value
    return out


def _merge_cookie_header(existing: list[tuple[str, str]],
                          cookies: Mapping[str, str]) -> list[tuple[str, str]]:
    """Return a new header list with ``Cookie:`` updated to include
    every ``cookies`` entry. Existing cookies in the request are
    preserved unless overridden by name."""
    if not cookies:
        return list(existing)
    have: dict[str, str] = {}
    others: list[tuple[str, str]] = []
    for k, v in existing:
        if k.lower() == "cookie":
            for kv in v.split(";"):
                kv = kv.strip()
                if not kv or "=" not in kv:
                    continue
                ck, cv = kv.split("=", 1)
                have[ck.strip()] = cv.strip()
        else:
            others.append((k, v))
    for ck, cv in cookies.items():
        have[ck] = cv
    if have:
        cookie_line = "; ".join(f"{k}={v}" for k, v in have.items())
        others.append(("Cookie", cookie_line))
    return others


# ---------------------------------------------------------------------------
# AuthSession.
# ---------------------------------------------------------------------------

class AuthSession:
    """Stateful session manager wired into an active scan run.

    Lifecycle::

        sess = AuthSession(macro, config)
        sess.prime(sender=send)              # runs login once
        for probe_req in ...:
            req = sess.apply_to_request(probe_req, sender=send)
            response = send(req)
            sess.notify_response(req, response)
            sess.maybe_revalidate(sender=send)

    The class is intentionally pure-Python with no shared mutable
    globals so two parallel instances are fully isolated.

    ``sender`` is a callable ``(Request) -> Response`` that performs
    the HTTP I/O. The active scanner injects its already-configured
    httpx wrapper; tests inject an in-memory fake.
    """

    def __init__(
        self,
        macro: Macro,
        config: AuthSessionConfig,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.macro = macro
        self.config = config
        self.stats = AuthSessionStats()
        # Cookies + bearer-style headers harvested from the most
        # recent macro run.
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}
        # CSRF token cache: maps (parent_url, token_name) -> (value, fetched_at)
        self._csrf_cache: dict[tuple[str, str], tuple[str, float]] = {}
        # Probe counter for periodic revalidation. We count probes
        # *applied through the session* rather than total probes, so
        # the AuthSession remains correct even if the host scanner
        # changes its global probe counter semantics.
        self._probes_since_validity_check = 0
        self._primed = False
        self._now = now or time.monotonic

    # ----- macro execution -------------------------------------------------

    def _prepared_macro(self) -> Macro:
        """Return a copy of the macro with the credentials merged
        into its variable scope. We copy rather than mutate so the
        on-disk macro definition is never touched."""
        m = Macro(
            name=self.macro.name,
            base_headers=dict(self.macro.base_headers),
            variables=dict(self.macro.variables),
            steps=list(self.macro.steps),
        )
        if self.config.credentials:
            m.variables.update(self.config.credentials.values())
        return m

    def _run_macro(
        self, sender: Callable[[Request], Response] | None,
    ) -> MacroRun:
        macro_run = run_macro(self._prepared_macro(), sender=sender)
        self.stats.macro_runs += 1
        failed = any(s.error for s in macro_run.steps) or (
            macro_run.steps and macro_run.steps[-1].status >= 400
        )
        if failed:
            self.stats.macro_failures += 1
        return macro_run

    def _harvest_from_macro_run(
        self, macro_run: MacroRun, *, step_responses: list[Response] | None = None,
    ) -> None:
        """Update ``_session_cookies`` + ``_session_headers`` from a
        completed macro run. ``step_responses`` is the per-step
        :class:`Response` list captured by an instrumented sender.
        When omitted we fall back to whatever the macro itself
        captured as a variable named like a session cookie/header.
        """
        if step_responses:
            wanted_headers = {h.lower() for h in self.config.extra_session_headers}
            for resp in step_responses:
                if resp is None:
                    continue
                # Cookies.
                sc = resp.header("Set-Cookie") or ""
                cookies = harvest_cookies_from_set_cookie(
                    sc, only=self.config.session_cookie_names,
                )
                self._session_cookies.update(cookies)
                # Pass-through headers.
                if wanted_headers:
                    for k, v in (resp.headers or []):
                        if k.lower() in wanted_headers and v:
                            self._session_headers[k] = v
        # Macro-captured variables that look session-y are a useful
        # fallback when the response shim doesn't expose headers
        # cleanly (e.g. a JSON-body capture).
        for var, value in macro_run.variables.items():
            if not value:
                continue
            low = var.lower()
            if low.endswith("token") or low.endswith("cookie") or low in {
                "session", "sid", "jsessionid", "phpsessid",
            }:
                # If the capture name matches a configured cookie name,
                # treat it as a cookie; else treat it as a bearer-style
                # header iff its name matches an extra_session_headers
                # entry. Otherwise silently ignore — we don't want to
                # invent a header out of thin air.
                if var in self.config.session_cookie_names:
                    self._session_cookies[var] = value
                elif var in self.config.extra_session_headers:
                    self._session_headers[var] = value

    # ----- public lifecycle ------------------------------------------------

    def prime(
        self, *, sender: Callable[[Request], Response] | None = None,
    ) -> MacroRun:
        """Run the login macro once. Safe to call again; each call
        increments ``stats.macro_runs``."""
        responses: list[Response] = []
        instrumented = self._instrument_sender(sender, responses)
        macro_run = self._run_macro(instrumented)
        self._harvest_from_macro_run(macro_run, step_responses=responses)
        self._primed = True
        self._probes_since_validity_check = 0
        return macro_run

    def apply_to_request(
        self, req: Request, *,
        sender: Callable[[Request], Response] | None = None,
    ) -> Request:
        """Return ``req`` with session cookies + bearer headers
        merged in, and any CSRF token in the body refreshed."""
        new_headers = list(req.headers)
        if self._session_headers:
            have = {k.lower() for k, _ in new_headers}
            for k, v in self._session_headers.items():
                if k.lower() in have:
                    new_headers = [
                        (hk, v) if hk.lower() == k.lower() else (hk, hv)
                        for hk, hv in new_headers
                    ]
                else:
                    new_headers.append((k, v))
        new_headers = _merge_cookie_header(new_headers, self._session_cookies)
        new_body = req.body
        if self.config.csrf_token_names and new_body:
            new_body = self._maybe_refresh_csrf_in_body(
                req=Request(method=req.method, url=req.url,
                             headers=new_headers, body=new_body),
                sender=sender,
            )
        if (new_headers is req.headers and new_body is req.body):
            return req
        return Request(method=req.method, url=req.url,
                        headers=new_headers, body=new_body)

    def notify_response(self, req: Request, resp: Response) -> None:
        """Hook so the session can opportunistically harvest cookies
        that the target rotates mid-scan. Currently records any
        ``Set-Cookie`` that appears."""
        del req  # reserved for future use (per-URL cookie scoping)
        if resp is None:
            return
        sc = resp.header("Set-Cookie") or ""
        if not sc:
            return
        cookies = harvest_cookies_from_set_cookie(
            sc, only=self.config.session_cookie_names,
        )
        for k, v in cookies.items():
            # Don't overwrite a cookie with an empty value (some
            # logout responses set ``foo=`` to clear it).
            if v:
                self._session_cookies[k] = v

    def maybe_revalidate(
        self, *,
        sender: Callable[[Request], Response] | None = None,
    ) -> bool:
        """If revalidation is configured and the probe-count threshold
        is reached, fire the validity probe and re-run the macro if
        the session looks dead. Returns True iff a recovery happened.
        """
        self._probes_since_validity_check += 1
        cfg = self.config
        if cfg.revalidate_every_n_probes <= 0:
            return False
        if self._probes_since_validity_check < cfg.revalidate_every_n_probes:
            return False
        self._probes_since_validity_check = 0
        return self._revalidate_now(sender=sender)

    def _revalidate_now(
        self, *, sender: Callable[[Request], Response] | None,
    ) -> bool:
        cfg = self.config
        if not cfg.validity_probe_url:
            # No probe configured → preemptively re-run the macro.
            self._refresh_via_macro(sender=sender)
            self.stats.session_recoveries += 1
            return True
        probe_req = self.apply_to_request(
            Request(
                method=cfg.validity_probe_method,
                url=cfg.validity_probe_url,
                headers=[],
                body=b"",
            ),
            sender=sender,  # CSRF unlikely on a validity probe, but harmless
        )
        try:
            resp = (sender or _default_send)(probe_req)
        except Exception:  # noqa: BLE001 — network failures are recoverable
            return False
        self.stats.validity_probes += 1
        if not self._is_session_expired(resp):
            return False
        self._refresh_via_macro(sender=sender)
        self.stats.session_recoveries += 1
        return True

    def _refresh_via_macro(
        self, *, sender: Callable[[Request], Response] | None,
    ) -> None:
        responses: list[Response] = []
        instrumented = self._instrument_sender(sender, responses)
        macro_run = self._run_macro(instrumented)
        self._harvest_from_macro_run(macro_run, step_responses=responses)

    def _is_session_expired(self, resp: Response) -> bool:
        cfg = self.config
        if resp is None:
            return False
        if resp.status in cfg.validity_failure_statuses:
            return True
        if 300 <= resp.status < 400 and cfg.validity_failure_location_substrings:
            loc = (resp.header("Location") or "").lower()
            if any(s in loc for s in cfg.validity_failure_location_substrings):
                return True
        return False

    # ----- CSRF ------------------------------------------------------------

    def _maybe_refresh_csrf_in_body(
        self, *, req: Request,
        sender: Callable[[Request], Response] | None,
    ) -> bytes:
        body = req.body or b""
        if not body:
            return body
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return body
        target_names = [
            n for n in self.config.csrf_token_names
            if (n + "=") in text or _name_in_json_or_form(text, n)
        ]
        if not target_names:
            return body
        parent_url = self._guess_parent_url(req)
        if not parent_url:
            return body
        tokens = self._fetch_csrf_tokens(
            parent_url, target_names, sender=sender,
        )
        if not tokens:
            return body
        new_text = text
        for name in target_names:
            new_value = tokens.get(name)
            if not new_value:
                continue
            # urlencoded form: key=val&...
            new_text = re.sub(
                rf"({re.escape(name)}=)([^&]*)",
                lambda m: m.group(1) + _quote(new_value),
                new_text,
            )
            # JSON: "name":"value"  (very small subset of cases on
            # purpose — anything more elaborate would need a proper
            # parser and we won't pretend to here).
            new_text = re.sub(
                rf'("{re.escape(name)}"\s*:\s*)"[^"]*"',
                lambda m: f'{m.group(1)}"{new_value}"',
                new_text,
            )
        if new_text != text:
            self.stats.csrf_token_swaps += 1
            return new_text.encode("utf-8", errors="replace")
        return body

    def _guess_parent_url(self, req: Request) -> str | None:
        # 1) Prefer an explicit Referer the original recorder captured.
        for k, v in req.headers:
            if k.lower() == "referer" and v:
                return v
        # 2) Same-origin page is the most defensible fallback for a
        #    form POST: just strip the query and use that as the
        #    "form page" URL. It often isn't right, but it never
        #    crosses an origin.
        return _origin_root(req.url)

    def _fetch_csrf_tokens(
        self, parent_url: str, names: list[str], *,
        sender: Callable[[Request], Response] | None,
    ) -> dict[str, str]:
        now = self._now()
        result: dict[str, str] = {}
        names_to_fetch: list[str] = []
        ttl = self.config.csrf_token_ttl_seconds
        for n in names:
            cached = self._csrf_cache.get((parent_url, n))
            if cached and (now - cached[1]) <= ttl:
                result[n] = cached[0]
            else:
                names_to_fetch.append(n)
        if not names_to_fetch:
            return result
        try:
            resp = (sender or _default_send)(
                self.apply_to_request(
                    Request(method="GET", url=parent_url,
                            headers=[], body=b""),
                    sender=None,  # skip recursive CSRF for the fetch
                )
            )
        except Exception:  # noqa: BLE001
            return result
        self.stats.csrf_token_refetches += 1
        html = (resp.body or b"").decode("utf-8", errors="replace")
        fresh = _extract_csrf_tokens(html, names_to_fetch)
        for name, value in fresh.items():
            self._csrf_cache[(parent_url, name)] = (value, now)
            result[name] = value
        return result

    # ----- introspection ---------------------------------------------------

    @property
    def session_cookies(self) -> dict[str, str]:
        """Defensive copy of the harvested cookie jar."""
        return dict(self._session_cookies)

    @property
    def session_headers(self) -> dict[str, str]:
        """Defensive copy of any bearer-style headers."""
        return dict(self._session_headers)

    @property
    def primed(self) -> bool:
        return self._primed

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _instrument_sender(
        sender: Callable[[Request], Response] | None,
        responses: list[Response],
    ) -> Callable[[Request], Response]:
        """Wrap a sender so each step's response is appended to
        ``responses``. We need this because :func:`reqlore.macros.run`
        returns ``MacroRun`` summaries, not raw responses."""
        real = sender or _default_send

        def _wrapped(req: Request) -> Response:
            resp = real(req)
            responses.append(resp)
            return resp

        return _wrapped


# ---------------------------------------------------------------------------
# Module-level helpers (kept private; not in __all__).
# ---------------------------------------------------------------------------

def _default_send(req: Request) -> Response:
    return httpx_engine.send(req, follow_redirects=True)


def _origin_root(url: str) -> str | None:
    """Return ``scheme://host[:port]/`` for ``url`` or ``None`` if
    parsing fails."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return None
        return f"{p.scheme}://{p.netloc}/"
    except Exception:  # noqa: BLE001
        return None


def _name_in_json_or_form(text: str, name: str) -> bool:
    """Conservative check that *name* is referenced as a form field
    or JSON key in *text*."""
    if not name:
        return False
    if (name + "=") in text:
        return True
    if f'"{name}"' in text:
        return True
    return False


def _quote(value: str) -> str:
    """Minimal urlencode: keep the call-site readable. We don't pull
    in :mod:`urllib.parse` for a hot path since CSRF tokens are
    typically already URL-safe (hex / base64url)."""
    from urllib.parse import quote_plus
    return quote_plus(value)


def _extract_csrf_tokens(
    html: str, names: Iterable[str],
) -> dict[str, str]:
    """Pull CSRF token values out of an HTML form/meta page.

    Looks for ``<input name="<n>" value="...">`` first, then
    ``<meta name="<n>" content="...">``. Returns only names found.
    """
    wanted = {n: None for n in names}
    if not html or not wanted:
        return {}
    for m in _INPUT_VALUE_RE.finditer(html):
        name = m.group("name")
        if name in wanted and wanted[name] is None:
            wanted[name] = m.group("value")
    for m in _META_CSRF_RE.finditer(html):
        name = m.group("name")
        if name in wanted and wanted[name] is None:
            wanted[name] = m.group("value")
    return {k: v for k, v in wanted.items() if v is not None}


# ---------------------------------------------------------------------------
# Project-store loader.
# ---------------------------------------------------------------------------

def build_auth_session_from_state(
    project: Any, config: AuthSessionConfig,
    *, now: Callable[[], float] | None = None,
) -> AuthSession:
    """Load macro #``config.macro_id`` from ``project_state`` and
    return a configured :class:`AuthSession`.

    Raises ``LookupError`` if the macro does not exist or cannot be
    parsed. The caller is expected to surface that as a flash message
    rather than crash the scan.
    """
    try:
        blob = project.get_state(f"macro:{config.macro_id}", "")
    except AttributeError as exc:
        raise LookupError(
            "Project does not support get_state(); cannot load macro"
        ) from exc
    if not blob:
        raise LookupError(
            f"No macro stored with id={config.macro_id}"
        )
    try:
        macro = Macro.from_json(blob)
    except Exception as exc:  # noqa: BLE001 — surface as LookupError
        raise LookupError(
            f"Macro id={config.macro_id} could not be parsed: {exc}"
        ) from exc
    return AuthSession(macro, config, now=now)
