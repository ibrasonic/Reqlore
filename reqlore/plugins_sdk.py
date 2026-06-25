"""Plugin authoring SDK — typed builders used by example plugins.

A plugin file is a plain ``.py`` module. To register code you only need
to expose a module-level ``PLUGIN_INFO`` dict and optionally one or more
of these entry points:

* ``scanner_rules() -> list[callable]`` — passive rules
* ``register(app)``                     — Flask hook / blueprint
* ``copy_as() -> list[CopyAsHandler]``  — extra "copy-as" renderers
* ``PLUGIN_APP`` (Phase 16)             — a standalone Plugin App with
                                          its own settings form, Run
                                          button, live log, results
                                          table and findings hook.

This module provides:

* :func:`make_info`                  build a valid ``PLUGIN_INFO`` dict
* :func:`make_passive_rule`          decorator/wrapper for a rule fn
* :class:`CopyAsHandler`             dataclass for new copy-as helpers
* :func:`assert_compatible`          static check used at load time
* :func:`make_app`                   build a :class:`PluginApp`
* :class:`PluginApp`                 standalone plugin metadata + runner
* :class:`Field` and subclasses      typed settings form fields
* :class:`PluginContext`             everything a plugin run can touch
* :class:`ScopeView`                 read-only sitemap scope projection
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field as _field
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlparse

from .scanner.findings import Finding, Severity   # noqa: F401 - re-export for SDK users
from .scanner.passive import RuleContext           # noqa: F401 - re-export


SDK_VERSION = "1.0"


def make_info(*, name: str, version: str = "0.1",
              description: str = "",
              author: str = "",
              homepage: str = "",
              min_reqlore: str = "0.1") -> dict[str, Any]:
    """Build a well-formed ``PLUGIN_INFO`` dict."""
    return {
        "name": name,
        "version": version,
        "description": description,
        "author": author,
        "homepage": homepage,
        "min_reqlore": min_reqlore,
        "sdk_version": SDK_VERSION,
    }


def make_passive_rule(name: str, *, severity: str = "info") -> Callable:
    """Decorator: tag a ``(ctx) -> Iterable[Finding]`` function with a name.

    Example::

        @make_passive_rule("missing-server-timing", severity="info")
        def rule(ctx):
            if not ctx.resp.header("server-timing"):
                yield Finding(severity="info",
                              title="No Server-Timing header",
                              host=ctx.host, url=ctx.url)
    """
    def deco(fn: Callable) -> Callable:
        fn.reqlore_rule_name = name              # type: ignore[attr-defined]
        fn.reqlore_rule_severity = severity      # type: ignore[attr-defined]
        return fn
    return deco


@dataclass
class CopyAsHandler:
    name: str                            # menu label (e.g. "PHP curl")
    render: Callable[[bytes], str]       # bytes (raw req) -> printable text


def assert_compatible(info: dict[str, Any]) -> None:
    """Validate a ``PLUGIN_INFO`` dict. Raise ``ValueError`` on mismatch."""
    if not isinstance(info, dict):
        raise ValueError("PLUGIN_INFO must be a dict")
    if "name" not in info or not str(info["name"]).strip():
        raise ValueError("PLUGIN_INFO['name'] is required")
    sdk = str(info.get("sdk_version", SDK_VERSION))
    major = sdk.split(".")[0]
    if major != SDK_VERSION.split(".")[0]:
        raise ValueError(
            f"plugin built against SDK {sdk}, host SDK is {SDK_VERSION}")


# ===========================================================================
# Phase 16 — Plugin Apps
#
# A *Plugin App* is a standalone tool with its own URL, its own settings
# form, its own Run/Stop buttons, its own live log + results table, and
# its own findings written into the project's ``issues`` table tagged
# ``source = "plugin:<slug>"``.
#
# Plugin authors declare a module-level ``PLUGIN_APP = make_app(...)``,
# then decorate the entry-point function with ``@PLUGIN_APP.runner``.
# A run executes on its own daemon thread with cooperative cancel; the
# UI polls a JSON endpoint for log + progress + result updates.
# ===========================================================================


_SLUG_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_-")


def _check_slug(slug: str) -> str:
    s = (slug or "").strip().lower()
    if not s:
        raise ValueError("plugin app slug is required")
    if len(s) > 64:
        raise ValueError("plugin app slug is too long (max 64 chars)")
    if set(s) - _SLUG_OK:
        raise ValueError(
            "plugin app slug may only contain a-z, 0-9, '_' and '-'")
    if s.startswith("-") or s.startswith("_"):
        raise ValueError("plugin app slug must start with a letter or digit")
    return s


# ---- settings form fields --------------------------------------------------

@dataclass
class Field:
    """Base class for settings-form fields. Subclasses implement
    :meth:`validate` and inherit a sane :meth:`render_dict`."""

    name: str
    label: str = ""
    help: str = ""
    required: bool = False
    default: Any = None
    kind: str = "str"          # template branch key

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Field.name is required")
        # Light identifier check — Jinja and HTML name= want plain ASCII.
        for ch in self.name:
            if not (ch.isalnum() or ch in "_-"):
                raise ValueError(
                    f"Field.name {self.name!r} contains invalid character "
                    f"{ch!r}; use [A-Za-z0-9_-]")
        if not self.label:
            self.label = self.name.replace("_", " ").replace("-", " ").title()

    # Subclasses override:
    def validate(self, raw: str | None) -> Any:    # pragma: no cover - abstract
        raise NotImplementedError

    def render_dict(self) -> dict[str, Any]:
        """Shape consumed by the Jinja template."""
        return {
            "name": self.name,
            "label": self.label,
            "help": self.help,
            "required": bool(self.required),
            "default": self.default,
            "kind": self.kind,
        }


@dataclass
class StrField(Field):
    placeholder: str = ""
    max_len: int = 4096
    kind: str = "str"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.default is None:
            self.default = ""
        if self.max_len < 1:
            raise ValueError("StrField.max_len must be >= 1")

    def validate(self, raw: str | None) -> str:
        s = "" if raw is None else str(raw)
        if not s.strip():
            if self.required:
                raise ValueError(f"{self.label}: required")
            return str(self.default or "")
        if len(s) > self.max_len:
            raise ValueError(
                f"{self.label}: too long ({len(s)} > {self.max_len})")
        return s

    def render_dict(self) -> dict[str, Any]:
        d = super().render_dict()
        d["placeholder"] = self.placeholder
        d["max_len"] = self.max_len
        return d


@dataclass
class TextField(Field):
    """Multi-line text. Used for wordlists, payload sets, etc."""

    rows: int = 6
    placeholder: str = ""
    max_len: int = 5_000_000
    kind: str = "text"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.default is None:
            self.default = ""
        if self.rows < 1:
            raise ValueError("TextField.rows must be >= 1")
        if self.max_len < 1:
            raise ValueError("TextField.max_len must be >= 1")

    def validate(self, raw: str | None) -> str:
        s = "" if raw is None else str(raw)
        if not s.strip():
            if self.required:
                raise ValueError(f"{self.label}: required")
            return str(self.default or "")
        if len(s) > self.max_len:
            raise ValueError(
                f"{self.label}: too long ({len(s)} > {self.max_len} chars)")
        return s

    def render_dict(self) -> dict[str, Any]:
        d = super().render_dict()
        d["rows"] = self.rows
        d["placeholder"] = self.placeholder
        d["max_len"] = self.max_len
        return d


@dataclass
class IntField(Field):
    min: int | None = None
    max: int | None = None
    kind: str = "int"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.default is None:
            self.default = 0
        if (self.min is not None and self.max is not None
                and self.min > self.max):
            raise ValueError(
                f"IntField.min ({self.min}) must be <= max ({self.max})")

    def validate(self, raw: str | None) -> int:
        s = "" if raw is None else str(raw).strip()
        if not s:
            if self.required:
                raise ValueError(f"{self.label}: required")
            return int(self.default)
        try:
            v = int(s, 10)
        except (TypeError, ValueError):
            raise ValueError(f"{self.label}: not an integer ({s!r})")
        if self.min is not None and v < self.min:
            raise ValueError(f"{self.label}: must be >= {self.min}")
        if self.max is not None and v > self.max:
            raise ValueError(f"{self.label}: must be <= {self.max}")
        return v

    def render_dict(self) -> dict[str, Any]:
        d = super().render_dict()
        d["min"] = self.min
        d["max"] = self.max
        return d


@dataclass
class BoolField(Field):
    kind: str = "bool"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.default is None:
            self.default = False

    def validate(self, raw: str | None) -> bool:
        if raw is None:
            return False    # checkboxes omit the key when unchecked
        s = str(raw).strip().lower()
        if not s:
            return False
        return s in ("1", "true", "on", "yes")


@dataclass
class SelectField(Field):
    choices: Sequence[str] = ()
    kind: str = "select"

    def __post_init__(self) -> None:
        super().__post_init__()
        choices = list(self.choices or ())
        if not choices:
            raise ValueError("SelectField.choices must be a non-empty sequence")
        # Normalise to plain strings; reject duplicates so the rendered
        # <select> doesn't ambiguously match two options.
        seen: set[str] = set()
        normalised: list[str] = []
        for c in choices:
            cs = str(c)
            if cs in seen:
                raise ValueError(f"SelectField.choices contains duplicate {cs!r}")
            seen.add(cs)
            normalised.append(cs)
        self.choices = tuple(normalised)
        if self.default is None:
            self.default = normalised[0]
        if str(self.default) not in seen:
            raise ValueError(
                f"SelectField.default {self.default!r} is not in choices")

    def validate(self, raw: str | None) -> str:
        s = "" if raw is None else str(raw)
        if not s:
            if self.required:
                raise ValueError(f"{self.label}: required")
            return str(self.default)
        if s not in self.choices:
            raise ValueError(f"{self.label}: not a valid choice ({s!r})")
        return s

    def render_dict(self) -> dict[str, Any]:
        d = super().render_dict()
        d["choices"] = list(self.choices)
        return d


# ---- ScopeView -------------------------------------------------------------

class ScopeView:
    """Read-only projection of the project's sitemap scope rules.

    Plugin authors should branch on :meth:`is_in_scope` (or
    :meth:`is_url_in_scope`) before sending probes when the user has
    asked them to honour scope. ``empty`` returns ``True`` when no
    rules exist — by Reqlore convention an empty scope is **permissive**
    (every host is in-scope) so the plugin should usually treat
    ``empty`` as "scope is not configured, run anyway with a warning".
    """

    def __init__(self, rules: Iterable[dict] | None = None):
        self._rules: list[dict] = list(rules or [])

    @classmethod
    def from_project(cls, project: Any) -> "ScopeView":
        """Construct from a :class:`reqlore.storage.Project`. Defensive:
        a project without ``list_scope`` (older fakes in tests) yields
        an empty (permissive) scope."""
        try:
            rules = list(project.list_scope())
        except (AttributeError, Exception):
            rules = []
        return cls(rules)

    @property
    def rules(self) -> list[dict]:
        return list(self._rules)

    @property
    def empty(self) -> bool:
        """True iff there are zero enabled rules of any kind."""
        return not any(r.get("enabled") for r in self._rules)

    def hosts(self) -> list[str]:
        """Patterns from enabled include / host rules. Useful for an
        empty-target seed list."""
        out: list[str] = []
        for r in self._rules:
            if not r.get("enabled"):
                continue
            if r.get("kind") != "include":
                continue
            if (r.get("target") or "host") != "host":
                continue
            pat = (r.get("pattern") or "").strip()
            if pat and pat not in out:
                out.append(pat)
        return out

    def is_in_scope(self, host: str) -> bool:
        # Local import: scope_utils ships with the scanner module to
        # keep the SDK importable without pulling in the scanner pkg
        # at module load.
        from .scanner.scope_utils import host_in_scope
        return host_in_scope(host or "", self._rules)

    def is_url_in_scope(self, url: str) -> bool:
        if not url:
            return False
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return False
        return self.is_in_scope(host)


# ---- Seed request (Send-to-plugin) ----------------------------------------

@dataclass
class SeedRequest:
    """Original HTTP request the plugin run was seeded from.

    Populated when the operator launched the plugin via the
    Send-to-plugin flow from History or the Proxy intercept queue.
    Plugin authors may ignore it (the chooser shows every plugin app)
    or use it to skip the user typing the URL by hand.

    ``raw`` is the full request blob exactly as captured. The
    convenience fields are best-effort parses; a malformed blob still
    yields a usable :class:`SeedRequest` (empty strings / lists, raw
    bytes preserved).
    """
    history_id: int
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = "/"
    headers: list[tuple[str, str]] = _field(default_factory=list)
    body: bytes = b""
    raw: bytes = b""

    def header(self, name: str) -> str:
        """Return the first header value matching ``name``
        (case-insensitive), or ``""`` if no such header is present."""
        target = name.lower()
        for k, v in self.headers:
            if k.lower() == target:
                return v
        return ""


def parse_seed_request(history_id: int, raw: bytes) -> SeedRequest:
    """Best-effort parse of a raw HTTP request blob into a
    :class:`SeedRequest`. Never raises — the runner cannot afford to
    crash on a malformed captured request."""
    raw = bytes(raw or b"")
    sep = raw.find(b"\r\n\r\n")
    head = raw[:sep] if sep >= 0 else raw
    body = raw[sep + 4:] if sep >= 0 else b""
    try:
        lines = head.decode("latin-1", errors="replace").split("\r\n")
    except Exception:
        lines = []
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
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    elif host:
        url = f"http://{host}{path}"
    else:
        url = path
    return SeedRequest(
        history_id=int(history_id), method=method, url=url, host=host,
        path=path, headers=headers, body=body, raw=raw,
    )



# ---- PluginContext ---------------------------------------------------------

class CancelledError(RuntimeError):
    """Raised when a plugin run is cancelled cooperatively. Plugins do
    NOT have to catch this; the runner catches it and records
    ``status = 'cancelled'``."""


class PluginContext:
    """Everything a plugin's ``run(ctx)`` function may touch.

    The context is constructed fresh for each run and never shared.
    All callbacks (log / progress / result) are *fire-and-forget*: a
    failure in the UI-update path must NEVER crash the plugin. The
    runner installs robust callbacks that swallow their own
    exceptions; plugin code never sees one.
    """

    def __init__(
        self,
        *,
        project: Any,
        slug: str,
        run_id: int,
        settings: dict[str, Any],
        scope: ScopeView,
        stop_event: threading.Event,
        on_log: Callable[[str, str], None] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        on_result: Callable[[dict], None] | None = None,
        oast: Any = None,
        seed_request: "SeedRequest | None" = None,
    ):
        self.project = project
        self.slug = slug
        self.run_id = int(run_id)
        self.settings = dict(settings)
        self.scope = scope
        self._stop = stop_event
        self._on_log = on_log
        self._on_progress = on_progress
        self._on_result = on_result
        self._oast = oast
        self.seed_request = seed_request

    # ---- cancellation ----
    def stop_requested(self) -> bool:
        """Cooperative cancel signal. Plugins should check this in
        their inner loop and return early when it flips to True."""
        return self._stop.is_set()

    def check_stop(self) -> None:
        """Raise :class:`CancelledError` if a stop has been requested.
        Convenience for plugins that want fail-fast cancel semantics."""
        if self._stop.is_set():
            raise CancelledError("plugin run cancelled by operator")

    def sleep(self, seconds: float) -> bool:
        """Sleep up to ``seconds`` seconds, returning early if a stop
        is signalled. Returns ``True`` if the full duration elapsed
        and the run should continue, ``False`` if a stop was signalled
        partway through. Plugin loops should prefer this over
        :func:`time.sleep` so cancel feels responsive."""
        # Event.wait returns True if the flag is set during the wait.
        return not self._stop.wait(timeout=max(0.0, float(seconds)))

    # ---- log / progress / results ----
    def log(self, msg: str, level: str = "info") -> None:
        if self._on_log is None:
            return
        try:
            self._on_log(str(level or "info"), str(msg))
        except Exception:
            pass

    def progress(self, done: int, total: int = 0, message: str = "") -> None:
        if self._on_progress is None:
            return
        try:
            self._on_progress(int(done), int(total), str(message))
        except Exception:
            pass

    def add_result(self, row: dict) -> None:
        """Append a row to the live results table.  Keys map to the
        ``columns`` declared on the plugin app; extra keys are kept
        as JSON-stringifiable values so plugins can attach evidence
        without losing it."""
        if self._on_result is None:
            return
        try:
            # Coerce to a plain dict so callers can pass dataclasses,
            # sqlite rows, etc. without surprises downstream.
            self._on_result(dict(row))
        except Exception:
            pass

    # ---- findings ----
    def record_finding(
        self, *,
        title: str,
        severity: str = "info",
        host: str = "",
        url: str = "",
        evidence: str = "",
        payload: str = "",
        description: str = "",
        remediation: str = "",
        cwe: str = "",
        owasp: str = "",
        references: list[str] | None = None,
        confidence: str = "firm",
        request_id: int | None = None,
        response_id: int | None = None,
    ) -> int:
        """Write a finding into the project's issues table tagged
        ``source = "plugin:<slug>"``. Returns the finding id (existing
        id when the dedupe key collides)."""
        return int(self.project.add_finding(
            title=str(title), severity=str(severity), host=str(host),
            url=str(url), evidence=str(evidence), payload=str(payload),
            description=str(description), remediation=str(remediation),
            cwe=str(cwe), owasp=str(owasp),
            references=list(references or []),
            confidence=str(confidence),
            request_id=request_id, response_id=response_id,
            source=f"plugin:{self.slug}",
            rule_id=f"plugin:{self.slug}",
        ))

    # ---- send (engine factory) ----
    def send(
        self, method: str, url: str, *,
        headers: list[tuple[str, str]] | None = None,
        body: bytes | str = b"",
        engine: str = "httpx",
        timeout: float = 30.0,
        follow_redirects: bool = False,
        verify: bool | str = False,
    ) -> Any:
        """Send a request via the configured engine. ``engine`` is one
        of ``httpx`` (default), ``raw``, ``h3``, or
        ``curl-cffi[:profile]``. Optional engines fall back to ``httpx``
        if the extra isn't installed. Returns a
        :class:`reqlore.engines.Response`.

        Errors propagate to the caller — the plugin chose to send, the
        plugin should decide what to do when the network blows up.
        """
        from .engines import Request
        from .engines import httpx_engine

        if isinstance(body, str):
            body_b = body.encode("utf-8", errors="replace")
        else:
            body_b = bytes(body or b"")
        req = Request(
            method=str(method).upper(),
            url=str(url),
            headers=list(headers or []),
            body=body_b,
            http_version="1.1",
        )

        eng = (engine or "httpx").strip()
        try:
            if eng.startswith("curl-cffi"):
                try:
                    from .engines import curl_cffi_engine
                except ImportError:
                    return httpx_engine.send(
                        req, timeout=timeout,
                        follow_redirects=follow_redirects, verify=verify,
                    )
                profile = eng.split(":", 1)[1] if ":" in eng else "chrome120"
                return curl_cffi_engine.send(
                    req, profile=profile, timeout=timeout,
                    follow_redirects=follow_redirects, verify=verify,
                )
            if eng == "raw":
                try:
                    from .engines import raw_engine
                    return raw_engine.send(req, verify=bool(verify), timeout=timeout)
                except ImportError:
                    return httpx_engine.send(
                        req, timeout=timeout,
                        follow_redirects=follow_redirects, verify=verify,
                    )
            if eng == "h3":
                try:
                    from .engines import h3_engine
                    return h3_engine.send(req, timeout=timeout, verify=bool(verify))
                except ImportError:
                    return httpx_engine.send(
                        req, timeout=timeout,
                        follow_redirects=follow_redirects, verify=verify,
                    )
            return httpx_engine.send(
                req, timeout=timeout,
                follow_redirects=follow_redirects, verify=verify,
            )
        except Exception as exc:
            # Don't swallow — surface as a Response with an `error`
            # field so plugins can log + continue without an
            # outer try/except.
            from .engines import Response, Timings
            return Response(
                status=0, reason="send failed", headers=[],
                body=b"", http_version="1.1", timings=Timings(),
                engine=eng, raw_request=None, error=str(exc),
            )

    # ---- OAST passthrough ----
    def oast_token(self) -> tuple[str, str] | None:
        """Request an OAST token + callback URL. Returns ``None`` when
        the OAST listener is not running (extras not installed,
        operator hasn't enabled it)."""
        if self._oast is None:
            return None
        try:
            if not self._oast.is_running():
                return None
            token = self._oast.new_token()
            url = self._oast.url_for(token)
            return (str(token), str(url))
        except Exception:
            return None

    def oast_interactions(self, token: str) -> list[Any]:
        """Poll OAST for interactions on ``token``. Returns ``[]`` when
        OAST isn't available."""
        if self._oast is None or not token:
            return []
        try:
            return list(self._oast.interactions(token=token))
        except Exception:
            return []


# ---- PluginApp + make_app --------------------------------------------------

class PluginApp:
    """Metadata + runner for one standalone plugin (Phase 16).

    Plugin authors construct via :func:`make_app` and attach the run
    function via the :meth:`runner` decorator. The host process never
    invokes the runner directly — the :class:`PluginRunner` thread
    pool calls it inside a guarded context with a fresh
    :class:`PluginContext`.
    """

    def __init__(
        self, *,
        slug: str,
        name: str,
        description: str = "",
        author: str = "",
        version: str = "0.1",
        fields: Sequence[Field] = (),
        columns: Sequence[str] = (),
        timeout_s: int = 3600,
        tags: Sequence[str] = (),
        category: str = "general",
    ):
        self.slug = _check_slug(slug)
        self.name = str(name).strip() or self.slug
        self.description = str(description or "")
        self.author = str(author or "")
        self.version = str(version or "0.1")
        # Defensive copies so callers can't mutate registry state by
        # tweaking the list they passed in.
        seen_names: set[str] = set()
        field_list: list[Field] = []
        for f in fields:
            if not isinstance(f, Field):
                raise TypeError(
                    f"{type(f).__name__} is not a Field; use StrField, "
                    f"IntField, BoolField, TextField, SelectField, or a "
                    f"Field subclass")
            if f.name in seen_names:
                raise ValueError(
                    f"plugin app {self.slug!r}: duplicate field name {f.name!r}")
            seen_names.add(f.name)
            field_list.append(f)
        self.fields: list[Field] = field_list
        self.columns: list[str] = [str(c) for c in (columns or [])]
        if timeout_s < 5:
            raise ValueError("PluginApp.timeout_s must be >= 5")
        self.timeout_s = int(timeout_s)
        self.tags: list[str] = [str(t) for t in (tags or [])]
        self.category = str(category or "general")
        self._runner_fn: Callable[[PluginContext], Any] | None = None

    def runner(self, fn: Callable[[PluginContext], Any]) -> Callable[[PluginContext], Any]:
        """Decorator: register the entry point.  The function MUST take
        a single :class:`PluginContext` argument."""
        if not callable(fn):
            raise TypeError("PluginApp.runner expects a callable")
        self._runner_fn = fn
        return fn

    @property
    def runner_fn(self) -> Callable[[PluginContext], Any] | None:
        return self._runner_fn

    def is_runnable(self) -> bool:
        return self._runner_fn is not None

    def field_dicts(self) -> list[dict[str, Any]]:
        return [f.render_dict() for f in self.fields]

    def validate_settings(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Validate a raw form dict and return a normalised settings
        dict. Raises :class:`ValueError` on the first failure with a
        human-readable message naming the field."""
        raw = dict(raw or {})
        out: dict[str, Any] = {}
        for f in self.fields:
            # ``raw.get`` returns the empty string when an HTML <input>
            # is present but blank; missing keys (unchecked
            # checkboxes) become None which BoolField interprets as
            # False.
            val = raw.get(f.name)
            out[f.name] = f.validate(val)
        return out


def make_app(
    *,
    slug: str,
    name: str,
    description: str = "",
    author: str = "",
    version: str = "0.1",
    fields: Sequence[Field] = (),
    columns: Sequence[str] = (),
    timeout_s: int = 3600,
    tags: Sequence[str] = (),
    category: str = "general",
) -> PluginApp:
    """Build a :class:`PluginApp`. Plugin authors call this at module
    top level and assign the result to ``PLUGIN_APP``.

    Example::

        from reqlore import plugins_sdk as sdk

        PLUGIN_APP = sdk.make_app(
            slug="echo",
            name="Echo",
            description="Send one request and show the response.",
            fields=[
                sdk.StrField("url", required=True),
                sdk.SelectField("method", choices=["GET","POST"]),
            ],
            columns=["status", "length", "body_excerpt"],
        )

        @PLUGIN_APP.runner
        def run(ctx):
            resp = ctx.send(ctx.settings["method"], ctx.settings["url"])
            ctx.add_result({
                "status": resp.status,
                "length": len(resp.body),
                "body_excerpt": resp.body[:200].decode(errors="replace"),
            })
    """
    return PluginApp(
        slug=slug, name=name, description=description, author=author,
        version=version, fields=fields, columns=columns,
        timeout_s=timeout_s, tags=tags, category=category,
    )
