"""Sequencer **live capture**.

The classic Sequencer page is paste-only: the operator collects tokens
themselves (curl loop, Intruder scrape) and pastes them into the
textarea. The live-capture workflow streamlines that: point at a
request, tell Reqlore which response field holds the token, press
start, and Reqlore re-fires the request thousands of times in the
background, extracts the token from each response, and updates the
statistics live.

This module provides that workflow. It is intentionally
a thin shell around the same primitives Intruder already uses:

* `Project` for persistent storage of captures and samples,
* `template_to_request` + the four `engines.*` modules for sending,
* a `threading.Thread`-based runner with cancel / pause / resume,
* a per-process registry indexed by capture id.

Extractors
==========

A capture stores ``extractor_kind`` and ``extractor_arg``:

* ``cookie`` -- ``arg`` is the cookie name; pulled from every
  ``Set-Cookie`` response header.
* ``header`` -- ``arg`` is the response header name (case-insensitive).
* ``regex``  -- ``arg`` is a regex with one capturing group, run against
  the decoded response body.
* ``json``   -- ``arg`` is a dotted path (``a.b.c``) into a JSON body.
  List indices via integers (``items.0.token``).

Each extractor returns ``str | None``; ``None`` means "no token in this
response" and the runner records nothing for that seq but counts it as
an error.
"""
from __future__ import annotations

import contextlib
import json
import re
import threading
import time
from typing import Any

from .engines import Request, Response, httpx_engine, raw_engine
from .intruder import template_to_request

EXTRACTOR_KINDS: tuple[str, ...] = ("cookie", "header", "regex", "json")

_DEFAULT_TIMEOUT = 15.0
_MAX_TOKEN_LEN = 4096  # truncate absurdly long tokens before storing


# ---------- extractors ----------

_COOKIE_RE = re.compile(r"^\s*([^=;\s]+)\s*=\s*([^;]*)")


def _extract_cookie(name: str, resp: Response) -> str | None:
    """Return the value of ``Set-Cookie: <name>=...`` from ``resp``.

    Multiple ``Set-Cookie`` headers are common; we return the first that
    matches the requested name. Cookie attributes (``Path``, ``HttpOnly``,
    etc.) are stripped.
    """
    if not name:
        return None
    needle = name.strip()
    for k, v in resp.headers:
        if k.lower() != "set-cookie":
            continue
        m = _COOKIE_RE.match(v)
        if not m:
            continue
        if m.group(1) == needle:
            return m.group(2).strip()
    return None


def _extract_header(name: str, resp: Response) -> str | None:
    if not name:
        return None
    needle = name.lower().strip()
    for k, v in resp.headers:
        if k.lower() == needle:
            return v.strip()
    return None


def _extract_regex(pattern: str, resp: Response) -> str | None:
    if not pattern:
        return None
    try:
        rx = re.compile(pattern)
    except re.error:
        return None
    body = (resp.body or b"").decode("utf-8", errors="replace")
    m = rx.search(body)
    if not m:
        return None
    # Prefer the first capture group; fall back to the whole match.
    return (m.group(1) if m.groups() else m.group(0))


def _walk_json(path: str, doc: Any) -> Any:
    cur = doc
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                return None
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur


def _extract_json(path: str, resp: Response) -> str | None:
    if not path:
        return None
    body = (resp.body or b"").decode("utf-8", errors="replace")
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    val = _walk_json(path, doc)
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return json.dumps(val, separators=(",", ":"), sort_keys=True)
    return str(val)


def extract_token(kind: str, arg: str, resp: Response) -> str | None:
    """Apply the named extractor; return ``None`` on failure.

    Unknown ``kind`` returns ``None`` rather than raising so a bad
    config never kills the runner thread.
    """
    tok: str | None
    if kind == "cookie":
        tok = _extract_cookie(arg, resp)
    elif kind == "header":
        tok = _extract_header(arg, resp)
    elif kind == "regex":
        tok = _extract_regex(arg, resp)
    elif kind == "json":
        tok = _extract_json(arg, resp)
    else:
        return None
    if tok is None:
        return None
    if len(tok) > _MAX_TOKEN_LEN:
        return tok[:_MAX_TOKEN_LEN]
    return tok


# ---------- runner ----------

def _engine_send(engine: str, req: Request, *, timeout: float) -> Response:
    """Pick the send function for ``engine``.

    Only stdlib engines (``httpx`` and ``raw``) are wired in here. Live
    capture is a tight loop of identical requests against a single URL,
    so engine choice has minimal impact on the science -- exotic engines
    (curl-cffi browser profiles, HTTP/3) can be added without changing
    the analysis layer if a target ever needs them.
    """
    if engine == "raw":
        return raw_engine.send(req, verify=False, timeout=timeout)
    return httpx_engine.send(req, verify=False, timeout=timeout,
                              follow_redirects=False)


class CaptureRunner:
    """Threaded runner mirroring :class:`reqlore.intruder.AttackRunner`.

    Cancellable via :meth:`cancel`, pausable via :meth:`pause` /
    :meth:`resume`. Stops automatically once ``max_samples`` tokens have
    been collected.
    """

    def __init__(self, project: Any, capture_id: int):
        self.project = project
        self.capture_id = capture_id
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()  # not paused by default
        self._thread: threading.Thread | None = None
        self._done = threading.Event()
        self.collected: int = 0
        self.errors: int = 0
        self.stop_reason: str = ""

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def is_paused(self) -> bool:
        return not self._pause.is_set() and not self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        self._pause.clear()
        # status update best-effort
        with contextlib.suppress(Exception):
            self.project.set_sequencer_capture_status(self.capture_id, "paused")

    def resume(self) -> None:
        self._pause.set()
        with contextlib.suppress(Exception):
            self.project.set_sequencer_capture_status(self.capture_id, "running")

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    def start(self) -> None:
        if self.is_running():
            return
        self._done.clear()
        self._cancel.clear()
        self._pause.set()
        self._thread = threading.Thread(
            target=self._run, name=f"seqcap-{self.capture_id}", daemon=True,
        )
        self._thread.start()

    # -- internals -------------------------------------------------

    def _run(self) -> None:
        try:
            cap = self.project.get_sequencer_capture(self.capture_id)
            if not cap:
                return
            self.project.set_sequencer_capture_status(
                self.capture_id, "running", stop_reason="", error_count=0,
            )
            template = cap["template"]
            url = cap["url"]
            engine = cap["engine"]
            kind = cap["extractor_kind"]
            arg = cap["extractor_arg"]
            max_samples = int(cap["max_samples"])
            delay_ms = max(0, int(cap["delay_ms"]))
            # Resume an existing capture by continuing past the last seq;
            # this lets the operator pause + add more samples without
            # destroying the already-collected ones.
            self.collected = self.project.count_sequencer_samples(self.capture_id)
            seq = self.collected

            try:
                req = template_to_request(template, url)
            except Exception as exc:  # noqa: BLE001
                self.stop_reason = f"bad request template: {exc}"
                self.project.set_sequencer_capture_status(
                    self.capture_id, "errored", stop_reason=self.stop_reason,
                )
                return

            while self.collected < max_samples:
                self._pause.wait()
                if self._cancel.is_set():
                    break
                seq += 1
                t0 = time.monotonic()
                try:
                    resp = _engine_send(engine, req, timeout=_DEFAULT_TIMEOUT)
                except Exception as exc:  # noqa: BLE001
                    self.errors += 1
                    self.project.set_sequencer_capture_status(
                        self.capture_id, "running", error_count=self.errors,
                    )
                    if self.errors >= 10 and self.collected == 0:
                        self.stop_reason = (
                            f"10 consecutive send failures; last: "
                            f"{exc.__class__.__name__}: {exc}"
                        )
                        self._cancel.set()
                        break
                    if delay_ms:
                        time.sleep(delay_ms / 1000.0)
                    continue

                tok = extract_token(kind, arg, resp)
                dur = int((time.monotonic() - t0) * 1000)
                if tok is None:
                    self.errors += 1
                    if self.errors >= 10 and self.collected == 0:
                        self.stop_reason = (
                            f"10 responses without an extractable token; "
                            f"check the {kind}={arg!r} extractor"
                        )
                        self._cancel.set()
                        break
                else:
                    self.project.add_sequencer_sample(
                        capture_id=self.capture_id, seq=seq, token=tok,
                        status=resp.status, duration_ms=dur,
                    )
                    self.collected += 1
                self.project.set_sequencer_capture_status(
                    self.capture_id, "running", error_count=self.errors,
                )
                if delay_ms:
                    time.sleep(delay_ms / 1000.0)

            if self._cancel.is_set() and not self.stop_reason:
                self.project.set_sequencer_capture_status(
                    self.capture_id, "cancelled", error_count=self.errors,
                )
            elif self.stop_reason:
                self.project.set_sequencer_capture_status(
                    self.capture_id, "errored",
                    stop_reason=self.stop_reason, error_count=self.errors,
                )
            else:
                self.project.set_sequencer_capture_status(
                    self.capture_id, "done",
                    stop_reason=f"reached max_samples ({max_samples})",
                    error_count=self.errors,
                )
        finally:
            self._done.set()

# ---------- per-process registry ----------

_REGISTRY: dict[int, CaptureRunner] = {}
_REG_LOCK = threading.Lock()


def get_runner(capture_id: int) -> CaptureRunner | None:
    with _REG_LOCK:
        return _REGISTRY.get(capture_id)


def register(runner: CaptureRunner) -> None:
    with _REG_LOCK:
        _REGISTRY[runner.capture_id] = runner


def unregister(capture_id: int) -> None:
    with _REG_LOCK:
        _REGISTRY.pop(capture_id, None)


# ---------- helpers for the blueprint ----------

def parse_target_from_history(req_blob: bytes, url_hint: str) -> dict:
    """Return a dict suitable for ``create_sequencer_capture`` after
    inspecting a History request.

    Picks a sensible default extractor by sniffing the request: if the
    request sends a session cookie back to the same host (a common
    pattern for testing the session-cookie generator), suggest a
    ``cookie`` extractor with that cookie's name.
    """
    from .web.send_targets import parse_raw_request
    parsed = parse_raw_request(req_blob)
    # Default to looking for the most common session cookie names.
    default = ("cookie", "")
    for k, v in parsed.headers:
        if k.lower() != "cookie":
            continue
        for piece in v.split(";"):
            piece = piece.strip()
            if not piece or "=" not in piece:
                continue
            name = piece.split("=", 1)[0].strip()
            if name.lower() in (
                "sessionid", "session", "session_id", "phpsessid", "jsessionid",
                "asp.net_sessionid", "connect.sid", "auth", "token", "_token",
            ):
                default = ("cookie", name)
                break
        if default[1]:
            break
    return {
        "url": url_hint,
        "template": req_blob,
        "extractor_kind": default[0],
        "extractor_arg": default[1],
    }
