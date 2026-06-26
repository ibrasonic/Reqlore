"""Thin wrapper around mitmproxy's library API.

Runs the proxy in a background thread, mirrors every request/response into the
project history, applies Match & Replace rules, and supports both async-hold
(record-and-forward) and sync-hold (block until UI forwards/drops/edits).
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import urllib.parse
import uuid
from typing import Any

from ..storage import Project
from ..scanner.scope_utils import host_in_scope, load_scope_rules
from .ca import ensure_ca
from .matchreplace import MRRule, apply_request, apply_response, from_row
from .rules import (
    InterceptConfig, Rule, should_hold_request, should_hold_response,
)

log = logging.getLogger("reqlore.proxy")


HOLD_POLL_MS = 100
HOLD_TIMEOUT_S = 600  # 10 min: tunable

# Phase 15 — redirect-aware intercept. When the operator forwards a held
# request whose response is 3xx, the browser issues a follow-up request
# to the Location target. We stash (parent_iid, ts) for that target so
# the next request hook can mark the follow-up as a child of the
# original.  TTL keeps the cache from accumulating stale entries when
# the browser never actually navigates.
_REDIRECT_TTL_S = 30.0


def _load_mr(project: Project) -> list[MRRule]:
    return [from_row(r) for r in project.list_mr()]


# Hostnames that always resolve to "this machine". Used together with the
# Reqlore UI port to make sure we never accidentally hold a request that
# the operator's browser is making *to* the Reqlore web UI itself.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"})


def _host_port_from_header(host_hdr: str) -> tuple[str, int]:
    """Parse a 'Host:' header value into (host_lower, port). Port is 0
    when the header has no explicit port."""
    if not host_hdr:
        return "", 0
    s = host_hdr.strip()
    # Strip IPv6 brackets while keeping the address.
    if s.startswith("["):
        end = s.find("]")
        if end > 0:
            h = s[1:end].lower()
            rest = s[end + 1:]
            if rest.startswith(":"):
                try:
                    return h, int(rest[1:])
                except ValueError:
                    return h, 0
            return h, 0
    if ":" in s:
        h, _, p = s.rpartition(":")
        try:
            return h.lower(), int(p)
        except ValueError:
            return s.lower(), 0
    return s.lower(), 0


def _is_self_ui_request(req: Any, ui_port: int) -> bool:
    """True if this request is targeting the Reqlore UI itself.
    Belt-and-braces: matches on req.port, req.pretty_host, and the
    Host header so we never hold the operator's own browser tab.
    """
    if ui_port <= 0:
        return False
    # 1. Direct attribute check
    try:
        host = (req.pretty_host or "").lower()
    except Exception:
        host = ""
    try:
        port = int(req.port or 0)
    except Exception:
        port = 0
    if port == ui_port and host in _LOCAL_HOSTS:
        return True
    # 2. Host-header check — covers the case where pretty_host/port
    #    aren't populated as expected for proxied requests.
    try:
        host_hdr = req.headers.get("host", "") or req.headers.get("Host", "")
    except Exception:
        host_hdr = ""
    h2, p2 = _host_port_from_header(host_hdr)
    if p2 == ui_port and h2 in _LOCAL_HOSTS:
        return True
    # 3. URL prefix as last resort.
    try:
        url = (req.pretty_url or "").lower()
    except Exception:
        url = ""
    for h in _LOCAL_HOSTS:
        if url.startswith(f"http://{h}:{ui_port}/") or \
           url.startswith(f"https://{h}:{ui_port}/"):
            return True
    return False


# Backwards-compatible shim kept for the existing unit test.
def _is_self_ui(host: str, port: int, ui_port: int) -> bool:
    if ui_port <= 0 or port != ui_port:
        return False
    return (host or "").lower() in _LOCAL_HOSTS


class _HistoryAddon:
    def __init__(self, project: Project, rules: list[Rule], sync_hold: bool,
                 ui_port: int = 0, ui_port_fn: Any = None,
                 live_enqueue: Any = None,
                 auth_matrix_enqueue: Any = None,
                 cfg_reader: Any = None):
        self.project = project
        self.rules = rules
        self.sync_hold = sync_hold
        # ui_port may be wrong at addon construction time (e.g. the user
        # started the proxy via CLI before the web app told it its real
        # port). Accept a callable that returns the *current* value so
        # the controller can update it later without re-creating us.
        if ui_port_fn is None:
            ui_port_fn = lambda p=ui_port: p  # noqa: E731
        self._ui_port_fn = ui_port_fn
        # Phase 1 — optional live-scan callback. Called with the
        # freshly-inserted history-row id after every recorded
        # response. Wrapped in try/except at the call site so a slow
        # or broken scanner can never block the proxy event loop.
        self._live_enqueue = live_enqueue
        # Phase 17 — optional Auth Matrix shadow callback. Same
        # contract as ``live_enqueue``: drop-on-overflow, never
        # blocks the event loop, the worker itself enforces scope.
        self._auth_matrix_enqueue = auth_matrix_enqueue
        # Phase 18 — callable returning the live InterceptConfig so
        # the addon can read runtime-mutable flags (currently just
        # ``restrict_to_scope``) without recreating the addon when
        # the operator edits the filter from the UI.
        self._cfg_reader = cfg_reader
        # Phase 15 — redirect chain linkage. Keyed by the absolute
        # URL the parent's Location pointed at; value is
        # (parent_intercept_id, monotonic_ts).  Single-process lock
        # because the addon runs on mitmproxy's single event loop
        # but `_sync_hold` may sit awaiting alongside other flow
        # hooks.
        self._redirect_cache: dict[str, tuple[int, float]] = {}
        self._redirect_lock = threading.Lock()

    # ----- Phase 15: redirect chain helpers -----
    def _prune_redirect_cache(self, now: float) -> None:
        """Drop entries older than ``_REDIRECT_TTL_S`` seconds.  Must
        be called with ``_redirect_lock`` held."""
        stale = [k for k, (_, ts) in self._redirect_cache.items()
                 if now - ts > _REDIRECT_TTL_S]
        for k in stale:
            self._redirect_cache.pop(k, None)

    def _consume_redirect_parent(self, url: str) -> int | None:
        """Pop and return the parent intercept id for ``url`` if one
        was stashed within the TTL window, else None."""
        if not url:
            return None
        with self._redirect_lock:
            now = time.monotonic()
            self._prune_redirect_cache(now)
            hit = self._redirect_cache.pop(url, None)
        if hit is None:
            return None
        parent_iid, _ = hit
        return parent_iid

    def _stash_redirect_parent(self, url: str, parent_iid: int) -> None:
        """Record ``parent_iid`` as the parent of any future request to
        ``url``.  No-op when ``url`` is empty or ``parent_iid`` is 0."""
        if not url or not parent_iid:
            return
        with self._redirect_lock:
            now = time.monotonic()
            self._prune_redirect_cache(now)
            self._redirect_cache[url] = (parent_iid, now)

    # ----- request hook -----
    async def request(self, flow: Any) -> None:
        try:
            req = flow.request
            host = req.pretty_host or ""

            # DOM Hunter: if `document.referrer` is in the auto-inject
            # list, splice the canary into the Referer header of every
            # in-scope request. Runs BEFORE Match & Replace so the user
            # can still override via an M&R rule if they want. Only
            # rewrites an EXISTING Referer; never synthesises one (a
            # missing Referer is usually intentional -- Referrer-Policy:
            # no-referrer, cross-origin downgrade, etc.). See
            # reqlore.dom_hunter.inject_referer_canary.
            try:
                from .. import dom_hunter as _dh
                if _dh.should_inject_referer(self.project, host):
                    cur = list(req.headers.items())
                    # Use the "-r" tagged canary variant so DOM Hunter's
                    # source attribution can prove the value flowed in
                    # via the Referer header (exact substring match)
                    # instead of guessing from co-occurrence with
                    # location.hash / search / window.name.
                    base = _dh.get_or_make_canary(self.project)
                    new = _dh.inject_referer_canary(
                        cur,
                        _dh.tagged_canary(base, "document.referrer"),
                    )
                    if new != cur:
                        req.headers.clear()
                        for k, v in new:
                            req.headers[k] = v
            except Exception:
                log.exception("DOM Hunter referer injection failed")

            # Match & Replace on the way out
            mr = _load_mr(self.project)
            if mr:
                hdrs = list(req.headers.items())
                body = bytes(req.raw_content or b"")
                new_h, new_b = apply_request(mr, host, hdrs, body)
                if new_h != hdrs or new_b != body:
                    req.headers.clear()
                    for k, v in new_h:
                        req.headers[k] = v
                    req.set_content(new_b)

            # Never hold a request the browser is making to the Reqlore UI
            # itself, otherwise turning intercept ON locks the operator out
            # of the very panel they need to forward/drop intercepts from.
            ui_port = int(self._ui_port_fn() or 0)
            if _is_self_ui_request(req, ui_port):
                return

            # Phase 15 — if this request's URL is the Location target
            # of a recently-forwarded held request, mark it as the
            # child of that intercept so the queue UI can show the
            # redirect chain.
            try:
                parent_iid = self._consume_redirect_parent(req.pretty_url or "")
            except Exception:
                # Defence in depth: cache failures must never block
                # the proxy. We just lose the link badge.
                log.exception("redirect-cache lookup failed")
                parent_iid = None

            if should_hold_request(self.rules, host, req.method,
                                   req.path or ""):
                # Phase 18 — opt-in: if restrict_to_scope is on, never
                # hold requests for hosts outside the project's Sitemap
                # scope rules. Lets the operator browse non-target
                # sites without manually toggling intercept off.
                if self._cfg_reader is not None:
                    try:
                        cfg = self._cfg_reader()
                    except Exception:
                        cfg = None
                    if cfg is not None and getattr(
                            cfg, "restrict_to_scope", False):
                        if not host_in_scope(
                                host, load_scope_rules(self.project)):
                            return
                if self.sync_hold:
                    await self._sync_hold(
                        "request", flow, _serialise_request(req),
                        "rule:request", apply_to_request=True,
                        parent_intercept_id=parent_iid)
                else:
                    self.project.enqueue_intercept(
                        "request", _serialise_request(req), "rule:request",
                        parent_intercept_id=parent_iid,
                    )
        except Exception:
            log.exception("request hook failed")

    # ----- response hook -----
    async def response(self, flow: Any) -> None:
        try:
            req = flow.request
            resp = flow.response
            host = req.pretty_host or ""

            mr = _load_mr(self.project)
            if mr:
                hdrs = list(resp.headers.items())
                body = bytes(resp.raw_content or b"")
                new_h, new_b = apply_response(mr, host, hdrs, body)
                if new_h != hdrs or new_b != body:
                    resp.headers.clear()
                    for k, v in new_h:
                        resp.headers[k] = v
                    resp.set_content(new_b)

            method = req.method
            url = req.pretty_url
            status = int(resp.status_code)
            duration_ms = int(getattr(flow, "duration", 0.0) * 1000)
            raw_req = _serialise_request(req)
            raw_resp = _serialise_response(resp)
            hid = self.project.add_history(
                host=host, method=method, url=url, status=status,
                duration_ms=duration_ms, engine="proxy",
                raw_req=raw_req, raw_resp=raw_resp,
            )
            # Phase 1 — hand the freshly-inserted row off to the live
            # scanner. ``put_nowait`` semantics inside the callback
            # mean we never block the event loop; the broad except
            # below is belt-and-braces in case a third-party
            # implementation raises something unexpected.
            if self._live_enqueue is not None and hid:
                try:
                    self._live_enqueue(int(hid))
                except Exception:
                    log.exception("live scan enqueue failed for hid=%s", hid)
            # Phase 17 — Auth Matrix passive shadow. Same defensive
            # wrapping: a broken worker can never stall the proxy.
            if self._auth_matrix_enqueue is not None and hid:
                try:
                    self._auth_matrix_enqueue(int(hid))
                except Exception:
                    log.exception(
                        "auth-matrix shadow enqueue failed for hid=%s", hid)
            # Same self-bypass as the request hook: never hold responses
            # coming from the Reqlore UI itself, otherwise the panel's
            # own redirects (e.g. the 302 from /proxy/intercept/toggle)
            # get queued and lock the operator out.
            ui_port = int(self._ui_port_fn() or 0)
            if _is_self_ui_request(req, ui_port):
                return

            # Phase 15 — if this response is a 3xx for a flow we held
            # on the request leg, stash the Location target so the
            # browser's follow-up request gets linked to this intercept.
            try:
                parent_iid = getattr(flow, "_reqlore_iid", None)
                if parent_iid and 300 <= status < 400:
                    loc = (resp.headers.get("location")
                            or resp.headers.get("Location") or "").strip()
                    if loc:
                        abs_url = urllib.parse.urljoin(url, loc)
                        self._stash_redirect_parent(abs_url, int(parent_iid))
            except Exception:
                log.exception("redirect-cache stash failed")

            if should_hold_response(self.rules, status, resp.headers.get("content-type", "")):
                if self.sync_hold:
                    await self._sync_hold(
                        "response", flow, raw_resp,
                        "rule:response", apply_to_request=False)
                else:
                    self.project.enqueue_intercept(
                        "response", raw_resp, "rule:response",
                    )
        except Exception:
            log.exception("response hook failed")

    # ----- sync intercept (blocks this flow only, not the event loop) -----
    async def _sync_hold(self, kind: str, flow: Any, raw: bytes, reason: str,
                          *, apply_to_request: bool,
                          parent_intercept_id: int | None = None) -> None:
        """Park the flow until the operator decides forward / drop / edit.
        Critically: ``await asyncio.sleep`` yields control back to
        mitmproxy's event loop so OTHER flows keep being processed (and
        the Reqlore UI's own traffic keeps flowing through the self-
        bypass). A blocking ``time.sleep`` here would freeze the whole
        proxy until this single flow is decided — which is exactly the
        "everything is now held" symptom we just fixed.
        """
        flow_id = uuid.uuid4().hex
        iid = self.project.enqueue_intercept_sync(
            kind, raw, reason, flow_id,
            parent_intercept_id=parent_intercept_id,
        )
        # Phase 15: tag the flow so the response hook knows this is the
        # parent of any subsequent redirect target.  ``flow`` is a
        # mitmproxy HTTPFlow which accepts arbitrary attributes.
        try:
            flow._reqlore_iid = iid
        except Exception:
            pass
        deadline = time.monotonic() + HOLD_TIMEOUT_S
        while time.monotonic() < deadline:
            decision, edited = self.project.get_intercept_decision(iid)
            if decision in ("forward", "drop", "forward_edited"):
                if decision == "drop":
                    flow.kill()
                elif decision == "forward_edited" and edited is not None:
                    if apply_to_request:
                        _apply_raw_to_request(flow.request, edited)
                    else:
                        _apply_raw_to_response(flow.response, edited)
                return
            await asyncio.sleep(HOLD_POLL_MS / 1000.0)
        # timeout: just forward
        log.warning("intercept %d timed out; forwarding", iid)


def _serialise_request(req: Any) -> bytes:
    head = f"{req.method} {req.path} HTTP/{req.http_version.split('/')[-1] if isinstance(req.http_version, str) else '1.1'}\r\n"
    for k, v in req.headers.items():
        head += f"{k}: {v}\r\n"
    return head.encode("latin-1", errors="replace") + b"\r\n" + bytes(req.raw_content or b"")


def _serialise_response(resp: Any) -> bytes:
    head = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
    for k, v in resp.headers.items():
        head += f"{k}: {v}\r\n"
    return head.encode("latin-1", errors="replace") + b"\r\n" + bytes(resp.raw_content or b"")


def _apply_raw_to_request(req: Any, raw: bytes) -> None:
    sep = raw.find(b"\r\n\r\n")
    head, body = (raw[:sep], raw[sep + 4:]) if sep >= 0 else (raw, b"")
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            req.method = parts[0]
            req.path = parts[1]
    req.headers.clear()
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            req.headers[k.strip()] = v.strip()
    req.set_content(body)


def _apply_raw_to_response(resp: Any, raw: bytes) -> None:
    sep = raw.find(b"\r\n\r\n")
    head, body = (raw[:sep], raw[sep + 4:]) if sep >= 0 else (raw, b"")
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            try:
                resp.status_code = int(parts[1])
            except ValueError:
                pass
            if len(parts) >= 3:
                resp.reason = parts[2]
    resp.headers.clear()
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp.headers[k.strip()] = v.strip()
    resp.set_content(body)


class ProxyController:
    """Owns a mitmproxy DumpMaster running in a worker thread."""

    def __init__(self, project: Project, host: str, port: int, ca_dir,
                 *, sync_hold: bool = True, ui_port: int = 0):
        self.project = project
        self.host = host
        self.port = port
        self.ca_dir = ca_dir
        self.rules: list[Rule] = []
        # The intercept toggle inserts a *single* rule built from the
        # current InterceptConfig. Defaults to "state-changing methods
        # only, exclude browser noise" so flipping intercept on doesn't
        # bury the operator under hundreds of asset requests.
        self._intercept_cfg = InterceptConfig()
        self.sync_hold = sync_hold
        self.ui_port = ui_port
        self._thread: threading.Thread | None = None
        self._master: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        # Phase 1 — live passive scan worker. Wired by the web app at
        # boot when the project flag ``live_scan:enabled`` is on.
        # ``None`` means "do not enqueue"; the addon falls back to its
        # historical no-live-scan behaviour. The attribute is public
        # so the scanner blueprint can flip it at runtime without
        # restarting the proxy.
        self.live_worker: Any = None
        # Phase 17 — Auth Matrix passive shadow worker. Same pattern
        # as ``live_worker``: wired at boot from the web app, public
        # so the auth-matrix blueprint can flip it at runtime, and
        # an unset value means "do not shadow".
        self.auth_matrix_shadow: Any = None
        ensure_ca(ca_dir)

    def set_intercept(self, on: bool,
                      config: InterceptConfig | None = None) -> None:
        """Global intercept switch: when on, hold requests that match
        the current InterceptConfig. Mutates self.rules in place so the
        running mitmproxy addon (which holds a reference to the same
        list) sees the change.
        """
        if config is not None:
            self._intercept_cfg = config
        self.rules.clear()
        if on:
            self.rules.append(self._intercept_cfg.to_rule())

    def set_intercept_config(self, config: InterceptConfig) -> None:
        """Replace the intercept filter while keeping intercept's on/off
        state. Rebuilds the active rule if intercept is currently on.
        """
        was_on = self.intercept_on()
        self._intercept_cfg = config
        if was_on:
            self.rules.clear()
            self.rules.append(config.to_rule())

    def get_intercept_config(self) -> InterceptConfig:
        return self._intercept_cfg

    def intercept_on(self) -> bool:
        return bool(self.rules)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="reqlore-proxy", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._master is None or self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._master.shutdown)
        except RuntimeError:
            # Loop already closed in a race with another caller; nothing to do.
            return
        # Wait for the proxy thread to actually exit before returning. Without
        # this, the main process can drop out of cmd_both while the loop is
        # mid-cleanup, leaving the held-request sleep task and the mitmproxy
        # accept_coro pending — Windows ProactorEventLoop then prints
        # "Task was destroyed but it is pending!" on shutdown.
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=5.0)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ----- live passive scan -----
    def _live_enqueue(self, hid: int) -> None:
        """Forward a history-row id to the live worker if one is
        attached. Pulled apart from the addon so the worker can be
        swapped at runtime (``self.live_worker = ...``) without
        recreating the mitmproxy addon — the addon captures the bound
        method once at startup and we keep the indirection here.
        """
        w = self.live_worker
        if w is None:
            return
        try:
            w.enqueue(int(hid))
        except Exception:
            log.exception("live worker enqueue failed for hid=%s", hid)

    # ----- Auth Matrix passive shadow -----
    def _auth_matrix_enqueue(self, hid: int) -> None:
        """Forward a history-row id to the Auth Matrix shadow worker
        if one is attached. Same swap-at-runtime indirection as
        :meth:`_live_enqueue`."""
        w = self.auth_matrix_shadow
        if w is None:
            return
        try:
            w.enqueue(int(hid))
        except Exception:
            log.exception(
                "auth-matrix shadow enqueue failed for hid=%s", hid)

    def _run(self) -> None:
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster
        except Exception:
            log.exception("mitmproxy not installed correctly")
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # H-1: validate upstream TLS certificates by default. Operators
        # working against staging targets that legitimately use self-signed
        # certs can opt back in by exporting ``REQLORE_PROXY_SSL_INSECURE=1``
        # in their environment. The default of ``False`` means an attacker
        # can no longer transparently MITM Reqlore's own upstream
        # connections from a hostile network.
        ssl_insecure = os.environ.get(
            "REQLORE_PROXY_SSL_INSECURE", "").strip() in ("1", "true", "yes")
        opts = Options(
            listen_host=self.host,
            listen_port=self.port,
            confdir=str(self.ca_dir),
            ssl_insecure=ssl_insecure,
        )
        try:
            self._master = DumpMaster(
                opts, with_termlog=False, with_dumper=False, loop=self._loop,
            )
        except TypeError:
            # Older mitmproxy releases don't accept loop=; fall back to constructing
            # the master inside the loop so asyncio.get_running_loop() succeeds.
            async def _make() -> DumpMaster:
                return DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master = self._loop.run_until_complete(_make())
        self._master.addons.add(
            _HistoryAddon(self.project, self.rules, self.sync_hold,
                          ui_port_fn=lambda: self.ui_port,
                          live_enqueue=self._live_enqueue,
                          auth_matrix_enqueue=self._auth_matrix_enqueue,
                          cfg_reader=self.get_intercept_config))
        try:
            self._loop.run_until_complete(self._master.run())
        except Exception:
            log.exception("proxy crashed")
        finally:
            # Cancel any tasks still pending — the held-request poll loop in
            # _sync_hold(), mitmproxy's IocpProactor.accept coroutine, etc. —
            # so they don't leak as "Task was destroyed but it is pending!"
            # warnings on Windows ProactorEventLoop when the loop closes.
            try:
                pending = [t for t in asyncio.all_tasks(self._loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            except Exception:
                log.exception("error while draining proxy event loop")
            try:
                self._loop.close()
            except Exception:
                pass
