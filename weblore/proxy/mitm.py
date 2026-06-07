"""Thin wrapper around mitmproxy's library API.

Runs the proxy in a background thread, mirrors every request/response into the
project history, applies Match & Replace rules, and supports both async-hold
(record-and-forward) and sync-hold (block until UI forwards/drops/edits).
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from typing import Any

from ..storage import Project
from .ca import ensure_ca
from .matchreplace import MRRule, apply_request, apply_response, from_row
from .rules import (
    InterceptConfig, Rule, should_hold_request, should_hold_response,
)

log = logging.getLogger("weblore.proxy")


HOLD_POLL_MS = 100
HOLD_TIMEOUT_S = 600  # 10 min: tunable


def _load_mr(project: Project) -> list[MRRule]:
    return [from_row(r) for r in project.list_mr()]


# Hostnames that always resolve to "this machine". Used together with the
# Weblore UI port to make sure we never accidentally hold a request that
# the operator's browser is making *to* the Weblore web UI itself.
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
    """True if this request is targeting the Weblore UI itself.
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
                 ui_port: int = 0, ui_port_fn: Any = None):
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

    # ----- request hook -----
    async def request(self, flow: Any) -> None:
        try:
            req = flow.request
            host = req.pretty_host or ""

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

            # Never hold a request the browser is making to the Weblore UI
            # itself, otherwise turning intercept ON locks the operator out
            # of the very panel they need to forward/drop intercepts from.
            ui_port = int(self._ui_port_fn() or 0)
            if _is_self_ui_request(req, ui_port):
                return

            if should_hold_request(self.rules, host, req.method,
                                   req.path or ""):
                if self.sync_hold:
                    await self._sync_hold(
                        "request", flow, _serialise_request(req),
                        "rule:request", apply_to_request=True)
                else:
                    self.project.enqueue_intercept(
                        "request", _serialise_request(req), "rule:request",
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
            self.project.add_history(
                host=host, method=method, url=url, status=status,
                duration_ms=duration_ms, engine="proxy",
                raw_req=raw_req, raw_resp=raw_resp,
            )
            # Same self-bypass as the request hook: never hold responses
            # coming from the Weblore UI itself, otherwise the panel's
            # own redirects (e.g. the 302 from /proxy/intercept/toggle)
            # get queued and lock the operator out.
            ui_port = int(self._ui_port_fn() or 0)
            if _is_self_ui_request(req, ui_port):
                return
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
                          *, apply_to_request: bool) -> None:
        """Park the flow until the operator decides forward / drop / edit.
        Critically: ``await asyncio.sleep`` yields control back to
        mitmproxy's event loop so OTHER flows keep being processed (and
        the Weblore UI's own traffic keeps flowing through the self-
        bypass). A blocking ``time.sleep`` here would freeze the whole
        proxy until this single flow is decided — which is exactly the
        "everything is now held" symptom we just fixed.
        """
        flow_id = uuid.uuid4().hex
        iid = self.project.enqueue_intercept_sync(kind, raw, reason, flow_id)
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
        ensure_ca(ca_dir)

    def set_intercept(self, on: bool,
                      config: InterceptConfig | None = None) -> None:
        """Burp-style global intercept: when on, hold requests that match
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
            target=self._run, name="weblore-proxy", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._master is None or self._loop is None:
            return
        self._loop.call_soon_threadsafe(self._master.shutdown)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster
        except Exception:
            log.exception("mitmproxy not installed correctly")
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        opts = Options(
            listen_host=self.host,
            listen_port=self.port,
            confdir=str(self.ca_dir),
            ssl_insecure=True,
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
                          ui_port_fn=lambda: self.ui_port))
        try:
            self._loop.run_until_complete(self._master.run())
        except Exception:
            log.exception("proxy crashed")
        finally:
            try:
                self._loop.close()
            except Exception:
                pass
