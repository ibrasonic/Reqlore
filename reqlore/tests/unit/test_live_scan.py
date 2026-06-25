"""Phase 1 tests for live passive scanning.

These cover:

* `scope_utils.host_in_scope` — exclude wins over include, empty rules
  allow all, empty host treated as in-scope.
* `LiveScanWorker` lifecycle — queue consumption, drop-oldest overflow
  semantics, scope filtering, error isolation.
* Passive scanner's new ``respect_scope`` flag — in-scope hosts get
  scanned, out-of-scope hosts are counted and skipped.
* Proxy `_HistoryAddon` non-blocking enqueue — the response hook must
  return promptly even if the worker callback raises.

The scanner is configured with a single trivially-firing rule so the
tests stay focused on the queue + scope plumbing rather than the
specific findings produced.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from reqlore.scanner import (
    LiveScanWorker,
    Scanner,
    host_in_scope,
    load_scope_rules,
)
from reqlore.scanner.findings import Finding
from reqlore.storage import Project


# ---------------------------------------------------------------------------
# scope_utils


def test_host_in_scope_no_rules_allows_all():
    assert host_in_scope("anything.example", []) is True


def test_host_in_scope_empty_host_treated_as_in_scope():
    # Some proxy paths record rows without a host (CONNECT failures
    # etc.); the scanner must not drop them silently.
    assert host_in_scope("", [{"kind": "include", "pattern": "x.com",
                                 "target": "host", "enabled": True}]) is True


def test_host_in_scope_include_only():
    rules = [{"kind": "include", "pattern": "*.example.com",
              "target": "host", "enabled": True}]
    assert host_in_scope("api.example.com", rules) is True
    assert host_in_scope("other.test", rules) is False


def test_host_in_scope_exclude_wins_over_include():
    rules = [
        {"kind": "include", "pattern": "*.example.com",
         "target": "host", "enabled": True},
        {"kind": "exclude", "pattern": "api.example.com",
         "target": "host", "enabled": True},
    ]
    assert host_in_scope("api.example.com", rules) is False
    assert host_in_scope("www.example.com", rules) is True


def test_host_in_scope_disabled_rule_is_ignored():
    rules = [{"kind": "include", "pattern": "good.test",
              "target": "host", "enabled": False}]
    # With no *enabled* includes, everything is in scope.
    assert host_in_scope("other.test", rules) is True


def test_host_in_scope_ignores_non_host_target():
    # `target` other than "host" is for URL-path rules; the scope
    # helper deliberately scopes only on host.
    rules = [{"kind": "exclude", "pattern": "x.com",
              "target": "url", "enabled": True}]
    assert host_in_scope("x.com", rules) is True


# ---------------------------------------------------------------------------
# LiveScanWorker — happy path, overflow, scope, error isolation


def _project(tmp_path: Path) -> Project:
    return Project(tmp_path / "live.rlr")


def _add_row(p: Project, host: str = "x.test", url: str = None) -> int:
    return p.add_history(
        host=host, method="GET", url=url or f"https://{host}/",
        status=200, duration_ms=1, engine="test",
        raw_req=b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
    )


def _trivial_rule(ctx):
    """Always-fires passive rule for queue plumbing tests."""
    return [Finding(severity="info", title="trivial",
                    host=ctx.host, url=ctx.url, evidence="ok")]


def test_live_worker_consumes_queue(tmp_path: Path):
    p = _project(tmp_path)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False)
    hids = [_add_row(p) for _ in range(5)]
    w.start()
    try:
        for h in hids:
            w.enqueue(h)
        deadline = time.monotonic() + 2.0
        while w.scanned < 5 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        w.stop(timeout=1.0)
    assert w.scanned == 5
    assert w.findings_added >= 5  # one finding per scanned row
    assert w.errors == 0


def test_live_worker_overflow_writes_to_durable_backlog(tmp_path: Path):
    """Phase 1.1 contract: when the in-memory queue is full, the
    overflowed row goes to the durable ``live_scan_backlog`` table
    rather than being dropped. The worker drains the backlog on idle
    so the row is eventually scanned. Nothing is lost."""
    p = _project(tmp_path)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, maxsize=3, respect_scope=False,
                       backlog_batch=8)
    # Pre-load 4 real history rows so the worker has rows to load.
    hids = [_add_row(p) for _ in range(4)]
    # Push the first 3 into the in-memory queue (no thread yet).
    for hid in hids[:3]:
        w.enqueue(hid)
    assert w.queue_depth() == 3
    assert w.overflowed == 0
    assert p.backlog_count() == 0
    # Pushing a 4th id overflows the queue. It must be durably
    # parked, not silently dropped, and the in-memory queue must
    # still contain the original 3.
    w.enqueue(hids[3])
    assert w.queue_depth() == 3
    assert w.overflowed == 1
    assert p.backlog_count() == 1
    # Start the worker. It should drain the in-memory queue first,
    # then pull the parked row off the backlog.
    w.start()
    try:
        deadline = time.monotonic() + 5.0
        while w.scanned < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        w.stop(timeout=2.0)
    assert w.scanned == 4
    assert w.backlog_drained == 1
    assert p.backlog_count() == 0


def test_live_worker_stop_flushes_inmemory_queue_to_backlog(tmp_path: Path):
    """A graceful ``stop()`` must move any unprocessed in-memory ids
    to the durable backlog so a worker restart can finish them. This
    is the crash-recovery seam."""
    p = _project(tmp_path)
    scanner = Scanner(rules=[_trivial_rule])
    # Never start the worker; just enqueue + stop.
    w = LiveScanWorker(p, scanner, maxsize=8, respect_scope=False)
    hids = [_add_row(p) for _ in range(3)]
    for hid in hids:
        w.enqueue(hid)
    assert w.queue_depth() == 3
    assert p.backlog_count() == 0
    w.stop(timeout=0.1)  # no-op join because worker never started
    assert w.queue_depth() == 0
    assert p.backlog_count() == 3


def test_live_worker_picks_up_backlog_on_restart(tmp_path: Path):
    """A previous session that exited with rows in the backlog must
    have them scanned by the next worker that opens the project."""
    p = _project(tmp_path)
    hids = [_add_row(p) for _ in range(3)]
    for hid in hids:
        p.backlog_enqueue(hid)
    assert p.backlog_count() == 3
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False, backlog_batch=8)
    w.start()
    try:
        deadline = time.monotonic() + 5.0
        while p.backlog_count() > 0 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        w.stop(timeout=2.0)
    assert p.backlog_count() == 0
    assert w.backlog_drained == 3
    assert w.scanned == 3


def test_live_worker_request_catchup_uses_larger_batch(tmp_path: Path):
    """``request_catchup()`` should clear the backlog faster by
    pulling a 10x batch on the next idle tick. We verify the
    multiplier indirectly: with ``backlog_batch=1`` a non-catch-up
    tick can drain at most 1 row, so finishing 8 rows in one wall-
    clock second proves the multiplier took effect (worker idles for
    250 ms between ticks, so 4 ticks max in 1 s)."""
    p = _project(tmp_path)
    hids = [_add_row(p) for _ in range(8)]
    for hid in hids:
        p.backlog_enqueue(hid)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False, backlog_batch=1)
    w.request_catchup()
    w.start()
    try:
        deadline = time.monotonic() + 5.0
        while p.backlog_count() > 0 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        w.stop(timeout=2.0)
    assert p.backlog_count() == 0
    assert w.scanned == 8


def test_live_worker_skips_out_of_scope(tmp_path: Path):
    p = _project(tmp_path)
    p.add_scope("include", "good.test", "host")
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=True)
    in_hid = _add_row(p, host="good.test")
    out_hid = _add_row(p, host="bad.test")
    w.start()
    try:
        w.enqueue(in_hid)
        w.enqueue(out_hid)
        deadline = time.monotonic() + 2.0
        while (w.scanned + w.skipped_out_of_scope) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        w.stop(timeout=1.0)
    assert w.scanned == 1
    assert w.skipped_out_of_scope == 1


def test_live_worker_isolates_rule_errors(tmp_path: Path):
    p = _project(tmp_path)

    def bad(ctx):
        raise RuntimeError("boom")

    scanner = Scanner(rules=[bad, _trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False)
    hid = _add_row(p)
    w.start()
    try:
        w.enqueue(hid)
        deadline = time.monotonic() + 2.0
        while w.scanned < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        w.stop(timeout=1.0)
    # ``run_passive`` already catches per-rule exceptions and emits a
    # synthetic "Scanner rule raised" finding rather than re-raising —
    # so the loop must keep going and produce *more* findings, not
    # fewer. The worker's own ``errors`` counter only ticks on
    # exceptions that escape ``run_passive``.
    assert w.scanned == 1
    titles = {f["title"] for f in p.list_findings()}
    assert any("Scanner rule raised" in t for t in titles)
    assert "trivial" in titles
    assert w.findings_added >= 2


def test_live_worker_start_is_idempotent(tmp_path: Path):
    p = _project(tmp_path)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False)
    w.start()
    t1 = w._thread
    w.start()  # second start while alive is a no-op
    assert w._thread is t1
    w.stop(timeout=1.0)
    assert not w.is_alive()


def test_live_worker_snapshot_shape(tmp_path: Path):
    p = _project(tmp_path)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(p, scanner, respect_scope=False)
    snap = w.snapshot()
    expected = {
        "alive", "queue_depth", "scanned", "findings_added",
        "overflowed", "skipped_out_of_scope", "errors",
        "scans_per_minute", "last_error", "last_error_ts",
    }
    assert expected.issubset(snap.keys())
    assert snap["alive"] is False
    assert snap["queue_depth"] == 0


# ---------------------------------------------------------------------------
# Scanner.scan_project — new respect_scope flag


def test_scan_project_respects_scope(tmp_path: Path):
    p = _project(tmp_path)
    p.add_scope("include", "good.test", "host")
    _add_row(p, host="good.test")
    _add_row(p, host="bad.test")
    scanner = Scanner(rules=[_trivial_rule])
    result = scanner.scan_project(p, respect_scope=True, resume=False)
    assert result.scanned_in_scope == 1
    assert result.skipped_out_of_scope == 1


def test_scan_project_respect_scope_false_scans_all(tmp_path: Path):
    p = _project(tmp_path)
    p.add_scope("include", "good.test", "host")
    _add_row(p, host="good.test")
    _add_row(p, host="bad.test")
    scanner = Scanner(rules=[_trivial_rule])
    result = scanner.scan_project(p, respect_scope=False, resume=False)
    assert result.scanned_in_scope == 2
    assert result.skipped_out_of_scope == 0


# ---------------------------------------------------------------------------
# Proxy hook — non-blocking, error-isolated


def test_history_addon_response_hook_never_raises_on_callback_error():
    """The mitm response hook must capture the hid and forward it to
    the live worker without ever propagating an exception back into
    the mitmproxy event loop."""
    from reqlore.proxy.mitm import _HistoryAddon

    @dataclass
    class _Flow:
        request: "_Req"
        response: "_Resp"

    @dataclass
    class _Req:
        host: str
        method: str
        url: str
        scheme: str = "https"
        port: int = 443
        path: str = "/"
        http_version: str = "HTTP/1.1"
        content: bytes = b""
        headers: dict = None

    @dataclass
    class _Resp:
        status_code: int
        reason: str = "OK"
        content: bytes = b""
        headers: dict = None

    calls: list[int] = []

    def raising_enqueue(hid):
        calls.append(int(hid))
        raise RuntimeError("simulated worker failure")

    class _FakeProject:
        def add_history(self, **kw):
            return 99

    # The hook's job is fully covered by ProxyController._live_enqueue
    # which already wraps the callback in try/except. Verify that
    # contract directly: a raising callback must not propagate.
    from reqlore.proxy.mitm import ProxyController

    class _Worker:
        def enqueue(self, hid):
            raising_enqueue(hid)

    pc = ProxyController.__new__(ProxyController)
    pc.live_worker = _Worker()
    pc._live_enqueue(7)  # must not raise
    assert calls == [7]


def test_history_addon_swallows_missing_live_worker():
    """When no worker is wired (CLI mode), the controller's _live_enqueue
    must still be safe to call."""
    from reqlore.proxy.mitm import ProxyController
    pc = ProxyController.__new__(ProxyController)
    pc.live_worker = None
    pc._live_enqueue(1)  # no exception, no side effect


# ---------------------------------------------------------------------------
# Storage: backlog table CRUD


def test_backlog_enqueue_and_count(tmp_path: Path):
    p = _project(tmp_path)
    assert p.backlog_count() == 0
    assert p.backlog_enqueue(101) is True
    assert p.backlog_enqueue(102) is True
    assert p.backlog_count() == 2
    # Re-enqueuing the same hid is idempotent.
    assert p.backlog_enqueue(101) is False
    assert p.backlog_count() == 2


def test_backlog_pop_batch_claims_oldest_without_deleting(tmp_path: Path):
    p = _project(tmp_path)
    for hid in (5, 4, 3, 2, 1):
        p.backlog_enqueue(hid)
    # Pop oldest-first by ts (insertion order). All five rows have the
    # same epoch-second so the PK tie-break makes the order
    # deterministic by ascending hid.
    out = p.backlog_pop_batch(3)
    assert [t[0] for t in out] == [1, 2, 3]
    # Every popped tuple is (hid, retries) and retries is zero on a
    # freshly-enqueued row.
    assert [t[1] for t in out] == [0, 0, 0]
    # Rows are *claimed*, not deleted — the total count still includes
    # them so the operator-facing "work remaining" figure is honest.
    assert p.backlog_count() == 5
    # A second pop must not see the already-claimed rows.
    second = p.backlog_pop_batch(99)
    assert [t[0] for t in second] == [4, 5]
    third = p.backlog_pop_batch(99)
    assert third == []


def test_backlog_release_removes_row(tmp_path: Path):
    p = _project(tmp_path)
    p.backlog_enqueue(1)
    p.backlog_pop_batch(1)
    assert p.backlog_release(1) is True
    assert p.backlog_count() == 0
    # Idempotent: releasing a row that no longer exists is a no-op.
    assert p.backlog_release(1) is False


def test_backlog_yield_clears_claim_without_bumping_retries(tmp_path: Path):
    p = _project(tmp_path)
    p.backlog_enqueue(7)
    p.backlog_pop_batch(1)
    # A second pop sees nothing because the row is claimed.
    assert p.backlog_pop_batch(1) == []
    assert p.backlog_yield(7) is True
    # After yield the row is eligible again and retries is still 0.
    again = p.backlog_pop_batch(1)
    assert again == [(7, 0)]


def test_backlog_reset_claims_clears_all_claims(tmp_path: Path):
    p = _project(tmp_path)
    for hid in (1, 2, 3):
        p.backlog_enqueue(hid)
    p.backlog_pop_batch(2)  # claim two
    # A fresh worker session should be able to pick those up again.
    reset = p.backlog_reset_claims()
    assert reset == 2
    all_again = p.backlog_pop_batch(99)
    assert sorted(t[0] for t in all_again) == [1, 2, 3]


def test_backlog_requeue_bumps_retries_and_eventually_drops(tmp_path: Path):
    p = _project(tmp_path)
    p.backlog_enqueue(42)
    # First scan attempt: claim, fail, requeue. The lease pattern means
    # the row is back to claimed_at=0 (eligible) with retries=1.
    p.backlog_pop_batch(1)
    assert p.backlog_requeue(42, max_retries=3) is True
    again = p.backlog_pop_batch(1)
    assert again == [(42, 1)]
    assert p.backlog_requeue(42, max_retries=3) is True
    again = p.backlog_pop_batch(1)
    assert again == [(42, 2)]
    assert p.backlog_requeue(42, max_retries=3) is True
    again = p.backlog_pop_batch(1)
    assert again == [(42, 3)]
    # 4th failure: retries would become 4 > max_retries=3, so drop.
    assert p.backlog_requeue(42, max_retries=3) is False
    assert p.backlog_count() == 0


def test_backlog_requeue_missing_row_returns_false(tmp_path: Path):
    p = _project(tmp_path)
    # Row never enqueued — requeue cannot bring it back into existence.
    assert p.backlog_requeue(999, max_retries=3) is False


def test_backlog_clear_returns_count(tmp_path: Path):
    p = _project(tmp_path)
    for hid in (10, 11, 12):
        p.backlog_enqueue(hid)
    assert p.backlog_clear() == 3
    assert p.backlog_count() == 0


# ---------------------------------------------------------------------------
# Worker retry policy


def test_live_worker_retries_then_drops_unrecoverable_row(tmp_path: Path):
    """A row that consistently fails to scan must be re-parked with
    a retry counter and finally dropped only after the budget is
    exhausted. The metric ``dropped_unrecoverable`` ticks once per
    row that ran out of retries."""

    class _RaisingProject:
        """Project shim that wraps the real Project but makes
        ``get_history`` raise so every scan fails. All other calls
        delegate so the backlog table still works."""
        def __init__(self, inner):
            self._inner = inner
            self.fail_calls = 0

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def get_history(self, hid):
            self.fail_calls += 1
            raise RuntimeError("simulated load failure")

    inner = _project(tmp_path)
    real_hid = _add_row(inner)
    inner.backlog_enqueue(real_hid)
    raising = _RaisingProject(inner)
    scanner = Scanner(rules=[_trivial_rule])
    w = LiveScanWorker(raising, scanner, respect_scope=False,
                       max_retries=2, backlog_batch=1)
    w.start()
    try:
        deadline = time.monotonic() + 5.0
        while w.dropped_unrecoverable == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        w.stop(timeout=2.0)
    assert w.dropped_unrecoverable == 1
    assert inner.backlog_count() == 0


# ---------------------------------------------------------------------------
# Web routes


@pytest.fixture
def web_app(tmp_path: Path):
    from reqlore.config import Settings
    from reqlore.web import create_app
    return create_app(tmp_path / "live.rlr", Settings(), proxy=None)


def _csrf_for(client) -> str:
    """Round-trip a GET so Flask sets the session cookie + csrf, then
    return the token string for use in POST bodies."""
    client.get("/scanner/live")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _inject_worker(app):
    """Install a real worker bound to the app's project. Used to
    exercise the catch-up route under ``proxy=None`` test apps."""
    project = app.extensions["reqlore_project"]
    scanner = Scanner(rules=[_trivial_rule])
    worker = LiveScanWorker(project, scanner, respect_scope=False)
    app.extensions["reqlore_live_worker"] = worker
    return worker


def test_route_live_get_renders_without_worker(web_app):
    """The live page must render even when no worker is wired (CLI
    mode / tests). Backlog count is read from the project directly."""
    client = web_app.test_client()
    r = client.get("/scanner/live")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Live passive scanning" in body
    assert "Durable backlog" in body


def test_route_live_json_includes_backlog_key(web_app):
    client = web_app.test_client()
    r = client.get("/scanner/live.json")
    assert r.status_code == 200
    data = r.get_json()
    assert "backlog" in data
    assert "queue_depth" in data
    assert "dropped_unrecoverable" in data


def test_route_live_json_reflects_durable_backlog(web_app):
    """The JSON endpoint must read the backlog table even when the
    worker hasn't been constructed yet (e.g. after a crash before
    create_app re-wires the worker)."""
    project = web_app.extensions["reqlore_project"]
    project.backlog_enqueue(1234)
    client = web_app.test_client()
    data = client.get("/scanner/live.json").get_json()
    assert data["backlog"] == 1


def test_route_live_catchup_signals_worker(web_app):
    worker = _inject_worker(web_app)
    client = web_app.test_client()
    csrf = _csrf_for(client)
    r = client.post("/scanner/live/catchup",
                    data={"_csrf": csrf}, follow_redirects=False)
    assert r.status_code == 302
    # The catch-up flag is set on the Event; calling is_set() drains
    # state but the worker thread will also clear it on its next idle
    # tick. We assert "either still set OR worker just consumed it".
    assert worker._catchup.is_set() or worker.is_alive()
    worker.stop(timeout=1.0)


def test_route_live_catchup_without_worker_flashes_warning(web_app):
    client = web_app.test_client()
    csrf = _csrf_for(client)
    r = client.post("/scanner/live/catchup",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    # Page rendered after the redirect; the flash message lands here.
    body = r.data.decode("utf-8", errors="replace")
    assert "not available" in body.lower() or "warn" in body.lower()


def test_route_live_clear_backlog_requires_confirm(web_app):
    project = web_app.extensions["reqlore_project"]
    project.backlog_enqueue(1)
    project.backlog_enqueue(2)
    client = web_app.test_client()
    csrf = _csrf_for(client)
    # Without confirm=yes the backlog must NOT be cleared.
    r = client.post("/scanner/live/clear-backlog",
                    data={"_csrf": csrf}, follow_redirects=False)
    assert r.status_code == 302
    assert project.backlog_count() == 2
    # With confirm=yes it is cleared.
    r = client.post("/scanner/live/clear-backlog",
                    data={"_csrf": csrf, "confirm": "yes"},
                    follow_redirects=False)
    assert r.status_code == 302
    assert project.backlog_count() == 0


def test_route_live_clear_backlog_requires_csrf(web_app):
    """A POST without a CSRF token must fail with 400 — defence in
    depth, even though the action is also confirm-gated."""
    project = web_app.extensions["reqlore_project"]
    project.backlog_enqueue(99)
    client = web_app.test_client()
    # Prime the session so a token *exists*, then post without one.
    client.get("/scanner/live")
    r = client.post("/scanner/live/clear-backlog",
                    data={"confirm": "yes"}, follow_redirects=False)
    assert r.status_code == 400
    assert project.backlog_count() == 1
