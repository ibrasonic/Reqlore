"""Phase 15 — redirect-aware intercept queue.

Covers:

* ``intercept_q.parent_intercept_id`` migration is idempotent.
* ``InterceptRow.parent_intercept_id`` round-trips through
  ``enqueue_intercept`` and ``enqueue_intercept_sync``.
* ``_HistoryAddon`` end-to-end:
    - ``_sync_hold`` tags the flow with ``flow._reqlore_iid``.
    - The response hook stashes the redirect target in the cache.
    - The next request to that target picks the parent off the cache
      and propagates ``parent_intercept_id`` to the enqueue.
* TTL eviction: stale entries never taint unrelated requests.
* Cache-miss path: the historical behaviour (no parent) is unchanged.
* Queue + detail templates render the badge / parent link.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.proxy.mitm import _REDIRECT_TTL_S, _HistoryAddon
from reqlore.proxy.rules import Rule
from reqlore.storage import InterceptRow, Project
from reqlore.web import create_app

# ---------------------------------------------------------------------------
# storage / migration
# ---------------------------------------------------------------------------


def test_intercept_row_has_parent_field_default_none(tmp_path: Path) -> None:
    p = Project(tmp_path / "p15_row.rlr")
    try:
        iid = p.enqueue_intercept("request", b"GET / HTTP/1.1\r\n\r\n", "test")
        row = p.get_intercept(iid)
        assert row is not None
        assert row.parent_intercept_id is None
    finally:
        p.close()


def test_enqueue_intercept_persists_parent_id(tmp_path: Path) -> None:
    p = Project(tmp_path / "p15_enq.rlr")
    try:
        parent = p.enqueue_intercept("request", b"GET /a HTTP/1.1\r\n\r\n", "first")
        child = p.enqueue_intercept(
            "request", b"GET /b HTTP/1.1\r\n\r\n", "redirect",
            parent_intercept_id=parent,
        )
        rows = {r.id: r for r in p.list_intercept()}
        assert rows[parent].parent_intercept_id is None
        assert rows[child].parent_intercept_id == parent

        single = p.get_intercept(child)
        assert single is not None
        assert single.parent_intercept_id == parent
    finally:
        p.close()


def test_enqueue_intercept_sync_persists_parent_id(tmp_path: Path) -> None:
    p = Project(tmp_path / "p15_sync.rlr")
    try:
        parent = p.enqueue_intercept_sync(
            "request", b"GET /a HTTP/1.1\r\n\r\n", "first", "flow-a",
        )
        p.enqueue_intercept_sync(
            "request", b"GET /b HTTP/1.1\r\n\r\n", "redirect", "flow-b",
            parent_intercept_id=parent,
        )
        # get_intercept_by_flow must surface the new field too.
        row = p.get_intercept_by_flow("flow-b")
        assert isinstance(row, InterceptRow)
        assert row.parent_intercept_id == parent
    finally:
        p.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "p15_mig.rlr"
    p = Project(db)
    try:
        p.enqueue_intercept("request", b"x", "y")
    finally:
        p.close()
    # Re-opening must not error and must keep the data.
    p2 = Project(db)
    try:
        rows = p2.list_intercept()
        assert len(rows) == 1
        assert rows[0].parent_intercept_id is None
    finally:
        p2.close()


# ---------------------------------------------------------------------------
# _HistoryAddon — redirect cache helpers
# ---------------------------------------------------------------------------


def _make_addon(tmp_path: Path) -> tuple[_HistoryAddon, Project]:
    p = Project(tmp_path / "addon.rlr")
    addon = _HistoryAddon(p, rules=[], sync_hold=False, ui_port=8787)
    return addon, p


def test_stash_and_consume_redirect_parent(tmp_path: Path) -> None:
    addon, p = _make_addon(tmp_path)
    try:
        addon._stash_redirect_parent("https://target.example/landing", 42)
        assert addon._consume_redirect_parent("https://target.example/landing") == 42
        # One-shot semantics — the second consume returns None.
        assert addon._consume_redirect_parent("https://target.example/landing") is None
    finally:
        p.close()


def test_stash_ignores_empty_inputs(tmp_path: Path) -> None:
    addon, p = _make_addon(tmp_path)
    try:
        addon._stash_redirect_parent("", 5)
        addon._stash_redirect_parent("https://x", 0)
        assert addon._redirect_cache == {}
    finally:
        p.close()


def test_consume_returns_none_after_ttl(tmp_path: Path, monkeypatch) -> None:
    addon, p = _make_addon(tmp_path)
    try:
        addon._stash_redirect_parent("https://t.example/", 7)
        # Force the cache entry to look ancient.
        with addon._redirect_lock:
            url, (parent, _) = next(iter(addon._redirect_cache.items()))
            addon._redirect_cache[url] = (parent, time.monotonic() - (_REDIRECT_TTL_S + 5))
        assert addon._consume_redirect_parent("https://t.example/") is None
    finally:
        p.close()


# ---------------------------------------------------------------------------
# end-to-end through the addon hooks
# ---------------------------------------------------------------------------


class _Hdrs:
    def __init__(self, d=None):
        self._d = {k.lower(): v for k, v in (d or {}).items()}
    def get(self, k, default=""):
        return self._d.get(k.lower(), default)
    def items(self):
        return list(self._d.items())
    def clear(self):
        self._d.clear()
    def __setitem__(self, k, v):
        self._d[k.lower()] = v


class _Req:
    def __init__(self, url="https://target.example/a", method="GET",
                 host="target.example", port=443):
        self.method = method
        self.path = "/a"
        self.http_version = "HTTP/1.1"
        self.pretty_host = host
        self.pretty_url = url
        self.port = port
        self.headers = _Hdrs({"Host": host})
        self.raw_content = b""
    def set_content(self, b):
        self.raw_content = b


class _Resp:
    def __init__(self, status=302, location="https://target.example/landing"):
        self.status_code = status
        self.reason = "Found"
        self.headers = _Hdrs({"Location": location} if location else {})
        self.raw_content = b""
    def set_content(self, b):
        self.raw_content = b


class _Flow:
    def __init__(self, req=None, resp=None):
        self.request = req or _Req()
        self.response = resp
        self.duration = 0.01
    def kill(self):
        pass


def test_redirect_chain_links_child_to_parent(tmp_path: Path) -> None:
    """End-to-end: held request → 3xx response stashes Location →
    follow-up request consumes the cache → child row links back."""
    p = Project(tmp_path / "e2e.rlr")
    try:
        # Hold every request so should_hold_request fires.
        rules = [Rule(enabled=True, host_regex=".*")]
        addon = _HistoryAddon(p, rules=rules, sync_hold=True,
                               ui_port_fn=lambda: 8787)

        # First flow: held request → response 302 → Location stashed.
        flow1 = _Flow(req=_Req(url="https://target.example/a"))

        # Replace the sync hold so the test doesn't actually park —
        # but keep the real flow tagging the test wants to verify.
        async def _fake_hold(kind, flow, raw, reason, *, apply_to_request,
                              parent_intercept_id=None):
            iid = p.enqueue_intercept_sync(
                kind, raw, reason, "flow-1",
                parent_intercept_id=parent_intercept_id,
            )
            flow._reqlore_iid = iid
        addon._sync_hold = _fake_hold  # type: ignore[method-assign]  # test monkey-patch to swap the addon's async intercept-hold path

        asyncio.run(addon.request(flow1))
        parent_iid = getattr(flow1, "_reqlore_iid", None)
        assert parent_iid, "parent request should have been held"

        # Now feed the 3xx response back.
        flow1.response = _Resp(status=302,
                                location="https://target.example/landing")
        asyncio.run(addon.response(flow1))

        # The cache should now hold the Location target.
        assert "https://target.example/landing" in addon._redirect_cache

        # Second flow: the browser's follow-up to the Location.
        flow2 = _Flow(req=_Req(url="https://target.example/landing",
                                 host="target.example"))
        # Make the second hold record an unambiguous flow id so we can
        # read it back.
        async def _fake_hold2(kind, flow, raw, reason, *, apply_to_request,
                                parent_intercept_id=None):
            iid = p.enqueue_intercept_sync(
                kind, raw, reason, "flow-2",
                parent_intercept_id=parent_intercept_id,
            )
            flow._reqlore_iid = iid
        addon._sync_hold = _fake_hold2  # type: ignore[method-assign]  # test monkey-patch to redirect the addon's async intercept-hold path to the second fake

        asyncio.run(addon.request(flow2))

        child = p.get_intercept_by_flow("flow-2")
        assert child is not None
        assert child.parent_intercept_id == parent_iid
    finally:
        p.close()


def test_redirect_chain_skipped_when_not_3xx(tmp_path: Path) -> None:
    p = Project(tmp_path / "no3xx.rlr")
    try:
        addon = _HistoryAddon(p, rules=[Rule(enabled=True, host_regex=".*")],
                               sync_hold=True, ui_port_fn=lambda: 8787)

        flow = _Flow(req=_Req(url="https://x.example/a"))

        async def _fake_hold(kind, flow, raw, reason, *, apply_to_request,
                              parent_intercept_id=None):
            iid = p.enqueue_intercept_sync(
                kind, raw, reason, "f", parent_intercept_id=parent_intercept_id,
            )
            flow._reqlore_iid = iid
        addon._sync_hold = _fake_hold  # type: ignore[method-assign]  # test monkey-patch to swap the addon's async intercept-hold path

        asyncio.run(addon.request(flow))
        flow.response = _Resp(status=200, location="")
        asyncio.run(addon.response(flow))
        assert addon._redirect_cache == {}
    finally:
        p.close()


def test_unrelated_request_gets_no_parent(tmp_path: Path) -> None:
    """A request whose URL is not in the cache must still enqueue,
    just without a parent link (cache-miss path = historical behaviour)."""
    p = Project(tmp_path / "miss.rlr")
    try:
        addon = _HistoryAddon(p, rules=[Rule(enabled=True, host_regex=".*")],
                               sync_hold=True, ui_port_fn=lambda: 8787)

        recorded: list[int | None] = []
        async def _fake_hold(kind, flow, raw, reason, *, apply_to_request,
                              parent_intercept_id=None):
            recorded.append(parent_intercept_id)
            iid = p.enqueue_intercept_sync(
                kind, raw, reason, "fm",
                parent_intercept_id=parent_intercept_id,
            )
            flow._reqlore_iid = iid
        addon._sync_hold = _fake_hold  # type: ignore[method-assign]  # test monkey-patch to swap the addon's async intercept-hold path

        asyncio.run(addon.request(_Flow(req=_Req(url="https://other.example/x"))))
        assert recorded == [None]

        row = p.get_intercept_by_flow("fm")
        assert row is not None
        assert row.parent_intercept_id is None
    finally:
        p.close()


def test_async_hold_path_also_propagates_parent(tmp_path: Path) -> None:
    """Sync-hold off (record + forward) must still attach the parent
    link when the cache has an entry."""
    p = Project(tmp_path / "async.rlr")
    try:
        addon = _HistoryAddon(p, rules=[Rule(enabled=True, host_regex=".*")],
                               sync_hold=False, ui_port_fn=lambda: 8787)
        # Pre-seed the cache as if a parent had completed.
        parent_iid = p.enqueue_intercept("request",
                                           b"GET /a HTTP/1.1\r\n\r\n",
                                           "first")
        addon._stash_redirect_parent("https://t.example/child", parent_iid)

        asyncio.run(addon.request(_Flow(req=_Req(url="https://t.example/child",
                                                    host="t.example"))))
        # The latest entry should be the child with parent set.
        rows = p.list_intercept()
        assert len(rows) == 2
        child = rows[-1]
        assert child.parent_intercept_id == parent_iid
    finally:
        p.close()


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------


@pytest.fixture
def app_and_client(tmp_path: Path):
    app = create_app(tmp_path / "p15_web.rlr", Settings(), proxy=None)
    app.testing = True
    return app, app.test_client()


def test_queue_template_renders_parent_badge(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    parent = proj.enqueue_intercept("request", b"GET /a HTTP/1.1\r\n\r\n", "x")
    proj.enqueue_intercept(
        "request", b"GET /b HTTP/1.1\r\n\r\n", "redirect",
        parent_intercept_id=parent,
    )
    r = c.get("/proxy/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert f"from #{parent}" in body
    assert "redirect-parent-link" in body


def test_detail_template_renders_parent_link(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    parent = proj.enqueue_intercept("request", b"GET /a HTTP/1.1\r\n\r\n", "x")
    child = proj.enqueue_intercept(
        "request", b"GET /b HTTP/1.1\r\n\r\n", "redirect",
        parent_intercept_id=parent,
    )
    r = c.get(f"/proxy/intercept/{child}")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Redirect of" in body
    assert f"Intercept #{parent}" in body
