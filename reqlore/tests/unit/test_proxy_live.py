"""Proxy held-queue live auto-refresh: /proxy/intercept/count endpoint
and template wiring for the screen-reader-friendly poll widget.

These tests are the Proxy counterpart of ``test_history_live.py`` and
exist because the old polling implementation reloaded the page on every
held-count change with no opt-in, no filter awareness, and no dedup of
the live-region announcement \u2014 hostile to assistive tech under WCAG
2.2 SC 2.2.4 / 3.2.5 / 4.1.3.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "proxy_live.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def project(app):
    return app.extensions["reqlore_project"]


def _hold(project, *, kind="request", method="GET",
          host="target.tld", path="/x", reason="manual") -> int:
    raw = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n\r\n").encode()
    return project.enqueue_intercept(kind, raw, reason)


# ---- /proxy/intercept/count: shape & semantics ----------------------------

def test_intercept_count_empty_db(client):
    r = client.get("/proxy/intercept/count")
    assert r.status_code == 200
    body = r.get_json()
    assert body == {"count": 0, "new": 0, "max_id": 0, "since": 0}


def test_intercept_count_reports_pending_total_and_max_id(client, project):
    a = _hold(project, host="a.test")
    b = _hold(project, host="b.test")
    body = client.get("/proxy/intercept/count").get_json()
    assert body["count"] == 2
    assert body["max_id"] == b
    # No `since` supplied \u2192 everything counts as "new".
    assert body["new"] == 2
    assert body["since"] == 0
    # The lower id is what a freshly-loaded page would treat as the new
    # frontier; double-check the relation.
    assert a < b


def test_intercept_count_since_only_counts_arrivals_after_cursor(client, project):
    a = _hold(project)
    _hold(project)
    c = _hold(project)
    body = client.get(f"/proxy/intercept/count?since={a}").get_json()
    assert body["new"] == 2
    assert body["max_id"] == c
    assert body["since"] == a
    # Caught up: no new arrivals after the highest known id.
    body = client.get(f"/proxy/intercept/count?since={c}").get_json()
    assert body["new"] == 0
    assert body["max_id"] == c


def test_intercept_count_bad_since_treated_as_zero(client, project):
    _hold(project)
    body = client.get("/proxy/intercept/count?since=not-a-number").get_json()
    assert body["since"] == 0 and body["new"] == 1


def test_intercept_count_skips_decided_items(client, project):
    a = _hold(project)
    b = _hold(project)
    # Forward the first one; only the still-pending b should be counted.
    project.decide_intercept(a, "forward", b"")
    body = client.get("/proxy/intercept/count").get_json()
    assert body["count"] == 1
    assert body["max_id"] == b


# ---- /proxy/intercept/count: filter awareness -----------------------------

def test_intercept_count_respects_kind_filter(client, project):
    _hold(project, kind="request")
    rid = _hold(project, kind="response")
    body = client.get("/proxy/intercept/count?kind=response").get_json()
    assert body["count"] == 1
    assert body["max_id"] == rid


def test_intercept_count_respects_method_filter(client, project):
    _hold(project, method="GET")
    pid = _hold(project, method="POST")
    body = client.get("/proxy/intercept/count?method=POST").get_json()
    assert body["count"] == 1
    assert body["max_id"] == pid


def test_intercept_count_respects_host_contains(client, project):
    _hold(project, host="alpha.test")
    _hold(project, host="alpha.test")
    _hold(project, host="beta.test")
    body = client.get("/proxy/intercept/count?host=alpha").get_json()
    # host_mode defaults to "contains".
    assert body["count"] == 2


def test_intercept_count_respects_host_exact(client, project):
    _hold(project, host="alpha.test")
    _hold(project, host="alphabeta.test")
    body = client.get(
        "/proxy/intercept/count?host=alpha.test&host_mode=exact"
    ).get_json()
    assert body["count"] == 1


def test_intercept_count_respects_url_substring(client, project):
    _hold(project, path="/api/users")
    _hold(project, path="/login")
    body = client.get("/proxy/intercept/count?q=api").get_json()
    assert body["count"] == 1


def test_intercept_count_bad_regex_falls_back_gracefully(client, project):
    # Bad regex must not 500; q_re=1 with broken pattern degrades to
    # substring search (mirrors the index view's degradation policy).
    _hold(project, path="/api/x")
    r = client.get("/proxy/intercept/count?q=%28&q_re=1")
    assert r.status_code == 200


# ---- Page template: live-refresh widget wiring ----------------------------

def test_proxy_index_renders_live_refresh_widget(client):
    r = client.get("/proxy/")
    assert r.status_code == 200
    assert b'data-live-refresh' in r.data
    assert b'data-latest-url="/proxy/intercept/count"' in r.data
    # The four ids the shared JS reads via data-*-id attrs.
    assert b'id="proxy-live-cb"' in r.data
    assert b'id="proxy-live-status"' in r.data
    assert b'id="proxy-live-refresh"' in r.data
    # localStorage key is page-scoped so flipping it on doesn't toggle
    # the History page (and vice versa).
    assert b'data-storage-key="reqloreProxyAutoRefresh"' in r.data
    # The role=status live region for SC 4.1.3 announcements.
    assert b'role="status"' in r.data
    # noscript fallback so JS-off users still get a discoverable hint.
    assert b'JavaScript disabled' in r.data


def test_proxy_live_toggle_defaults_off_for_aaa(client):
    """SC 3.2.5 Change on Request (AAA): the page reload must not happen
    until the user explicitly opts in. The checkbox is unchecked on
    every server render; only client-side localStorage may turn it on.
    """
    r = client.get("/proxy/")
    assert b'id="proxy-live-cb" checked' not in r.data
    assert b'<input type="checkbox" id="proxy-live-cb">' in r.data


def test_proxy_index_keeps_filter_querystring_on_latest_url(client):
    """Live-refresh poll URL must carry the same filters the user is
    looking at, otherwise an alert fires for unrelated arrivals.
    """
    r = client.get("/proxy/?kind=response&method=POST")
    assert r.status_code == 200
    assert b'data-latest-url="/proxy/intercept/count?kind=response&amp;method=POST"' in r.data


def test_proxy_index_no_legacy_intercept_watch_attrs(client):
    """Guard against regression to the old auto-reload-on-change poller.
    The legacy attributes triggered a full page reload with no opt-in
    and no live-region announcement, which is hostile to screen readers.
    """
    r = client.get("/proxy/")
    assert b'data-intercept-watch' not in r.data
    assert b'data-intercept-on' not in r.data
    assert b'data-intercept-count' not in r.data
    assert b'http-equiv="refresh"' not in r.data
