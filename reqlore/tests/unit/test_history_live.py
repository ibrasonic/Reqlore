"""History page live auto-refresh: storage helper + /history/latest.json."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "live.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def project(app):
    return app.extensions["reqlore_project"]


def _add(project, host="h.test", method="GET", url="http://h.test/x") -> int:
    return project.add_history(
        host=host, method=method, url=url, status=200,
        duration_ms=1, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
    )


# ---- storage helper -------------------------------------------------------

def test_count_history_after_empty(project):
    new, mx = project.count_history_after(0)
    assert (new, mx) == (0, 0)


def test_count_history_after_counts_newer(project):
    a = _add(project)
    b = _add(project)
    c = _add(project)
    new, mx = project.count_history_after(a)
    assert new == 2 and mx == c
    new, mx = project.count_history_after(c)
    assert new == 0 and mx == c
    new, mx = project.count_history_after(0)
    assert new == 3 and mx == c


def test_count_history_after_respects_filters(project):
    _add(project, host="alpha.test")
    _add(project, host="alpha.test")
    c = _add(project, host="beta.test")
    new_alpha, mx_alpha = project.count_history_after(0, host="alpha.test")
    new_beta, mx_beta = project.count_history_after(0, host="beta.test")
    assert new_alpha == 2 and mx_alpha < c
    assert new_beta == 1 and mx_beta == c


# ---- JSON endpoint --------------------------------------------------------

def test_latest_json_empty_db(client):
    r = client.get("/history/latest.json")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    body = r.get_json()
    assert body == {"new": 0, "max_id": 0, "since": 0}


def test_latest_json_reports_new_after_since(client, project):
    a = _add(project)
    _add(project)
    c = _add(project)
    r = client.get(f"/history/latest.json?since={a}")
    body = r.get_json()
    assert body["new"] == 2
    assert body["max_id"] == c
    assert body["since"] == a


def test_latest_json_filters_match_index(client, project):
    _add(project, host="alpha.test", url="http://alpha.test/")
    _add(project, host="beta.test", url="http://beta.test/")
    r = client.get("/history/latest.json?host=alpha.test")
    body = r.get_json()
    assert body["new"] == 1


def test_latest_json_bad_since_treated_as_zero(client, project):
    _add(project)
    r = client.get("/history/latest.json?since=not-a-number")
    body = r.get_json()
    assert body["since"] == 0 and body["new"] == 1


# ---- template wiring ------------------------------------------------------

def test_history_index_renders_live_root(client, project):
    _add(project)
    r = client.get("/history/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "data-history-live" in body
    assert "data-latest-url=" in body
    assert "/history/latest.json" in body
    assert 'id="hist-live-cb"' in body
    assert 'id="hist-live-status"' in body


def test_history_live_toggle_defaults_off_for_aaa(client, project):
    """WCAG 2.2 SC 3.2.5 (AAA) Change on Request.

    The auto-reload toggle must default to OFF so the first navigation
    away from the current view is user-initiated. Users who flip it on
    have their preference remembered client-side.
    """
    _add(project)
    r = client.get("/history/")
    body = r.data.decode("utf-8", "replace")
    # The checkbox must be present and NOT pre-checked.
    assert 'id="hist-live-cb"' in body
    assert 'id="hist-live-cb" checked' not in body
    assert 'id="hist-live-cb"checked' not in body


def test_history_index_live_root_carries_current_max_id(client, project):
    _add(project)
    mx = _add(project)
    r = client.get("/history/")
    body = r.data.decode("utf-8", "replace")
    assert f'data-since="{mx}"' in body


def test_history_index_live_root_passes_filters_into_url(client, project):
    _add(project, host="alpha.test")
    r = client.get("/history/?host=alpha.test")
    body = r.data.decode("utf-8", "replace")
    # url_for builds the query string into data-latest-url; the host
    # filter must round-trip so the poll matches the page view.
    assert "host=alpha.test" in body
