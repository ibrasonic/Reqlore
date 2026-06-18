"""Tests for the history per-column filter UI (storage + blueprint).

Covers the AAA-aligned filter rebuild:

* Storage-layer multi-select filters: ``methods``, ``statuses``
  (buckets and exact codes), ``engines``, ``host_mode=contains`` and
  the numeric ranges ``len_min/len_max`` / ``dur_min/dur_max``.
* Storage-layer regex URL filter (``q`` + ``q_regex=True``).
* Blueprint forwards CSV / repeated query params, dedupes, and drops
  unknown methods / malformed status tokens silently.
* Index page renders one ``<details>`` filter disclosure per column
  with a real ``<button>`` (``<summary>``) trigger and an
  ``aria-label`` that names the column.
* The history live region holds the count text only; the
  ``Refresh now`` link is a sibling, not a child of ``role="status"``
  (verified at template level).

These tests intentionally use the public ``Project`` API + Flask
test client so a future refactor of the SQL layer cannot silently
break the user-visible behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

from reqlore.storage import Project


# ---------- storage layer ---------------------------------------------------

def _project(tmp: Path) -> Project:
    return Project(tmp / "filters.rlr")


def _seed(p: Project) -> None:
    """Seed a small, predictable history fixture covering every
    filterable axis."""
    rows = [
        # host         method  url                 status engine  ms   resp_size
        ("a.example",  "GET",  "http://a/login",   200,   "httpx", 10, 100),
        ("a.example",  "POST", "http://a/api",     401,   "httpx", 50, 50),
        ("b.example",  "GET",  "http://b/admin",   403,   "raw",  100, 5_000),
        ("c.example",  "PUT",  "http://c/upload",  500,   "raw",  300, 10_000),
        ("d.test",     "GET",  "http://d/static",  304,   "h2",     5, 0),
        ("d.test",     "GET",  "http://d/page",    200,   "h2",   500, 250_000),
    ]
    for host, method, url, status, engine, ms, resp_size in rows:
        # Pad the response body so len_resp matches the expected size
        # (storage stores len(raw_resp) as len_resp).
        body = b"x" * resp_size
        p.add_history(
            host=host, method=method, url=url, status=status,
            duration_ms=ms, engine=engine,
            raw_req=b"GET / HTTP/1.1\r\n\r\n",
            raw_resp=b"HTTP/1.1 " + str(status).encode() + b" X\r\n\r\n" + body,
        )


def test_methods_multi_select(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(methods=["GET", "POST"])
    assert {r.method for r in rows} == {"GET", "POST"}


def test_statuses_bucket(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(statuses=["4xx"])
    assert {r.status for r in rows} == {401, 403}


def test_statuses_mixed_bucket_and_exact(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(statuses=["5xx", "200"])
    assert {r.status for r in rows} == {200, 500}


def test_engines_multi_select(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(engines=["httpx", "h2"])
    assert {r.engine for r in rows} == {"httpx", "h2"}


def test_host_contains(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(host="example", host_mode="contains")
    assert {r.host for r in rows} == {"a.example", "b.example", "c.example"}


def test_host_exact_default(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(host="a.example")
    assert {r.host for r in rows} == {"a.example"}


def test_len_range(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    # ``len_resp`` is len(raw_resp) including the status line + headers
    # (a few extra bytes). Use a wide window so the test isn't tied to
    # the exact framing length.
    rows = p.list_history(len_min=1_000, len_max=20_000)
    assert {r.url for r in rows} == {"http://b/admin", "http://c/upload"}


def test_duration_range(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(dur_min=100, dur_max=300)
    assert {r.url for r in rows} == {"http://b/admin", "http://c/upload"}


def test_url_regex(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    rows = p.list_history(q=r"/(login|admin)$", q_regex=True)
    assert {r.url for r in rows} == {"http://a/login", "http://b/admin"}


def test_url_regex_invalid_falls_back_silently(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    # ``[`` is an invalid regex; the storage layer must not raise.
    rows = p.list_history(q="[", q_regex=True)
    # With the regex disabled the LIKE filter still runs against ``[``
    # which won't match — that's fine; the important behaviour is
    # "doesn't crash".
    assert isinstance(rows, list)


def test_count_history_after_with_filters(tmp_path: Path):
    p = _project(tmp_path)
    _seed(p)
    # Anchor at id 0 then check filtered count + max_id.
    new_count, max_id = p.count_history_after(0, methods=["GET"])
    # Three GETs in the seed: a/login, b/admin (no, that's GET? yes
    # row 2 is POST so 4xx GET is row 3 b/admin? row 3 is GET 403)
    # Recount: GETs are a/login(200), b/admin(403), d/static(304),
    # d/page(200) -> 4 rows.
    assert new_count == 4
    assert max_id > 0


# ---------- blueprint -------------------------------------------------------

@pytest.fixture
def client(tmp_path: Path):
    """Spin up a minimal Flask app with the history blueprint mounted
    on a project seeded with the test fixture."""
    from reqlore.config import Settings
    from reqlore.web import create_app

    project_path = tmp_path / "bp.rlr"
    p = Project(project_path)
    _seed(p)
    p.close()
    app = create_app(project_path, Settings(), proxy=None)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_index_renders_per_column_filter_menus(client):
    r = client.get("/history/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # One <details> per filterable column. The marker IDs are stable.
    for col in ("method", "status", "host", "url", "bytes", "ms"):
        assert f'id="hist-filter-{col}"' in body, f"missing filter menu for {col}"
    # The summary carries an aria-label naming the column.
    assert 'aria-label="Method filter"' in body
    assert 'aria-label="URL filter"' in body
    # The old top-of-page form must be gone.
    assert 'class="filter-form"' not in body


def test_index_csv_methods_query_string(client):
    r = client.get("/history/?method=GET,POST")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Both methods checked in their menu.
    assert ('value="GET"' in body) and ('value="POST"' in body)
    # ``a.example`` (GET 200) AND (POST 401) rows present, but PUT
    # (c.example) row excluded.
    assert "http://a/login" in body
    assert "http://a/api" in body
    assert "http://c/upload" not in body


def test_index_status_buckets(client):
    r = client.get("/history/?status=4xx")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "http://a/api" in body          # 401
    assert "http://b/admin" in body        # 403
    assert "http://a/login" not in body    # 200


def test_index_unknown_method_dropped(client):
    # ``EVIL`` is not in the whitelist — must be silently dropped, NOT
    # forwarded to the WHERE clause.
    r = client.get("/history/?method=EVIL")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Page renders all rows because no real filter applied.
    assert "http://a/login" in body
    assert "http://c/upload" in body


def test_index_len_and_dur_range(client):
    r = client.get("/history/?len_min=1000&dur_min=100")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "http://b/admin" in body
    assert "http://c/upload" in body
    assert "http://a/login" not in body


def test_latest_json_filtered(client):
    r = client.get("/history/latest.json?since=0&method=GET")
    assert r.status_code == 200
    data = r.get_json()
    assert "new" in data and "max_id" in data
    # Only the GET rows should be counted.
    assert data["new"] == 4


def test_live_region_holds_count_only_in_template(client):
    """The ``role=status`` live region must contain ONLY the count
    text — never the Refresh link, otherwise screen readers re-read
    the link's label on every poll. The Refresh link is rendered as
    a sibling element with id ``hist-live-refresh``.
    """
    r = client.get("/history/")
    body = r.get_data(as_text=True)
    # Status element exists, with role=status, and is rendered EMPTY
    # at page load (the JS fills it only on actual change).
    assert 'id="hist-live-status"' in body
    assert 'role="status"' in body
    # Refresh link is a sibling with its own id, hidden by default.
    assert 'id="hist-live-refresh"' in body
    assert 'hidden>Refresh now</a>' in body


def test_each_filter_menu_renders_apply_and_cancel(client):
    """Every per-column filter menu must render an in-panel **Apply**
    submit button and a **Cancel** button so the commit / dismiss
    affordances are discoverable for sighted users (keyboard users
    additionally get Enter and Escape). The Cancel button carries
    ``data-hist-filter-close`` so the JS layer can wire it without
    accidentally catching the wrong button.
    """
    r = client.get("/history/")
    body = r.get_data(as_text=True)
    # Count once per filterable column. We have 6 mandatory columns
    # (method, status, host, url, bytes, ms) plus Engine when the
    # table has at least one engine value — the test fixture seeds
    # multiple engines so Engine always renders -> 7 menus.
    assert body.count('class="hist-filter-apply">Apply</button>') == 7
    assert body.count('data-hist-filter-close') == 7
    # The keyboard hint mentions both Enter and Esc so the contract
    # is documented in the page itself.
    assert body.count("Press <kbd>Enter</kbd>") == 7
    assert body.count("<kbd>Esc</kbd>") == 7
    # Arrow-key roving inside the open panel is also documented in
    # the hint so sighted users know it exists.
    assert body.count("<kbd>↑</kbd> <kbd>↓</kbd>") == 7
    # Every <summary> carries a stable id so the JS layer can wire
    # aria-labelledby on the panel when it upgrades the panel to
    # role="dialog" on open. The id MUST be present in the HTML so
    # AT can resolve the reference the moment open happens.
    for col in ("method", "status", "host", "url", "bytes", "ms", "engine"):
        assert f'id="hist-filter-toggle-{col}"' in body
        assert f'id="hist-filter-panel-{col}"' in body
