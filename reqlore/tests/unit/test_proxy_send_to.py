"""Tests for the Proxy "Send to" dispatch and bulk send-to-Repeater.

These exercise the end-to-end browser flow: a held intercept can be
copied into Repeater, Intruder, Comparer, PoC, JWT and Decoder; the
target page must hydrate from the snapshot history row; the held
intercept is left in the queue (non-destructive, like Burp's Action
menu); and the menu adapts to the request shape (JWT only when an
Authorization: Bearer JWT is present, Decoder only when a body exists).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


def _strip_u(html: str) -> str:
    """Remove `<u>…</u>` tags so substring assertions can ignore the
    access-key underline markup embedded in button labels."""
    return re.sub(r"</?u>", "", html)


@pytest.fixture
def app(tmp_path: Path):
    proj = tmp_path / "proxy.rlr"
    return create_app(proj, Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def project(app):
    return app.extensions["reqlore_project"]


def _csrf(client) -> str:
    client.get("/proxy/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# A representative held request: real-shaped HTTP/1.1 with Host, body,
# and a JWT-shaped Authorization header so the JWT target appears.
_RAW = (
    b"POST /api/login HTTP/1.1\r\n"
    b"Host: target.test\r\n"
    b"Authorization: Bearer "
    b"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 17\r\n"
    b"\r\n"
    b'{"u":"a","p":"b"}'
)


def _seed(project) -> int:
    return project.enqueue_intercept("request", _RAW, "manual")


def test_intercept_detail_lists_send_targets(client, project):
    iid = _seed(project)
    r = client.get(f"/proxy/intercept/{iid}")
    assert r.status_code == 200
    body = _strip_u(r.data.decode("utf-8", "replace"))
    # All six targets should be offered for a JSON body + JWT request.
    for label in ("Send to Repeater", "Send to Intruder",
                  "Send to Comparer", "Send to PoC builder",
                  "Send to JWT workbench", "Send to Decoder"):
        assert label in body, f"missing menu entry: {label}"
    # Breadcrumb is rendered for orientation (WCAG 2.4.8 Location).
    assert 'aria-label="Breadcrumb"' in body
    # Access keys are wired on the action buttons so the buttons can be
    # activated from anywhere on the page (Alt+letter / Alt+Shift+letter
    # depending on browser). The underline markup itself is verified by
    # checking the *raw* (non-stripped) response below.
    raw = r.data.decode("utf-8", "replace")
    assert 'accesskey="r"' in raw   # Send to Repeater
    assert 'accesskey="e"' in raw   # Forward edited
    assert 'accesskey="p"' in raw   # Drop
    assert "<u>R</u>epeater" in raw
    assert "Forward <u>e</u>dited" in raw


def test_send_target_menu_hides_jwt_without_bearer(client, project):
    raw = (b"GET /healthz HTTP/1.1\r\nHost: x.test\r\n\r\n")
    iid = project.enqueue_intercept("request", raw, "manual")
    body = _strip_u(client.get(f"/proxy/intercept/{iid}").data.decode())
    assert "Send to JWT workbench" not in body
    assert "Send to Decoder" not in body          # no body either
    assert "Send to Repeater" in body             # always available


def test_send_to_repeater_snapshots_history_and_redirects(client, project):
    iid = _seed(project)
    csrf = _csrf(client)
    before = project.history_count()
    r = client.post(f"/proxy/intercept/{iid}/send/repeater",
                    data={"_csrf": csrf})
    assert r.status_code == 302
    assert project.history_count() == before + 1
    # Snapshot is tagged so it can be distinguished from real proxied
    # traffic in the history view.
    rows = project.list_history(limit=1)
    assert rows[0].engine == "intercept-snapshot"
    assert f"intercept:{iid}" in rows[0].tags
    # Repeater landing URL carries the new history id.
    assert "/repeater/" in r.headers["Location"]
    assert f"from_history={rows[0].id}" in r.headers["Location"]
    # Crucially: the held intercept is still pending.
    decision, _ = project.get_intercept_decision(iid)
    assert decision is None


@pytest.mark.parametrize("slug,fragment", [
    ("intruder", "/intruder/new"),
    ("comparer", "/comparer/"),
    ("poc",      "/poc/"),
    ("jwt",      "/jwt/"),
    ("decoder",  "/decoder/"),
])
def test_send_to_each_tool_redirects(client, project, slug, fragment):
    iid = _seed(project)
    csrf = _csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/{slug}",
                    data={"_csrf": csrf})
    assert r.status_code == 302
    assert fragment in r.headers["Location"]
    decision, _ = project.get_intercept_decision(iid)
    assert decision is None, "Send-to must not forward or drop the flow"


def test_send_to_unknown_slug_404s(client, project):
    iid = _seed(project)
    csrf = _csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/nope",
                    data={"_csrf": csrf})
    assert r.status_code == 404


def test_send_to_intruder_prefills_template(client, project):
    iid = _seed(project)
    csrf = _csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/intruder",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    # The raw POST line and Host should appear in the pre-filled template.
    assert "POST /api/login HTTP/1.1" in body
    assert "target.test" in body


def test_send_to_jwt_prefills_token(client, project):
    iid = _seed(project)
    csrf = _csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/jwt",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    # The token from Authorization: Bearer reaches the JWT form field.
    assert b"eyJhbGciOiJub25lIn0" in r.data


def test_send_all_to_repeater_snapshots_every_pending(client, project):
    ids = [_seed(project) for _ in range(3)]
    csrf = _csrf(client)
    before = project.history_count()
    r = client.post("/proxy/intercept/send_all/repeater",
                    data={"_csrf": csrf})
    assert r.status_code == 302
    assert project.history_count() == before + 3
    assert "/repeater/" in r.headers["Location"]
    # All three intercepts remain pending afterwards.
    for iid in ids:
        decision, _ = project.get_intercept_decision(iid)
        assert decision is None


def test_send_all_to_repeater_with_empty_queue_flashes_and_redirects(client, project):
    csrf = _csrf(client)
    r = client.post("/proxy/intercept/send_all/repeater",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    assert b"No pending intercepts" in r.data
