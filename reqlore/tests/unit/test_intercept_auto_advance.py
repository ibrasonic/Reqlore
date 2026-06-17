"""Auto-advance after intercept decisions.

When the operator hits Forward / Drop / Forward-edited on an intercept
detail page, Reqlore should jump straight to the next still-pending
intercept (i.e. "stay in the held flow") instead of bouncing back to
the queue page. This file pins that behaviour: one redirect per
decision, never two.

Empty-queue case must still land on ``/proxy/`` so the operator sees
the "nothing held" state.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    proj = tmp_path / "advance.rlr"
    return create_app(proj, Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    # Touching any page seeds the CSRF token in the session.
    client.get("/proxy/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _enqueue(app, n: int) -> list[int]:
    project = app.extensions["reqlore_project"]
    return [
        project.enqueue_intercept_sync(
            "request", f"GET /r{i} HTTP/1.1\r\n\r\n".encode(), "test", f"f{i}",
        )
        for i in range(n)
    ]


def test_next_redirects_to_oldest_pending(client, app):
    ids = _enqueue(app, 3)
    r = client.get("/proxy/intercept/next")
    assert r.status_code == 302
    assert r.headers["Location"].endswith(f"/proxy/intercept/{ids[0]}")


def test_next_falls_back_to_queue_when_empty(client):
    r = client.get("/proxy/intercept/next")
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/proxy/")


def test_forward_auto_advances_to_next(client, app):
    ids = _enqueue(app, 3)
    token = _csrf(client)
    r = client.post(f"/proxy/intercept/{ids[0]}/forward",
                    data={"_csrf": token})
    assert r.status_code == 302
    # Must land on the next pending detail page, NOT the queue.
    assert r.headers["Location"].endswith(f"/proxy/intercept/{ids[1]}")


def test_drop_auto_advances_to_next(client, app):
    ids = _enqueue(app, 3)
    token = _csrf(client)
    r = client.post(f"/proxy/intercept/{ids[1]}/drop",
                    data={"_csrf": token})
    assert r.status_code == 302
    # Drop on ids[1] should skip to the next pending (ids[0] is still
    # held, but the operator was looking at ids[1]; the auto-advance
    # picks the oldest pending overall, which is ids[0]).
    assert (r.headers["Location"].endswith(f"/proxy/intercept/{ids[0]}")
            or r.headers["Location"].endswith(f"/proxy/intercept/{ids[2]}"))


def test_forward_edited_auto_advances(client, app):
    ids = _enqueue(app, 2)
    token = _csrf(client)
    r = client.post(f"/proxy/intercept/{ids[0]}/forward_edited",
                    data={"_csrf": token, "raw": "GET /edited HTTP/1.1\r\n\r\n"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith(f"/proxy/intercept/{ids[1]}")


def test_decision_on_last_pending_returns_to_queue(client, app):
    ids = _enqueue(app, 1)
    token = _csrf(client)
    r = client.post(f"/proxy/intercept/{ids[0]}/forward",
                    data={"_csrf": token})
    assert r.status_code == 302
    # Nothing left held — land on the queue page.
    assert r.headers["Location"].endswith("/proxy/")


def test_just_decided_intercept_is_not_picked_as_next(client, app):
    """The auto-advance must not loop back to the request we just
    decided — that would re-render its detail page with a stale 'pending'
    badge and confuse the operator."""
    ids = _enqueue(app, 2)
    token = _csrf(client)
    r = client.post(f"/proxy/intercept/{ids[0]}/forward",
                    data={"_csrf": token})
    assert r.status_code == 302
    target = r.headers["Location"]
    assert not target.endswith(f"/proxy/intercept/{ids[0]}")
    assert target.endswith(f"/proxy/intercept/{ids[1]}")
