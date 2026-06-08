"""Tests for the UI password gate."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings, settings_from_env
from reqlore.web import create_app


@pytest.fixture(autouse=True)
def _reset_throttle():
    """The auth module keeps an in-process failure counter keyed by IP
    so tests would interfere with each other through that shared dict.
    """
    from reqlore.web import auth as _auth
    _auth._FAILURES.clear()
    yield
    _auth._FAILURES.clear()


def _client(tmp_path: Path, **kw):
    proj = tmp_path / "auth.rlr"
    s = Settings(**kw)
    app = create_app(proj, s, proxy=None)
    app.testing = True
    return app, app.test_client()


# ---------------------------------------------------------------------------
# Defaults: no password configured -> open UI, no /login route.
# ---------------------------------------------------------------------------

def test_no_auth_when_password_unset(tmp_path):
    _, c = _client(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    assert b"Dashboard" in r.data


def test_login_404_when_auth_disabled(tmp_path):
    _, c = _client(tmp_path)
    r = c.get("/login")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Password configured -> non-loopback callers must sign in.
# ---------------------------------------------------------------------------

def test_loopback_bypasses_password(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    # Default test_client remote_addr is 127.0.0.1 -> loopback bypass.
    r = c.get("/")
    assert r.status_code == 200
    assert b"Dashboard" in r.data


def test_non_loopback_redirects_to_login(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    r = c.get("/", environ_overrides={"REMOTE_ADDR": "10.0.0.5"})
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_login_page_renders(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    r = c.get("/login", environ_overrides={"REMOTE_ADDR": "10.0.0.5"})
    assert r.status_code == 200
    assert b'name="password"' in r.data
    # a11y essentials present on the login page
    assert b'autocomplete="current-password"' in r.data
    assert b'aria-required="true"' in r.data
    assert b'class="skip-link"' in r.data
    assert b'aria-live="polite"' in r.data


def test_correct_password_grants_session(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    env = {"REMOTE_ADDR": "10.0.0.5"}
    # Seed the CSRF cookie via a GET to the login page.
    c.get("/login", environ_overrides=env)
    with c.session_transaction() as sess:
        token = sess["csrf"]
    r = c.post("/login", data={"_csrf": token, "password": "hunter2"},
               environ_overrides=env)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/")
    # Subsequent request from the same client must now succeed.
    r2 = c.get("/", environ_overrides=env)
    assert r2.status_code == 200


def test_wrong_password_is_rejected(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    env = {"REMOTE_ADDR": "10.0.0.5"}
    c.get("/login", environ_overrides=env)
    with c.session_transaction() as sess:
        token = sess["csrf"]
    r = c.post("/login", data={"_csrf": token, "password": "WRONG"},
               environ_overrides=env)
    assert r.status_code == 401
    assert b"Incorrect password" in r.data
    # No session granted.
    r2 = c.get("/", environ_overrides=env)
    assert r2.status_code == 302


def test_logout_clears_session(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    env = {"REMOTE_ADDR": "10.0.0.5"}
    c.get("/login", environ_overrides=env)
    with c.session_transaction() as sess:
        token = sess["csrf"]
    c.post("/login", data={"_csrf": token, "password": "hunter2"},
           environ_overrides=env)
    # Now sign out.
    with c.session_transaction() as sess:
        token = sess["csrf"]
    r = c.post("/logout", data={"_csrf": token}, environ_overrides=env)
    assert r.status_code == 302
    r2 = c.get("/", environ_overrides=env)
    assert r2.status_code == 302  # back to login


def test_open_redirect_guard(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    env = {"REMOTE_ADDR": "10.0.0.5"}
    c.get("/login?next=//evil.example/", environ_overrides=env)
    with c.session_transaction() as sess:
        token = sess["csrf"]
    r = c.post("/login?next=//evil.example/",
               data={"_csrf": token, "password": "hunter2"},
               environ_overrides=env)
    assert r.status_code == 302
    # Must not honour scheme-relative or absolute external URLs.
    assert "evil.example" not in r.headers["Location"]


def test_api_shaped_request_gets_401_not_redirect(tmp_path):
    _, c = _client(tmp_path, ui_password="hunter2")
    env = {"REMOTE_ADDR": "10.0.0.5"}
    # XHR-style GET with X-Reqlore-CSRF header signals a non-browser caller;
    # the auth gate must return 401 instead of a redirect they can't follow.
    r = c.get("/history/", environ_overrides=env,
              headers={"X-Reqlore-CSRF": "anything"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# REQLORE_PASSWORD env-var plumbing.
# ---------------------------------------------------------------------------

def test_settings_from_env_reads_password(monkeypatch):
    monkeypatch.setenv("REQLORE_PASSWORD", "from-env")
    s = settings_from_env(Settings())
    assert s.ui_password == "from-env"
    assert s.auth_enabled


def test_settings_from_env_reads_password_hash(monkeypatch):
    monkeypatch.setenv("REQLORE_PASSWORD_HASH",
                       "$argon2id$v=19$m=65536,t=3,p=2$xxxx$yyyy")
    s = settings_from_env(Settings())
    assert s.ui_password_hash.startswith("$argon2id$")
    assert s.auth_enabled


def test_pre_hashed_password_accepts_login(tmp_path):
    """A REQLORE_PASSWORD_HASH-style deployment (no plaintext in env)."""
    from argon2 import PasswordHasher
    hasher = PasswordHasher(time_cost=2, memory_cost=8 * 1024, parallelism=1)
    h = hasher.hash("super-secret")
    _, c = _client(tmp_path, ui_password_hash=h)
    env = {"REMOTE_ADDR": "10.0.0.5"}
    c.get("/login", environ_overrides=env)
    with c.session_transaction() as sess:
        token = sess["csrf"]
    r = c.post("/login", data={"_csrf": token, "password": "super-secret"},
               environ_overrides=env)
    assert r.status_code == 302


# ---------------------------------------------------------------------------
# CLI guard: --unsafe-bind without a password is refused.
# ---------------------------------------------------------------------------

def test_cli_refuses_unsafe_bind_without_password(monkeypatch, capsys):
    import argparse
    from reqlore.cli import _enforce_unsafe_bind_password
    monkeypatch.delenv("REQLORE_PASSWORD", raising=False)
    monkeypatch.delenv("REQLORE_PASSWORD_HASH", raising=False)
    s = Settings(ui_host="0.0.0.0")
    args = argparse.Namespace(unsafe_bind=True, no_password=False)
    rc = _enforce_unsafe_bind_password(s, args)
    assert rc == 2
    err = capsys.readouterr().err
    assert "REQLORE_PASSWORD" in err


def test_cli_allows_unsafe_bind_with_password(monkeypatch):
    import argparse
    from reqlore.cli import _enforce_unsafe_bind_password
    s = Settings(ui_host="0.0.0.0", ui_password="x")
    args = argparse.Namespace(unsafe_bind=True, no_password=False)
    assert _enforce_unsafe_bind_password(s, args) is None


def test_cli_allows_unsafe_bind_with_no_password_flag(monkeypatch, capsys):
    import argparse
    from reqlore.cli import _enforce_unsafe_bind_password
    monkeypatch.delenv("REQLORE_PASSWORD", raising=False)
    s = Settings(ui_host="0.0.0.0")
    args = argparse.Namespace(unsafe_bind=True, no_password=True)
    assert _enforce_unsafe_bind_password(s, args) is None
    err = capsys.readouterr().err
    assert "without authentication" in err


def test_cli_loopback_never_requires_password():
    import argparse
    from reqlore.cli import _enforce_unsafe_bind_password
    s = Settings(ui_host="127.0.0.1")
    args = argparse.Namespace(unsafe_bind=True, no_password=False)
    assert _enforce_unsafe_bind_password(s, args) is None
