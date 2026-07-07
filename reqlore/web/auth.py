"""UI authentication.

Reqlore's UI is loopback-only by default and ships unauthenticated. When the
operator opts into a non-loopback bind (``--unsafe-bind``), they must also
set a password — either as plaintext via ``REQLORE_PASSWORD`` or a
pre-computed argon2id hash via ``REQLORE_PASSWORD_HASH``. This module wires
that into the Flask app:

* A single ``/login`` route renders an accessible login form.
* A ``before_request`` hook gates every other route behind ``session["auth"]``.
* Requests originating from loopback always bypass — the operator on the
  same machine should never be locked out of their own tool, and this
  preserves the existing dev experience where no password is configured.
* Failed attempts are rate-limited with an exponential back-off keyed by
  client IP to deter trivial brute force.

The password is verified with ``argon2-cffi`` (argon2id), which is also
used to hash plaintext values once at startup so the live secret never sits
in memory beyond app init.
"""
from __future__ import annotations

import ipaddress
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..config import Settings

# Static argon2id parameters chosen to match OWASP 2024 baseline guidance
# for interactive logins (~50ms on modern hardware).
_HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# Paths that must work without auth so the login page itself can render.
# ``jwt.jwks_host`` serves an attacker-controlled JWK Set for the jku sink and
# is fetched by the *target server* (which has no Reqlore session) — testers
# legitimately point jku at lab IPs, so it must not be gated.
_PUBLIC_ENDPOINTS = frozenset({"auth.login", "auth.logout", "static", "jwt.jwks_host"})

# Per-IP throttle state: { ip: FailureRecord }. In-process only; restarts
# clear it. Acceptable for a single-operator tool; if you need persistence,
# put a real rate-limiter (e.g. nginx limit_req) in front.
@dataclass
class _FailureRecord:
    count: int = 0
    next_allowed: float = 0.0  # unix timestamp


_FAILURES: dict[str, _FailureRecord] = {}


def _client_ip() -> str:
    # We never trust X-Forwarded-For unless the operator explicitly fronted
    # us with a reverse proxy; for now the remote_addr is enough — non-
    # loopback clients are the only ones that get here at all.
    return request.remote_addr or "?"


def _is_loopback(addr: str) -> bool:
    if not addr or addr == "?":
        return False
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _settings() -> Settings:
    return current_app.config["REQLORE_SETTINGS"]


def _stored_hash() -> str:
    """Return the cached argon2 hash. Computed once at app init from
    REQLORE_PASSWORD; or used as-is when REQLORE_PASSWORD_HASH was given.
    """
    return current_app.config.get("REQLORE_PW_HASH", "")


def _verify_password(submitted: str) -> bool:
    h = _stored_hash()
    if not h or not submitted:
        return False
    try:
        return _HASHER.verify(h, submitted)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def _record_failure(ip: str) -> float:
    """Record a failed login from ``ip`` and return seconds the caller
    should wait before trying again. Back-off doubles per failure, capped
    at 60 seconds."""
    rec = _FAILURES.setdefault(ip, _FailureRecord())
    rec.count += 1
    delay = min(60.0, 0.5 * (2 ** (rec.count - 1)))
    rec.next_allowed = time.monotonic() + delay
    return delay


def _clear_failures(ip: str) -> None:
    _FAILURES.pop(ip, None)


def _check_throttle(ip: str) -> float:
    rec = _FAILURES.get(ip)
    if not rec:
        return 0.0
    remaining = rec.next_allowed - time.monotonic()
    return max(0.0, remaining)


def init_auth(app: Flask, settings: Settings) -> None:
    """Wire UI auth into ``app`` if the operator configured a password.

    Safe to call unconditionally; if no password is set the function only
    registers a no-op login route so links from misconfigured deployments
    don't 404.
    """
    # Precompute the argon2 hash so we never re-hash on every request and
    # so the plaintext is dropped from memory once the worker starts.
    pw_hash = ""
    if settings.ui_password_hash:
        pw_hash = settings.ui_password_hash
    elif settings.ui_password:
        pw_hash = _HASHER.hash(settings.ui_password)
    app.config["REQLORE_PW_HASH"] = pw_hash
    app.config["REQLORE_AUTH_ENABLED"] = bool(pw_hash)

    # Harden the session cookie. ``Secure`` is only set when the operator
    # is fronting us with TLS; we can't infer that, so we expose it as a
    # config hook and default to off (loopback HTTP is the common case).
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Strict")
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", settings.session_max_age_s)

    @app.before_request
    def _require_auth():
        if not app.config.get("REQLORE_AUTH_ENABLED"):
            return None
        # The login form, logout, and static assets must always be reachable.
        if request.endpoint in _PUBLIC_ENDPOINTS:
            return None
        # Loopback clients never need a password — they already have local
        # filesystem access to the project anyway.
        if _is_loopback(_client_ip()):
            return None
        if session.get("auth") is True:
            # Sliding-window: refresh the session so an active operator
            # isn't logged out mid-engagement.
            session.permanent = True
            session.modified = True
            return None
        # API-shaped requests (anything posting JSON or the X-Reqlore-CSRF
        # header) get a clean 401 instead of an HTML redirect they can't
        # follow.
        if request.method != "GET" or request.headers.get("X-Reqlore-CSRF"):
            abort(401)
        return redirect(url_for("auth.login", next=request.full_path or "/"))

    # Blueprint-shaped routes so url_for("auth.login") works from anywhere.
    from flask import Blueprint
    bp = Blueprint("auth", __name__)

    @bp.route("/login", methods=("GET", "POST"))
    def login():
        if not app.config.get("REQLORE_AUTH_ENABLED"):
            # No password configured — pretend the route doesn't exist
            # rather than render a useless form.
            abort(404)
        ip = _client_ip()
        error = ""
        if request.method == "POST":
            wait = _check_throttle(ip)
            if wait > 0:
                error = (f"Too many failed attempts. Try again in "
                         f"{int(wait) + 1} seconds.")
            else:
                # CSRF is enforced by the global before_request hook in
                # web/__init__.py; we only need to check the password.
                submitted = request.form.get("password", "")
                if _verify_password(submitted):
                    _clear_failures(ip)
                    # Rotate the session id on privilege change to defeat
                    # session-fixation attempts.
                    session.clear()
                    session["auth"] = True
                    session["csrf"] = secrets.token_urlsafe(32)
                    session.permanent = True
                    target = request.args.get("next") or url_for("dashboard.index")
                    # L-2: open-redirect guard. urlsplit() rejects any
                    # ``next`` value carrying a scheme or netloc (
                    # ``//evil.tld/path``, ``https://evil.tld``,
                    # ``http:evil.tld``); only same-origin paths are
                    # honoured, anything else falls back to the
                    # dashboard.
                    from urllib.parse import urlsplit
                    parts = urlsplit(target)
                    if parts.scheme or parts.netloc \
                            or not target.startswith("/") \
                            or target.startswith("//"):
                        target = url_for("dashboard.index")
                    flash("Signed in.", "info")
                    return redirect(target)
                delay = _record_failure(ip)
                error = (f"Incorrect password. Wait {int(delay) + 1} "
                         "seconds before retrying.")
        # GET, or POST with error -> render the form.
        return render_template("login.html", error=error,
                               next_url=request.args.get("next", "")), \
               (401 if error else 200)

    @bp.route("/logout", methods=("POST",))
    def logout():
        session.clear()
        flash("Signed out.", "info")
        return redirect(url_for("auth.login"))

    app.register_blueprint(bp)
