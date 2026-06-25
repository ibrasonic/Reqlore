"""Phase 10 — auth-aware scan + session handling tests.

Covers the new module :mod:`reqlore.scanner.auth_session` and its
integration with the active scanner.

All HTTP is mocked via in-memory senders; no network. We also
exercise the secret-redaction guarantees of :class:`AuthCredentials`
and the parallel-isolation guarantee of two independent sessions.
"""
from __future__ import annotations

import json
import pickle

import pytest

from reqlore.engines import Request, Response
from reqlore.macros import Macro, MacroStep
from reqlore.scanner import (
    ActiveOptions,
    ActiveScanner,
    AuthCredentials,
    AuthSession,
    AuthSessionConfig,
    AuthSessionStats,
    build_auth_session_from_state,
)
from reqlore.scanner.auth_session import (
    _extract_csrf_tokens,
    _name_in_json_or_form,
    _origin_root,
    harvest_cookies_from_set_cookie,
)


# ---------------------------------------------------------------------------
# Helpers — fakes for the macro sender + scanner sender.
# ---------------------------------------------------------------------------

def _resp(status: int = 200, *, body: bytes = b"",
           headers: list[tuple[str, str]] | None = None,
           error: str = "") -> Response:
    return Response(
        status=status,
        headers=list(headers or []),
        body=body,
        error=error or None,
    )


class _ScriptedSender:
    """Sender that returns canned responses keyed by request URL.

    Each entry in ``script`` is either a Response or a callable
    ``(req) -> Response``. Unmatched URLs fall through to
    ``default_response`` (or a 404 if not given).
    """

    def __init__(
        self,
        script: dict[str, object],
        *,
        default_response: Response | None = None,
    ) -> None:
        self.script = script
        self.default = default_response or _resp(404)
        self.calls: list[Request] = []

    def __call__(self, req: Request) -> Response:
        self.calls.append(req)
        entry = self.script.get(req.url)
        if entry is None:
            return self.default
        if callable(entry):
            return entry(req)
        return entry


def _login_macro(*, login_url: str = "https://app.test/login") -> Macro:
    """Minimal login macro: POST username+password, server replies
    with Set-Cookie: SID=..., done."""
    return Macro(
        name="login",
        steps=[
            MacroStep(
                name="post-login",
                method="POST",
                url=login_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="username={{username}}&password={{password}}",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# AuthCredentials — secret hygiene.
# ---------------------------------------------------------------------------

def test_credentials_repr_redacts_values():
    c = AuthCredentials({"username": "alice", "password": "topsecret"})
    assert "alice" not in repr(c)
    assert "topsecret" not in repr(c)
    assert "topsecret" not in str(c)
    assert "redacted" in repr(c).lower()
    assert "2" in repr(c)  # shows the count


def test_credentials_values_returns_defensive_copy():
    c = AuthCredentials({"username": "alice", "password": "topsecret"})
    out = c.values()
    out["password"] = "tampered"
    # Internal state is unchanged.
    assert c.values()["password"] == "topsecret"


def test_credentials_refuses_to_pickle():
    c = AuthCredentials({"password": "topsecret"})
    with pytest.raises(TypeError):
        pickle.dumps(c)


def test_credentials_refuses_json_via_default_encoder():
    c = AuthCredentials({"password": "topsecret"})
    with pytest.raises(TypeError):
        json.dumps(c, default=lambda o: o.__getstate__())


def test_credentials_bool_truthy_only_when_populated():
    assert not AuthCredentials()
    assert AuthCredentials({"k": "v"})


def test_credentials_keys_returns_names_only():
    c = AuthCredentials({"a": "1", "b": "2"})
    assert set(c.keys()) == {"a", "b"}


def test_credentials_drops_none_values():
    c = AuthCredentials({"a": "1", "b": None})  # type: ignore[dict-item]
    assert set(c.keys()) == {"a"}


# ---------------------------------------------------------------------------
# AuthSessionConfig — validation.
# ---------------------------------------------------------------------------

def test_config_rejects_zero_macro_id():
    with pytest.raises(ValueError):
        AuthSessionConfig(macro_id=0)


def test_config_rejects_negative_revalidate():
    with pytest.raises(ValueError):
        AuthSessionConfig(macro_id=1, revalidate_every_n_probes=-1)


def test_config_rejects_negative_ttl():
    with pytest.raises(ValueError):
        AuthSessionConfig(macro_id=1, csrf_token_ttl_seconds=-1.0)


def test_config_defaults_sensible():
    c = AuthSessionConfig(macro_id=1)
    assert c.revalidate_every_n_probes == 25
    assert c.validity_failure_statuses == (401, 403)
    assert "login" in c.validity_failure_location_substrings


# ---------------------------------------------------------------------------
# harvest_cookies_from_set_cookie — header parser.
# ---------------------------------------------------------------------------

def test_harvest_simple_cookie():
    out = harvest_cookies_from_set_cookie("SID=abc123; Path=/; HttpOnly")
    assert out == {"SID": "abc123"}


def test_harvest_multi_cookie_with_attrs():
    val = ("SID=abc; Path=/; HttpOnly, "
           "CSRF=xyz; Path=/; SameSite=Lax")
    out = harvest_cookies_from_set_cookie(val)
    assert out == {"SID": "abc", "CSRF": "xyz"}


def test_harvest_only_filter_is_case_insensitive():
    out = harvest_cookies_from_set_cookie(
        "SID=abc; Path=/, irrelevant=zzz", only=("sid",),
    )
    assert out == {"SID": "abc"}


def test_harvest_empty_returns_empty_dict():
    assert harvest_cookies_from_set_cookie("") == {}
    assert harvest_cookies_from_set_cookie("   ") == {}


def test_harvest_keeps_first_occurrence_only():
    out = harvest_cookies_from_set_cookie("SID=one, SID=two")
    assert out == {"SID": "one"}


# ---------------------------------------------------------------------------
# prime() — runs macro, harvests cookies.
# ---------------------------------------------------------------------------

def test_prime_runs_macro_and_harvests_session_cookie():
    sender = _ScriptedSender({
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=abc; Path=/; HttpOnly")],
        ),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            credentials=AuthCredentials(
                {"username": "alice", "password": "x"},
            ),
            session_cookie_names=("SID",),
        ),
    )
    sess.prime(sender=sender)
    assert sess.primed is True
    assert sess.session_cookies == {"SID": "abc"}
    assert sess.stats.macro_runs == 1
    assert sess.stats.macro_failures == 0
    # Credentials must NOT appear in the macro definition's variables.
    assert "topsecret" not in sess.macro.to_json()


def test_prime_substitutes_credentials_into_macro_body():
    captured: list[bytes] = []

    def sender(req: Request) -> Response:
        captured.append(req.body)
        return _resp(200, headers=[("Set-Cookie", "SID=ok")])

    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            credentials=AuthCredentials(
                {"username": "alice", "password": "topsecret"},
            ),
            session_cookie_names=("SID",),
        ),
    )
    sess.prime(sender=sender)
    body = captured[0].decode()
    assert "alice" in body
    assert "topsecret" in body


def test_prime_marks_failure_when_step_errors():
    sender = _ScriptedSender({
        "https://app.test/login": _resp(500, error="connect"),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess.prime(sender=sender)
    assert sess.stats.macro_runs == 1
    assert sess.stats.macro_failures == 1


def test_prime_marks_failure_on_4xx_last_step():
    sender = _ScriptedSender({
        "https://app.test/login": _resp(401),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess.prime(sender=sender)
    assert sess.stats.macro_failures == 1


# ---------------------------------------------------------------------------
# apply_to_request — cookie + header injection.
# ---------------------------------------------------------------------------

def test_apply_injects_cookies_into_outgoing_request():
    sender = _ScriptedSender({
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=abc")],
        ),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess.prime(sender=sender)
    req = Request("GET", "https://app.test/dashboard", [], b"")
    out = sess.apply_to_request(req)
    cookie = [v for k, v in out.headers if k.lower() == "cookie"]
    assert cookie and "SID=abc" in cookie[0]


def test_apply_merges_with_existing_cookie_header():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess._session_cookies["SID"] = "new"  # pre-set, no prime
    req = Request(
        "GET", "https://app.test/x",
        [("Cookie", "tracker=keep; SID=old"), ("Accept", "*/*")],
        b"",
    )
    out = sess.apply_to_request(req)
    cookie_lines = [v for k, v in out.headers if k.lower() == "cookie"]
    assert len(cookie_lines) == 1
    assert "SID=new" in cookie_lines[0]
    assert "tracker=keep" in cookie_lines[0]
    # Non-cookie headers preserved.
    assert ("Accept", "*/*") in out.headers


def test_apply_injects_bearer_header():
    sender = _ScriptedSender({
        "https://app.test/login": _resp(
            200,
            headers=[
                ("Authorization", "Bearer abc123"),
                ("Set-Cookie", "SID=irrelevant"),
            ],
        ),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            extra_session_headers=("Authorization",),
        ),
    )
    sess.prime(sender=sender)
    req = Request("GET", "https://app.test/me", [], b"")
    out = sess.apply_to_request(req)
    auth = [v for k, v in out.headers if k.lower() == "authorization"]
    assert auth == ["Bearer abc123"]


def test_apply_overwrites_existing_header():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1, extra_session_headers=("Authorization",),
        ),
    )
    sess._session_headers["Authorization"] = "Bearer new"
    req = Request(
        "GET", "https://app.test/x",
        [("Authorization", "Bearer stale")], b"",
    )
    out = sess.apply_to_request(req)
    auths = [v for k, v in out.headers if k.lower() == "authorization"]
    assert auths == ["Bearer new"]


def test_apply_is_a_noop_when_no_cookies_or_headers():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    req = Request("GET", "https://app.test/x", [("X", "Y")], b"")
    out = sess.apply_to_request(req)
    assert out is req or out.headers == req.headers


# ---------------------------------------------------------------------------
# notify_response — opportunistic cookie rotation.
# ---------------------------------------------------------------------------

def test_notify_picks_up_rotated_cookie():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess._session_cookies["SID"] = "old"
    sess.notify_response(
        Request("GET", "https://app.test/x", [], b""),
        _resp(200, headers=[("Set-Cookie", "SID=newer; Path=/")]),
    )
    assert sess.session_cookies["SID"] == "newer"


def test_notify_ignores_empty_clearing_set_cookie():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, session_cookie_names=("SID",)),
    )
    sess._session_cookies["SID"] = "keep"
    sess.notify_response(
        Request("GET", "https://app.test/logout", [], b""),
        _resp(200, headers=[("Set-Cookie", "SID=; Path=/; Max-Age=0")]),
    )
    # We refused to overwrite with the empty value.
    assert sess.session_cookies["SID"] == "keep"


# ---------------------------------------------------------------------------
# maybe_revalidate — periodic session-validity check.
# ---------------------------------------------------------------------------

def test_revalidate_disabled_when_zero_threshold():
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(macro_id=1, revalidate_every_n_probes=0),
    )
    for _ in range(50):
        assert sess.maybe_revalidate() is False
    assert sess.stats.validity_probes == 0
    assert sess.stats.session_recoveries == 0


def test_revalidate_fires_only_after_threshold():
    macro_runs = [0]

    def sender(req: Request) -> Response:
        if req.url == "https://app.test/login":
            macro_runs[0] += 1
            return _resp(200, headers=[("Set-Cookie", "SID=ok")])
        # Validity probe — always healthy.
        return _resp(200, body=b"hello")

    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            validity_probe_url="https://app.test/me",
            revalidate_every_n_probes=3,
        ),
    )
    sess.prime(sender=sender)
    # 1, 2 → nothing. 3 → validity probe. 4, 5 → nothing. 6 → again.
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.maybe_revalidate(sender=sender) is False
    assert sess.stats.validity_probes == 2
    assert sess.stats.session_recoveries == 0


def test_revalidate_runs_macro_on_401():
    macro_runs = [0]

    def sender(req: Request) -> Response:
        if req.url == "https://app.test/login":
            macro_runs[0] += 1
            return _resp(200, headers=[("Set-Cookie", "SID=fresh")])
        # Validity probe → 401 → recovery.
        return _resp(401)

    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            validity_probe_url="https://app.test/me",
            revalidate_every_n_probes=1,
        ),
    )
    sess.prime(sender=sender)
    sess.maybe_revalidate(sender=sender)
    assert sess.stats.session_recoveries == 1
    assert macro_runs[0] == 2  # initial prime + recovery
    assert sess.stats.macro_runs == 2


def test_revalidate_runs_macro_on_302_to_login():
    def sender(req: Request) -> Response:
        if req.url == "https://app.test/login":
            return _resp(200, headers=[("Set-Cookie", "SID=fresh")])
        # Validity probe → 302 to /login → recovery.
        return _resp(302, headers=[("Location", "/login?next=/me")])

    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            validity_probe_url="https://app.test/me",
            revalidate_every_n_probes=1,
        ),
    )
    sess.prime(sender=sender)
    sess.maybe_revalidate(sender=sender)
    assert sess.stats.session_recoveries == 1


def test_revalidate_no_probe_url_runs_macro_preemptively():
    """When ``validity_probe_url`` is None, every threshold-hit
    re-runs the macro unconditionally (Burp's "regenerate session
    every N requests" mode)."""
    def sender(req: Request) -> Response:
        return _resp(200, headers=[("Set-Cookie", "SID=" + str(id(req)))])

    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            validity_probe_url=None,
            revalidate_every_n_probes=2,
        ),
    )
    sess.prime(sender=sender)
    sess.maybe_revalidate(sender=sender)
    sess.maybe_revalidate(sender=sender)
    assert sess.stats.session_recoveries == 1
    assert sess.stats.macro_runs == 2  # prime + 1 recovery


# ---------------------------------------------------------------------------
# CSRF re-fetch.
# ---------------------------------------------------------------------------

_FORM_HTML = (
    b"<html><body>"
    b"<form><input type='hidden' name='csrf_token' value='FRESH-TOK-001'>"
    b"<input type='text' name='comment'></form>"
    b"</body></html>"
)


def test_csrf_token_swap_in_urlencoded_body():
    sender = _ScriptedSender({
        "https://app.test/comment": _resp(200, body=_FORM_HTML),
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=ok")],
        ),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            csrf_token_names=("csrf_token",),
        ),
    )
    sess.prime(sender=sender)
    req = Request(
        "POST", "https://app.test/comment",
        [("Referer", "https://app.test/comment")],
        b"csrf_token=STALE&comment=hi",
    )
    out = sess.apply_to_request(req, sender=sender)
    assert b"FRESH-TOK-001" in out.body
    assert b"STALE" not in out.body
    assert sess.stats.csrf_token_refetches == 1
    assert sess.stats.csrf_token_swaps == 1


def test_csrf_token_swap_caches_within_ttl():
    sender = _ScriptedSender({
        "https://app.test/comment": _resp(200, body=_FORM_HTML),
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=ok")],
        ),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            csrf_token_names=("csrf_token",),
            csrf_token_ttl_seconds=60.0,
        ),
    )
    sess.prime(sender=sender)
    req = Request(
        "POST", "https://app.test/comment",
        [("Referer", "https://app.test/comment")],
        b"csrf_token=STALE&comment=hi",
    )
    sess.apply_to_request(req, sender=sender)
    sess.apply_to_request(req, sender=sender)
    sess.apply_to_request(req, sender=sender)
    # The form page should only have been fetched once thanks to TTL.
    assert sess.stats.csrf_token_refetches == 1
    assert sess.stats.csrf_token_swaps == 3


def test_csrf_token_swap_skipped_when_token_field_absent():
    sender = _ScriptedSender({
        "https://app.test/post": _resp(200, body=_FORM_HTML),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1, csrf_token_names=("csrf_token",),
        ),
    )
    req = Request(
        "POST", "https://app.test/post",
        [("Referer", "https://app.test/post")],
        b"only=plain&data=here",
    )
    sess.apply_to_request(req, sender=sender)
    assert sess.stats.csrf_token_refetches == 0
    assert sess.stats.csrf_token_swaps == 0


def test_csrf_token_swap_in_json_body():
    sender = _ScriptedSender({
        "https://app.test/api/items": _resp(200, body=_FORM_HTML),
    })
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1, csrf_token_names=("csrf_token",),
        ),
    )
    req = Request(
        "POST", "https://app.test/api/items",
        [("Referer", "https://app.test/api/items"),
         ("Content-Type", "application/json")],
        b'{"csrf_token":"OLD","data":1}',
    )
    out = sess.apply_to_request(req, sender=sender)
    assert b"FRESH-TOK-001" in out.body
    assert b"OLD" not in out.body


def test_csrf_extract_handles_meta_tag():
    html = (
        '<head><meta name="csrf-token" content="META-VAL-9"></head>'
        '<body></body>'
    )
    out = _extract_csrf_tokens(html, ["csrf-token"])
    assert out == {"csrf-token": "META-VAL-9"}


def test_csrf_extract_input_wins_over_meta():
    html = (
        '<meta name="t" content="meta-val">'
        '<input name="t" value="input-val">'
    )
    out = _extract_csrf_tokens(html, ["t"])
    assert out == {"t": "input-val"}


# ---------------------------------------------------------------------------
# Per-instance isolation.
# ---------------------------------------------------------------------------

def test_two_sessions_have_isolated_cookie_jars():
    s1_sender = _ScriptedSender({
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=ONE")],
        ),
    })
    s2_sender = _ScriptedSender({
        "https://app.test/login": _resp(
            200, headers=[("Set-Cookie", "SID=TWO")],
        ),
    })
    cfg = AuthSessionConfig(macro_id=1, session_cookie_names=("SID",))
    s1 = AuthSession(_login_macro(), cfg)
    s2 = AuthSession(_login_macro(), cfg)
    s1.prime(sender=s1_sender)
    s2.prime(sender=s2_sender)
    assert s1.session_cookies == {"SID": "ONE"}
    assert s2.session_cookies == {"SID": "TWO"}


def test_stats_are_isolated_between_sessions():
    s1 = AuthSession(_login_macro(), AuthSessionConfig(macro_id=1))
    s2 = AuthSession(_login_macro(), AuthSessionConfig(macro_id=1))
    s1.stats.macro_runs = 5
    assert s2.stats.macro_runs == 0


# ---------------------------------------------------------------------------
# build_auth_session_from_state — project loader.
# ---------------------------------------------------------------------------

class _FakeProject:
    def __init__(self, state: dict[str, str]):
        self._state = dict(state)

    def get_state(self, key: str, default: str = "") -> str:
        return self._state.get(key, default)


def test_build_loads_macro_from_project_state():
    macro = _login_macro()
    proj = _FakeProject({"macro:7": macro.to_json()})
    sess = build_auth_session_from_state(
        proj, AuthSessionConfig(macro_id=7),
    )
    assert sess.macro.name == "login"
    assert len(sess.macro.steps) == 1


def test_build_raises_when_macro_absent():
    with pytest.raises(LookupError):
        build_auth_session_from_state(
            _FakeProject({}), AuthSessionConfig(macro_id=99),
        )


def test_build_raises_on_unparseable_macro():
    proj = _FakeProject({"macro:1": "not-valid-json{{"})
    with pytest.raises(LookupError):
        build_auth_session_from_state(proj, AuthSessionConfig(macro_id=1))


def test_build_raises_when_project_lacks_get_state():
    class _Bad:
        pass
    with pytest.raises(LookupError):
        build_auth_session_from_state(
            _Bad(), AuthSessionConfig(macro_id=1),
        )


# ---------------------------------------------------------------------------
# Misc helpers.
# ---------------------------------------------------------------------------

def test_origin_root_strips_path_and_query():
    assert _origin_root("https://app.test:8443/a/b?x=1") == (
        "https://app.test:8443/"
    )


def test_origin_root_returns_none_for_garbage():
    assert _origin_root("not a url") is None


def test_name_in_form_detects_urlencoded_key():
    assert _name_in_json_or_form("a=1&csrf_token=xyz&b=2", "csrf_token")


def test_name_in_json_detects_quoted_key():
    assert _name_in_json_or_form('{"csrf_token":"x"}', "csrf_token")


def test_name_in_form_rejects_unrelated():
    assert not _name_in_json_or_form("a=1&b=2", "csrf_token")


# ---------------------------------------------------------------------------
# Integration with ActiveScanner.run_on_project.
# ---------------------------------------------------------------------------

class _Row:
    def __init__(self, host: str, url: str):
        self.id = 1
        self.host = host
        self.url = url
        self.method = "GET"
        self.status = 200
        self.req_blob = (
            b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        )
        self.resp_blob = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


class _ProjForScan:
    def __init__(self, rows):
        self._rows = list(rows)

    def list_history(self, *, limit, host=None):
        del limit, host
        return list(self._rows)

    def list_scope(self):
        return []

    def record_rule_run(self, **_kw):
        pass


class _ProbeCheck:
    """One-shot check that fires a single GET via the sender."""

    from reqlore.scanner.rules import RuleMeta as _RM

    meta = _RM(
        id="active:probe",
        intensity="light",
        title="probe",
        default_severity="info",
    )
    name = "probe"
    description = "probe"

    def run(self, ctx, send, opts=None):  # noqa: ARG002
        send(Request("GET", "https://app.test/data", [], b""))
        return iter([])


def test_scanner_primes_auth_session_and_mirrors_stats():
    sent_with_cookie: list[bool] = []

    def sender(req: Request) -> Response:
        if req.url == "https://app.test/login":
            return _resp(200, headers=[("Set-Cookie", "SID=ok")])
        cookie = next(
            (v for k, v in req.headers if k.lower() == "cookie"), "",
        )
        sent_with_cookie.append("SID=ok" in cookie)
        return _resp(200)

    proj = _ProjForScan([_Row("app.test", "https://app.test/data")])
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1, session_cookie_names=("SID",),
        ),
    )
    scanner = ActiveScanner(checks=[_ProbeCheck()], sender=sender)
    opts = ActiveOptions(
        enabled_checks=["probe"],
        auth_session=sess,
    )
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert sess.primed is True
    assert sent_with_cookie == [True]
    assert result.auth_macro_runs == 1
    assert result.session_recoveries == 0


def test_scanner_revalidates_and_mirrors_recovery_count():
    state = {"calls": 0}

    def sender(req: Request) -> Response:
        if req.url == "https://app.test/login":
            return _resp(200, headers=[("Set-Cookie", "SID=" + str(id(req)))])
        if req.url == "https://app.test/whoami":
            # Validity probe: always reports session dead.
            return _resp(401)
        state["calls"] += 1
        return _resp(200)

    rows = [_Row("app.test", "https://app.test/data") for _ in range(3)]
    proj = _ProjForScan(rows)
    sess = AuthSession(
        _login_macro(),
        AuthSessionConfig(
            macro_id=1,
            session_cookie_names=("SID",),
            validity_probe_url="https://app.test/whoami",
            revalidate_every_n_probes=1,
        ),
    )
    scanner = ActiveScanner(checks=[_ProbeCheck()], sender=sender)
    opts = ActiveOptions(
        enabled_checks=["probe"],
        auth_session=sess,
    )
    result = scanner.run_on_project(proj, options=opts, limit=10)
    # 1 prime + 3 recoveries (one per row's probe).
    assert result.session_recoveries == 3
    assert result.validity_probes == 3
    assert result.auth_macro_runs == 4


def test_scanner_runs_normally_when_no_auth_session():
    proj = _ProjForScan([_Row("app.test", "https://app.test/data")])
    scanner = ActiveScanner(
        checks=[_ProbeCheck()],
        sender=lambda r: _resp(200),
    )
    opts = ActiveOptions(enabled_checks=["probe"])
    result = scanner.run_on_project(proj, options=opts, limit=10)
    assert result.auth_macro_runs == 0
    assert result.session_recoveries == 0
    assert result.rows_scanned == 1


# ---------------------------------------------------------------------------
# Stats dataclass.
# ---------------------------------------------------------------------------

def test_auth_session_stats_defaults_are_zero():
    s = AuthSessionStats()
    assert s.macro_runs == 0
    assert s.session_recoveries == 0
    assert s.csrf_token_refetches == 0
    assert s.csrf_token_swaps == 0
