"""Phase 26 -- session-fixation active check.

Closes the session-fixation half of ENHANCEMENT_PLAN item 2.4. The
check re-runs the configured auth macro with an attacker-chosen
value pre-set on the captured session-cookie name(s) and inspects
whether the server rotates the cookie on successful login.
"""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.macros import Macro, MacroStep
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import SessionFixationActiveCheck

# ---- shared fixtures -------------------------------------------------------


@dataclass
class _Row:
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _req(method: str, url: str, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


def _row():
    return _Row(
        id=1, host="x.test", url="https://x.test/me",
        method="GET", status=200,
        req_blob=_req("GET", "https://x.test/me"),
        resp_blob=_resp(200, [("Content-Type", "application/json")],
                        b'{"user":"alice"}'),
    )


def _macro_with_login(*, with_existing_cookie: bool = False) -> Macro:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if with_existing_cookie:
        headers["Cookie"] = "prefs=dark"
    return Macro(
        name="auth", variables={"u": "alice", "p": "hunter2"},
        steps=[
            MacroStep(name="login", method="POST",
                      url="https://x.test/login",
                      headers=headers,
                      body="username={{u}}&password={{p}}",
                      capture={"sess": {"source": "header",
                                          "name": "Set-Cookie"}},
                      step_type="login"),
            MacroStep(name="verify", method="GET",
                      url="https://x.test/me",
                      headers={"Cookie": "session={{sess}}"}),
        ],
    )


def _macro_without_login_type() -> Macro:
    m = _macro_with_login()
    for s in m.steps:
        s.step_type = ""
    return m


def _macro_login_without_set_cookie_capture() -> Macro:
    m = _macro_with_login()
    m.steps[0].capture = {"token": {"source": "header",
                                       "name": "X-Csrf-Token"}}
    return m


class _FakeAuth:
    def __init__(self, macro: Macro):
        self.macro = macro

    def apply_to_request(self, req, sender=None):
        return req

    def notify_response(self, req, resp):
        pass

    def maybe_revalidate(self, sender=None):
        pass


# Each responder factory captures the most recent Cookie header sent
# to /login so tests can assert that the fixated value was injected.

def _echo_responder():
    """Server that echoes back whatever Cookie value was sent."""
    seen = {"login_cookie": None}

    def responder(req: Request) -> Response:
        if "/login" in req.url:
            cookie = ""
            for k, v in req.headers:
                if k.lower() == "cookie":
                    cookie = v
                    break
            seen["login_cookie"] = cookie
            # Echo the supplied session value back verbatim --
            # the textbook session-fixation defect.
            return Response(
                status=200,
                headers=[("Set-Cookie",
                            "session=reqlore_fixated_session_zzz; Path=/")],
                body=b"ok", engine="fake",
            )
        return Response(status=404, headers=[], body=b"", engine="fake")

    responder.seen = seen  # type: ignore[attr-defined]
    return responder


def _silent_responder():
    """Server that returns no Set-Cookie on login -- the attacker's
    pre-set value remains the active session."""

    def responder(req: Request) -> Response:
        if "/login" in req.url:
            return Response(status=200, headers=[],
                            body=b"ok", engine="fake")
        return Response(status=404, headers=[], body=b"", engine="fake")

    return responder


def _safe_responder():
    """Server that issues a freshly generated session on login --
    the safe, expected behaviour."""

    def responder(req: Request) -> Response:
        if "/login" in req.url:
            return Response(
                status=200,
                headers=[("Set-Cookie",
                            "session=server_generated_fresh_abc; Path=/")],
                body=b"ok", engine="fake",
            )
        return Response(status=404, headers=[], body=b"", engine="fake")

    return responder


def _reject_responder():
    """Server that rejects the pre-set cookie outright."""

    def responder(req: Request) -> Response:
        if "/login" in req.url:
            return Response(status=403, headers=[],
                            body=b"go away", engine="fake")
        return Response(status=404, headers=[], body=b"", engine="fake")

    return responder


def _run_check(responder, *, auth_session) -> list:
    scanner = ActiveScanner(checks=[SessionFixationActiveCheck()],
                              sender=responder)
    return scanner.run_on_row(
        _row(),
        options=ActiveOptions(
            enabled_checks=["session-fixation"],
            auth_session=auth_session,
        ),
    )


# ---- positive paths --------------------------------------------------------


def test_session_fixation_fires_when_server_echoes_value():
    auth = _FakeAuth(_macro_with_login())
    findings = _run_check(_echo_responder(), auth_session=auth)
    assert any("Session fixation" in f.title for f in findings)
    finding = next(f for f in findings if "Session fixation" in f.title)
    assert finding.severity == "high"
    assert finding.cwe == "CWE-384"
    assert finding.confidence == "firm"
    assert "echoed" in finding.evidence


def test_session_fixation_fires_when_server_returns_no_set_cookie():
    auth = _FakeAuth(_macro_with_login())
    findings = _run_check(_silent_responder(), auth_session=auth)
    assert any("Session fixation" in f.title for f in findings)
    finding = next(f for f in findings if "Session fixation" in f.title)
    assert "not-rotated" in finding.evidence


def test_session_fixation_payload_mentions_injected_cookie():
    auth = _FakeAuth(_macro_with_login())
    findings = _run_check(_echo_responder(), auth_session=auth)
    finding = next(f for f in findings if "Session fixation" in f.title)
    assert "reqlore_fixated_session_zzz" in finding.payload
    assert "sess" in finding.payload


def test_session_fixation_preserves_existing_cookie_header():
    responder = _echo_responder()
    auth = _FakeAuth(_macro_with_login(with_existing_cookie=True))
    _run_check(responder, auth_session=auth)
    cookie = responder.seen["login_cookie"]
    assert cookie is not None
    assert "prefs=dark" in cookie
    assert "sess=reqlore_fixated_session_zzz" in cookie


def test_session_fixation_injects_when_no_prior_cookie_header():
    responder = _echo_responder()
    auth = _FakeAuth(_macro_with_login(with_existing_cookie=False))
    _run_check(responder, auth_session=auth)
    cookie = responder.seen["login_cookie"]
    assert cookie == "sess=reqlore_fixated_session_zzz"


# ---- negative paths --------------------------------------------------------


def test_session_fixation_silent_on_rotating_server():
    auth = _FakeAuth(_macro_with_login())
    findings = _run_check(_safe_responder(), auth_session=auth)
    assert not any("Session fixation" in f.title for f in findings)


def test_session_fixation_silent_when_server_rejects_login():
    auth = _FakeAuth(_macro_with_login())
    findings = _run_check(_reject_responder(), auth_session=auth)
    assert not any("Session fixation" in f.title for f in findings)


def test_session_fixation_silent_when_no_login_step():
    auth = _FakeAuth(_macro_without_login_type())
    findings = _run_check(_echo_responder(), auth_session=auth)
    assert not any("Session fixation" in f.title for f in findings)


def test_session_fixation_silent_when_login_has_no_set_cookie_capture():
    auth = _FakeAuth(_macro_login_without_set_cookie_capture())
    findings = _run_check(_echo_responder(), auth_session=auth)
    assert not any("Session fixation" in f.title for f in findings)


def test_session_fixation_silent_when_no_auth_session():
    scanner = ActiveScanner(checks=[SessionFixationActiveCheck()],
                              sender=_echo_responder())
    findings = scanner.run_on_row(
        _row(),
        options=ActiveOptions(enabled_checks=["session-fixation"]),
    )
    assert findings == []


# ---- one-shot semantics ----------------------------------------------------


def test_session_fixation_does_not_fire_twice_for_same_auth_session():
    auth = _FakeAuth(_macro_with_login())
    f1 = _run_check(_echo_responder(), auth_session=auth)
    assert any("Session fixation" in f.title for f in f1)
    f2 = _run_check(_echo_responder(), auth_session=auth)
    assert not any("Session fixation" in f.title for f in f2)


def test_session_fixation_fires_for_fresh_auth_session_instance():
    f1 = _run_check(_echo_responder(),
                    auth_session=_FakeAuth(_macro_with_login()))
    f2 = _run_check(_echo_responder(),
                    auth_session=_FakeAuth(_macro_with_login()))
    assert any("Session fixation" in f.title for f in f1)
    assert any("Session fixation" in f.title for f in f2)


# ---- meta sanity -----------------------------------------------------------


def test_check_meta_intensity_is_intrusive():
    assert SessionFixationActiveCheck.meta.intensity == "intrusive"
    assert SessionFixationActiveCheck.meta.id == "active:session-fixation"


def test_check_meta_has_cwe_384():
    assert SessionFixationActiveCheck.meta.cwe == "CWE-384"


def test_fixation_value_is_distinctive_substring():
    # Sanity: the fixation value must not be a plausible server token.
    assert "reqlore" in SessionFixationActiveCheck.FIXATION_VALUE
    assert len(SessionFixationActiveCheck.FIXATION_VALUE) >= 16
