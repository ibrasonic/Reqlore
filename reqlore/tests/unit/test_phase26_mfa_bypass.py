"""Phase 26 -- MFA-bypass active check.

Closes the MFA-bypass half of ENHANCEMENT_PLAN item 2.4. The check
re-runs the configured auth macro with every step tagged
``step_type="mfa"`` removed and observes whether the verification
step still returns 2xx -- which proves the server hands out a full
authenticated session after just the password step.
"""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.macros import Macro, MacroStep
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    ActiveContext,
    MFABypassCheck,
    _macro_from_opts,
    _macro_step_adapter,
    _raw_sender_from,
)


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


def _macro_with_mfa() -> Macro:
    return Macro(
        name="auth", variables={"u": "alice", "p": "hunter2"},
        steps=[
            MacroStep(name="login", method="POST",
                      url="https://x.test/login",
                      headers={"Content-Type":
                                 "application/x-www-form-urlencoded"},
                      body="username={{u}}&password={{p}}",
                      capture={"sess": {"source": "header",
                                          "name": "Set-Cookie"}},
                      step_type="login"),
            MacroStep(name="otp", method="POST",
                      url="https://x.test/otp",
                      headers={"Cookie": "session={{sess}}",
                                "Content-Type":
                                 "application/x-www-form-urlencoded"},
                      body="code=123456",
                      step_type="mfa"),
            MacroStep(name="verify", method="GET",
                      url="https://x.test/me",
                      headers={"Cookie": "session={{sess}}"}),
        ],
    )


def _macro_without_mfa() -> Macro:
    m = _macro_with_mfa()
    m.steps = [s for s in m.steps if s.step_type != "mfa"]
    return m


def _macro_ending_in_mfa() -> Macro:
    # No verification step after MFA -- the check cannot fire because
    # there is nothing to inspect for the bypass verdict.
    m = _macro_with_mfa()
    m.steps = [s for s in m.steps if s.name != "verify"]
    return m


class _FakeAuth:
    """Minimal AuthSession stand-in for the scanner's send wrapper."""

    def __init__(self, macro: Macro):
        self.macro = macro

    def apply_to_request(self, req, sender=None):
        return req

    def notify_response(self, req, resp):
        pass

    def maybe_revalidate(self, sender=None):
        pass


def _bypass_responder():
    """A server that grants /me regardless of MFA -- bypass scenario."""

    def responder(req: Request) -> Response:
        url = req.url
        if "/login" in url:
            return Response(status=200,
                            headers=[("Set-Cookie",
                                        "session=server_real_xyz; Path=/")],
                            body=b"login ok", engine="fake")
        if "/otp" in url:
            return Response(status=200, headers=[],
                            body=b"otp accepted", engine="fake")
        if "/me" in url:
            return Response(status=200,
                            headers=[("Content-Type", "application/json")],
                            body=b'{"user":"alice"}', engine="fake")
        return Response(status=404, headers=[], body=b"", engine="fake")

    return responder


def _safe_responder():
    """A server that refuses /me without the OTP step having run.

    The login step issues a *pre-MFA* cookie; only after /otp does the
    server promote it to a full session that /me will accept.
    """
    state = {"otp_done": False, "session": ""}

    def responder(req: Request) -> Response:
        url = req.url
        if "/login" in url:
            state["session"] = "pre_mfa_token"
            state["otp_done"] = False
            return Response(status=200,
                            headers=[("Set-Cookie",
                                        "session=pre_mfa_token; Path=/")],
                            body=b"login ok", engine="fake")
        if "/otp" in url:
            state["otp_done"] = True
            state["session"] = "full_session"
            return Response(status=200,
                            headers=[("Set-Cookie",
                                        "session=full_session; Path=/")],
                            body=b"otp ok", engine="fake")
        if "/me" in url:
            if state["otp_done"]:
                return Response(status=200, headers=[],
                                body=b'{"user":"alice"}', engine="fake")
            return Response(status=403, headers=[],
                            body=b"mfa required", engine="fake")
        return Response(status=404, headers=[], body=b"", engine="fake")

    return responder


def _run_check(responder, *, auth_session) -> list:
    scanner = ActiveScanner(checks=[MFABypassCheck()], sender=responder)
    return scanner.run_on_row(
        _row(),
        options=ActiveOptions(
            enabled_checks=["mfa-bypass"],
            auth_session=auth_session,
        ),
    )


# ---- positive paths --------------------------------------------------------


def test_mfa_bypass_fires_when_verify_succeeds_without_mfa():
    auth = _FakeAuth(_macro_with_mfa())
    findings = _run_check(_bypass_responder(), auth_session=auth)
    titles = [f.title for f in findings]
    assert any("MFA bypass" in t for t in titles), titles
    bypass = next(f for f in findings if "MFA bypass" in f.title)
    assert bypass.severity == "high"
    assert bypass.confidence == "firm"
    assert bypass.cwe == "CWE-308"
    assert "verify" in bypass.evidence


def test_mfa_bypass_evidence_mentions_step_and_status():
    auth = _FakeAuth(_macro_with_mfa())
    findings = _run_check(_bypass_responder(), auth_session=auth)
    bypass = next(f for f in findings if "MFA bypass" in f.title)
    assert "200" in bypass.evidence
    assert "verify" in bypass.description


# ---- negative paths --------------------------------------------------------


def test_mfa_bypass_silent_on_safe_server():
    auth = _FakeAuth(_macro_with_mfa())
    findings = _run_check(_safe_responder(), auth_session=auth)
    assert not any("MFA bypass" in f.title for f in findings)


def test_mfa_bypass_silent_when_no_mfa_step():
    auth = _FakeAuth(_macro_without_mfa())
    findings = _run_check(_bypass_responder(), auth_session=auth)
    assert not any("MFA bypass" in f.title for f in findings)


def test_mfa_bypass_silent_when_macro_ends_in_mfa():
    # No verification step -> nothing to inspect, cannot fire.
    auth = _FakeAuth(_macro_ending_in_mfa())
    findings = _run_check(_bypass_responder(), auth_session=auth)
    assert not any("MFA bypass" in f.title for f in findings)


def test_mfa_bypass_silent_when_no_auth_session():
    scanner = ActiveScanner(checks=[MFABypassCheck()],
                              sender=_bypass_responder())
    findings = scanner.run_on_row(
        _row(),
        options=ActiveOptions(enabled_checks=["mfa-bypass"]),
    )
    assert findings == []


def test_mfa_bypass_silent_when_verify_returns_403():
    # Even with MFA stripped, the server rejects /me -- no bypass.
    auth = _FakeAuth(_macro_with_mfa())
    findings = _run_check(_safe_responder(), auth_session=auth)
    assert not any("MFA bypass" in f.title for f in findings)


# ---- one-shot semantics ----------------------------------------------------


def test_mfa_bypass_does_not_fire_twice_for_same_auth_session():
    # Once an auth_session has been checked, a fresh row-level scan
    # using the SAME auth_session should not re-fire.
    auth = _FakeAuth(_macro_with_mfa())
    f1 = _run_check(_bypass_responder(), auth_session=auth)
    assert any("MFA bypass" in f.title for f in f1)
    f2 = _run_check(_bypass_responder(), auth_session=auth)
    assert not any("MFA bypass" in f.title for f in f2)


def test_mfa_bypass_fires_for_fresh_auth_session_instance():
    # A new AuthSession is a separate scan run -- the sentinel does
    # not bleed across instances.
    f1 = _run_check(_bypass_responder(),
                    auth_session=_FakeAuth(_macro_with_mfa()))
    f2 = _run_check(_bypass_responder(),
                    auth_session=_FakeAuth(_macro_with_mfa()))
    assert any("MFA bypass" in f.title for f in f1)
    assert any("MFA bypass" in f.title for f in f2)


# ---- helper coverage -------------------------------------------------------


def test_macro_from_opts_returns_none_without_auth_session():
    assert _macro_from_opts(ActiveOptions()) is None


def test_macro_from_opts_returns_none_when_macro_has_no_steps():
    auth = _FakeAuth(Macro(name="empty"))
    assert _macro_from_opts(
        ActiveOptions(auth_session=auth)
    ) is None


def test_macro_from_opts_returns_macro_when_steps_present():
    auth = _FakeAuth(_macro_with_mfa())
    macro = _macro_from_opts(ActiveOptions(auth_session=auth))
    assert macro is not None
    assert macro.steps[0].step_type == "login"


def test_raw_sender_from_returns_send_when_no_raw_attr():
    def bare(req):
        return None
    assert _raw_sender_from(bare) is bare


def test_macro_step_adapter_unwraps_probe_result():
    class _Probe:
        def __init__(self, resp):
            self.response = resp
    resp = Response(status=204, headers=[], body=b"", engine="fake")

    def fake_send(req):
        return _Probe(resp)
    adapter = _macro_step_adapter(fake_send)
    out = adapter(Request(method="GET", url="https://x.test/",
                            headers=[], body=b""))
    assert out is resp


def test_macro_step_adapter_passes_through_bare_response():
    resp = Response(status=200, headers=[], body=b"ok", engine="fake")

    def fake_send(req):
        return resp
    adapter = _macro_step_adapter(fake_send)
    assert adapter(Request(method="GET", url="https://x.test/",
                            headers=[], body=b"")) is resp


def test_macro_step_adapter_handles_sender_exception():
    def broken(req):
        raise RuntimeError("boom")
    adapter = _macro_step_adapter(broken)
    out = adapter(Request(method="GET", url="https://x.test/",
                            headers=[], body=b""))
    assert out.status == 0
    assert out.error == "send-failed"


def test_check_meta_intensity_is_intrusive():
    assert MFABypassCheck.meta.intensity == "intrusive"
    assert MFABypassCheck.meta.id == "active:mfa-bypass"


def test_active_context_round_trips_row():
    # Sanity check that the shared row builder produces a valid ctx
    # (paranoia against silent breakage of the test scaffold).
    ctx = ActiveContext.from_row(_row())
    assert ctx.host == "x.test"
    assert ctx.full_url == "https://x.test/me"
