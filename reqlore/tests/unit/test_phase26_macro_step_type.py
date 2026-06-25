"""Phase 26 -- ``MacroStep.step_type`` schema slice.

Adds a machine-readable tag to each step so the auth-flow active
checks (``MFABypassCheck``, ``SessionFixationActiveCheck``) can
locate specific stages without name-guessing. The field is purely
additive and defaults to the empty string so legacy macros load
unchanged.
"""
from __future__ import annotations

import json

from reqlore.macros import KNOWN_STEP_TYPES, Macro, MacroStep


def test_step_type_defaults_to_empty():
    step = MacroStep(name="x", method="GET", url="https://x.test/")
    assert step.step_type == ""


def test_step_type_roundtrips_through_to_dict_from_dict():
    step = MacroStep(name="login", method="POST",
                     url="https://x.test/login",
                     step_type="login")
    d = step.to_dict()
    assert d["step_type"] == "login"
    rebuilt = MacroStep.from_dict(d)
    assert rebuilt.step_type == "login"


def test_legacy_macro_without_step_type_loads_cleanly():
    # Macros stored before Phase 26 won't have ``step_type`` in their
    # serialised form. The dataclass must accept that and default to "".
    legacy = {
        "name": "legacy",
        "method": "GET",
        "url": "https://x.test/",
        "headers": {"Accept": "*/*"},
        "body": "",
        "capture": {},
        "timeout_s": 10.0,
        "follow_redirects": True,
    }
    step = MacroStep.from_dict(legacy)
    assert step.step_type == ""


def test_macro_json_roundtrip_preserves_step_type():
    macro = Macro(
        name="auth",
        variables={"u": "alice", "p": "hunter2"},
        steps=[
            MacroStep(name="login", method="POST",
                      url="https://x.test/login",
                      body="username={{u}}&password={{p}}",
                      capture={"sess": {"source": "header",
                                          "name": "Set-Cookie"}},
                      step_type="login"),
            MacroStep(name="otp", method="POST",
                      url="https://x.test/otp",
                      body="code=123456",
                      headers={"Cookie": "session={{sess}}"},
                      step_type="mfa"),
            MacroStep(name="verify", method="GET",
                      url="https://x.test/me",
                      headers={"Cookie": "session={{sess}}"}),
        ],
    )
    blob = macro.to_json()
    parsed = json.loads(blob)
    assert parsed["steps"][0]["step_type"] == "login"
    assert parsed["steps"][1]["step_type"] == "mfa"
    assert parsed["steps"][2]["step_type"] == ""

    rebuilt = Macro.from_json(blob)
    assert [s.step_type for s in rebuilt.steps] == ["login", "mfa", ""]


def test_step_type_from_dict_coerces_none_to_empty():
    step = MacroStep.from_dict({
        "name": "x", "method": "GET", "url": "https://x.test/",
        "step_type": None,
    })
    assert step.step_type == ""


def test_known_step_types_contains_login_and_mfa():
    assert "login" in KNOWN_STEP_TYPES
    assert "mfa" in KNOWN_STEP_TYPES
    assert "" in KNOWN_STEP_TYPES
