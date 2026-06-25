"""Session-handling macros.

A macro is an ordered list of HTTP steps replayed in sequence. After each
step the macro may capture values from the response (by regex or by header
name) into a variable dictionary. Subsequent steps may reference those
variables in their URL, headers, or body using ``{{var}}`` placeholders.

Use cases:
    * login + extract CSRF token → use the token in later requests
    * fetch a tenant id → fan out attacks against tenant-scoped endpoints
    * keep a session warm by replaying the login before each Intruder attack

The macro definition is plain JSON, stored under ``project_state`` key
``macro:<id>``. The runner uses the httpx engine and respects per-step
timeouts and a global ``base_headers`` map.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .engines import Request, Response
from .engines import httpx_engine


# Recognised values for ``MacroStep.step_type``. The empty string is the
# default (untyped step). The other values let auth-flow active checks
# locate specific stages of the macro without name-guessing:
#   - ``"login"``     -- the step that submits credentials and issues
#                        the first session cookie. Required by the
#                        ``SessionFixationActiveCheck``.
#   - ``"mfa"``       -- the step that submits a second-factor code.
#                        Required by the ``MFABypassCheck``.
# Plugin authors may use additional values; the dataclass does not
# enforce membership in this set so future checks can extend it.
KNOWN_STEP_TYPES: tuple[str, ...] = ("", "login", "mfa")


@dataclass
class MacroStep:
    name: str
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    capture: dict[str, dict] = field(default_factory=dict)
    timeout_s: float = 10.0
    follow_redirects: bool = True
    # Phase 26 -- machine-readable tag describing the role of this step
    # in the auth flow. See ``KNOWN_STEP_TYPES`` above. Defaults to the
    # empty string so existing macros and tests round-trip unchanged.
    step_type: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "MacroStep":
        return cls(
            name=d.get("name", "step"),
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            headers=dict(d.get("headers") or {}),
            body=d.get("body", "") or "",
            capture=dict(d.get("capture") or {}),
            timeout_s=float(d.get("timeout_s", 10.0)),
            follow_redirects=bool(d.get("follow_redirects", True)),
            step_type=str(d.get("step_type", "") or ""),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name, "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body, "capture": self.capture,
            "timeout_s": self.timeout_s, "follow_redirects": self.follow_redirects,
            "step_type": self.step_type,
        }


@dataclass
class Macro:
    name: str = ""
    base_headers: dict[str, str] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)
    steps: list[MacroStep] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({
            "name": self.name, "base_headers": self.base_headers,
            "variables": self.variables,
            "steps": [s.to_dict() for s in self.steps],
        }, indent=2)

    @classmethod
    def from_json(cls, blob: str) -> "Macro":
        if not blob:
            return cls()
        d = json.loads(blob)
        return cls(
            name=d.get("name", ""),
            base_headers=dict(d.get("base_headers") or {}),
            variables=dict(d.get("variables") or {}),
            steps=[MacroStep.from_dict(s) for s in d.get("steps") or []],
        )


@dataclass
class StepResult:
    step: str
    status: int
    duration_ms: int
    captured: dict[str, str]
    error: str = ""
    request_url: str = ""


@dataclass
class MacroRun:
    variables: dict[str, str] = field(default_factory=dict)
    steps: list[StepResult] = field(default_factory=list)
    elapsed_ms: int = 0


_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _substitute(text: str, variables: dict[str, str]) -> str:
    def repl(m):
        return variables.get(m.group(1), m.group(0))
    return _VAR_RE.sub(repl, text or "")


def _capture(response: Response, capture: dict[str, dict]) -> dict[str, str]:
    """Pull values out of a response per the capture spec.

    Capture spec for each variable is one of::

        {"source": "header", "name": "Set-Cookie"}
        {"source": "regex",  "where": "body" | "header:X-Something",
         "pattern": "csrf_token=([^;]+)"}
        {"source": "json",   "path": "data.token"}    # dotted path

    Missing values are stored as the empty string, never None.
    """
    out: dict[str, str] = {}
    for var, spec in (capture or {}).items():
        src = (spec or {}).get("source", "")
        if src == "header":
            name = spec.get("name", "")
            value = response.header(name) or ""
        elif src == "regex":
            pattern = spec.get("pattern", "")
            where = spec.get("where", "body")
            if where.startswith("header:"):
                hname = where.split(":", 1)[1]
                hay = response.header(hname) or ""
            else:
                hay = response.body.decode("utf-8", errors="replace")
            # H-4: bounded-time regex against attacker-influenced body.
            from . import _safe_regex
            m = _safe_regex.safe_search(pattern, hay) if pattern else None
            value = m.group(1) if (m and m.groups()) else (m.group(0) if m else "")
        elif src == "json":
            path = spec.get("path", "")
            try:
                obj = json.loads(response.body or b"null")
            except (ValueError, json.JSONDecodeError):
                obj = None
            for part in path.split(".") if path else []:
                if isinstance(obj, dict):
                    obj = obj.get(part)
                elif isinstance(obj, list):
                    try:
                        obj = obj[int(part)]
                    except (ValueError, IndexError):
                        obj = None
                else:
                    obj = None
            value = "" if obj is None else str(obj)
        else:
            value = ""
        out[var] = value
    return out


def run(macro: Macro, *, sender=None) -> MacroRun:
    """Execute the macro, returning a :class:`MacroRun` summary.

    ``sender`` is an optional callable(req)->Response used by tests; the
    default uses the httpx engine.
    """
    variables = dict(macro.variables)
    run = MacroRun(variables=variables)
    t0 = time.monotonic()
    for step in macro.steps:
        url = _substitute(step.url, variables)
        body = _substitute(step.body, variables).encode("utf-8")
        headers = []
        for k, v in {**macro.base_headers, **step.headers}.items():
            headers.append((k, _substitute(v, variables)))
        req = Request(method=step.method, url=url, headers=headers, body=body)
        ts = time.monotonic()
        if sender is not None:
            resp = sender(req)
        else:
            resp = httpx_engine.send(
                req, timeout=step.timeout_s,
                follow_redirects=step.follow_redirects,
            )
        dur = int((time.monotonic() - ts) * 1000)
        if resp.error:
            run.steps.append(StepResult(
                step=step.name, status=resp.status, duration_ms=dur,
                captured={}, error=resp.error, request_url=url,
            ))
            break
        captured = _capture(resp, step.capture)
        variables.update(captured)
        run.steps.append(StepResult(
            step=step.name, status=resp.status, duration_ms=dur,
            captured=captured, request_url=url,
        ))
    run.elapsed_ms = int((time.monotonic() - t0) * 1000)
    run.variables = variables
    return run
