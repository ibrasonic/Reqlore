"""Phase 19 — auth-flow timing + CSRF active checks.

Covers item 2.4 (account-enumeration timing sub-check) and item 3.1
(CSRF-token validation probe) from
``docs/internal/ENHANCEMENT_PLAN.md``.

Test strategy mirrors ``test_scanner_active.py``: a fake ``Row``
dataclass + a closure-based responder. Timing tests use a list-driven
``time.monotonic`` patch so we never actually ``time.sleep`` and the
suite stays fast.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    AccountEnumTimingCheck,
    CSRFTokenValidationCheck,
    _CSRF_HEADER_NAMES,
    _CSRF_PARAM_NAMES,
    _find_csrf_token,
    _find_username_field,
    _is_timing_anomaly,
    _mad,
    _median,
)
from reqlore.scanner.active import ActiveContext


# ---- shared row builders ---------------------------------------------------


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


def _row(url="https://x.test/", method="POST", status=200,
         req_headers=None, req_body=b"",
         resp_headers=None, resp_body=b"OK") -> _Row:
    return _Row(
        id=1, host="x.test", url=url, method=method, status=status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


# ---- median / MAD math -----------------------------------------------------


def test_median_odd_and_even_lengths():
    assert _median([]) == 0
    assert _median([5]) == 5
    assert _median([1, 2, 3]) == 2
    assert _median([1, 2, 3, 4]) == 2  # (2+3)//2 == 2 (integer median)


def test_mad_is_median_of_absolute_deviations():
    # values 1,2,3,4,5 around centre 3 -> deviations 2,1,0,1,2 -> median 1
    assert _mad([1, 2, 3, 4, 5], 3) == 1
    # single-value sample collapses MAD to zero
    assert _mad([7, 7, 7, 7], 7) == 0
    assert _mad([], 99) == 0


def test_timing_anomaly_respects_floor_and_mad():
    # Baseline jitter 100-110ms, probes 105-115ms: delta ~5ms < 50ms floor.
    base = [100, 102, 104, 108, 110, 105, 103]
    probe = [105, 108, 110, 112, 115, 109, 110]
    assert not _is_timing_anomaly(base, probe)
    # Now probes consistently +500ms: clear anomaly.
    probe_slow = [605, 608, 610, 612, 615, 609, 610]
    assert _is_timing_anomaly(base, probe_slow)
    # Tiny sample sizes refuse to fire.
    assert not _is_timing_anomaly([10], [500])


# ---- helper coverage -------------------------------------------------------


def test_find_username_field_picks_form_then_query():
    body = b"username=alice&password=hunter2"
    row = _row(method="POST",
               req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
               req_body=body)
    ctx = ActiveContext.from_row(row)
    assert _find_username_field(ctx) == ("form", "username", "alice")

    row_q = _row(url="https://x.test/login?email=bob@x.test&password=hunter2",
                 method="POST",
                 req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
                 req_body=b"")
    ctx_q = ActiveContext.from_row(row_q)
    assert _find_username_field(ctx_q) == ("query", "email", "bob@x.test")


def test_find_username_field_returns_none_when_absent():
    row = _row(method="POST",
               req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
               req_body=b"foo=bar&baz=qux")
    ctx = ActiveContext.from_row(row)
    assert _find_username_field(ctx) is None


def test_find_csrf_token_form_query_header_priority():
    body = b"_token=abc123&data=x"
    row = _row(method="POST",
               req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
               req_body=body)
    ctx = ActiveContext.from_row(row)
    assert _find_csrf_token(ctx) == ("form", "_token", "abc123")

    row_h = _row(method="POST",
                 req_headers=[("X-CSRF-Token", "deadbeef")],
                 req_body=b"")
    ctx_h = ActiveContext.from_row(row_h)
    loc, k, v = _find_csrf_token(ctx_h)
    assert loc == "header" and v == "deadbeef" and k.lower() == "x-csrf-token"


def test_find_csrf_token_skips_cookie_only_tokens():
    # Cookie-only CSRF is double-submit; not what we probe.
    row = _row(method="POST",
               req_headers=[("Cookie", "csrf_token=abc; sid=xyz")],
               req_body=b"")
    ctx = ActiveContext.from_row(row)
    assert _find_csrf_token(ctx) is None


def test_csrf_param_and_header_names_constants_lowercase():
    # Guard against accidental case drift; lookups are case-insensitive
    # but the source-of-truth set must stay lowercase.
    assert all(n == n.lower() for n in _CSRF_PARAM_NAMES)
    assert all(n == n.lower() for n in _CSRF_HEADER_NAMES)


# ---- AccountEnumTimingCheck ------------------------------------------------


def _timing_responder(times_by_field_value: dict[str, list[int]]):
    """Build a responder where elapsed_ms is driven by `time.monotonic`.

    The scanner's `_send` wrapper measures `time.monotonic` deltas, so
    we patch that. We return a fresh list per call and pop pre-recorded
    samples in order. The list is keyed by the value of the `username`
    form field so the same responder can yield distinct timings for
    exists vs absent probes.
    """
    def responder(req: Request) -> Response:
        return Response(status=200, headers=[("Content-Type", "text/html")],
                        body=b"login form", engine="fake")
    return responder


def _install_monotonic_queue(monkeypatch, values):
    """Patch time.monotonic in reqlore.scanner.active to yield each value
    on successive calls."""
    import reqlore.scanner.active as active_mod
    it = iter(values)
    last = [0.0]

    def fake_monotonic():
        try:
            v = next(it)
            last[0] = v
            return v
        except StopIteration:
            return last[0]

    monkeypatch.setattr(active_mod.time, "monotonic", fake_monotonic)


def test_account_enum_timing_fires_when_absent_slower(monkeypatch):
    # Plan: 7 exists probes (interleaved with 7 absent probes).
    # Each `send()` measures two monotonic calls: t1 and t1+elapsed.
    # We'll feed pairs: exists -> (0, 0.005) → 5ms; absent -> (1, 1.6) → 600ms.
    timeline: list[float] = []
    for i in range(AccountEnumTimingCheck.SAMPLES_PER_SIDE):
        # exists probe
        timeline.extend([float(i * 10), float(i * 10) + 0.005])
        # absent probe
        timeline.extend([float(i * 10) + 1.0, float(i * 10) + 1.0 + 0.600])
    _install_monotonic_queue(monkeypatch, timeline)

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[("Content-Type", "text/html")],
                        body=b"login form", engine="fake")

    row = _row(
        url="https://x.test/login", method="POST", status=200,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"username=alice&password=hunter2",
    )
    scanner = ActiveScanner(checks=[AccountEnumTimingCheck()], sender=responder)
    findings = scanner.run_on_row(row,
                                  options=ActiveOptions(
                                      enabled_checks=["auth-enum-timing"]))
    assert any("Account enumeration" in f.title for f in findings)


def test_account_enum_timing_silent_when_flat(monkeypatch):
    # Both sides ~5ms — no anomaly.
    timeline: list[float] = []
    for i in range(AccountEnumTimingCheck.SAMPLES_PER_SIDE):
        timeline.extend([float(i * 10), float(i * 10) + 0.005])
        timeline.extend([float(i * 10) + 1.0, float(i * 10) + 1.0 + 0.005])
    _install_monotonic_queue(monkeypatch, timeline)

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[("Content-Type", "text/html")],
                        body=b"login form", engine="fake")

    row = _row(
        url="https://x.test/login", method="POST", status=200,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"username=alice&password=hunter2",
    )
    scanner = ActiveScanner(checks=[AccountEnumTimingCheck()], sender=responder)
    findings = scanner.run_on_row(row,
                                  options=ActiveOptions(
                                      enabled_checks=["auth-enum-timing"]))
    assert not any(f.cwe == "CWE-204" for f in findings)


def test_account_enum_timing_skipped_when_no_username_field():
    def responder(req: Request) -> Response:  # pragma: no cover — never called
        raise AssertionError("responder should not be invoked")

    row = _row(method="POST", status=200,
               req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
               req_body=b"q=hi")
    scanner = ActiveScanner(checks=[AccountEnumTimingCheck()], sender=responder)
    findings = scanner.run_on_row(row,
                                  options=ActiveOptions(
                                      enabled_checks=["auth-enum-timing"]))
    assert findings == []


def test_account_enum_timing_skipped_on_get_method():
    def responder(req: Request) -> Response:  # pragma: no cover
        raise AssertionError("responder should not be invoked")

    row = _row(url="https://x.test/login?username=alice",
               method="GET", status=200,
               req_headers=[("Content-Type", "application/x-www-form-urlencoded")])
    scanner = ActiveScanner(checks=[AccountEnumTimingCheck()], sender=responder)
    findings = scanner.run_on_row(row,
                                  options=ActiveOptions(
                                      enabled_checks=["auth-enum-timing"]))
    assert findings == []


# ---- CSRFTokenValidationCheck ----------------------------------------------


def test_csrf_check_fires_when_form_token_removed_accepted():
    seen_bodies: list[bytes] = []

    def responder(req: Request) -> Response:
        seen_bodies.append(req.body or b"")
        # Broken server: ignores the token and 200s every time.
        return Response(status=200, headers=[], body=b"updated", engine="fake")

    row = _row(
        url="https://x.test/account/update", method="POST", status=200,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"_token=valid_xyz&email=new@x.test",
    )
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert any(f.cwe == "CWE-352" for f in findings)
    # Confirm at least one probe carried the mangled token marker.
    assert any(b"reqlore_invalid_csrf_zzz" in b for b in seen_bodies)


def test_csrf_check_quiet_when_server_rejects_both_probes():
    def responder(req: Request) -> Response:
        # Sane server: rejects anything missing the original token value.
        if b"_token=valid_xyz" in (req.body or b""):
            return Response(status=200, headers=[], body=b"ok", engine="fake")
        return Response(status=403, headers=[], body=b"forbidden", engine="fake")

    row = _row(
        url="https://x.test/account/update", method="POST", status=200,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"_token=valid_xyz&email=new@x.test",
    )
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert not any(f.cwe == "CWE-352" for f in findings)


def test_csrf_check_header_token_removed(monkeypatch):
    seen_headers: list[list[tuple[str, str]]] = []

    def responder(req: Request) -> Response:
        seen_headers.append(list(req.headers))
        return Response(status=200, headers=[], body=b"updated", engine="fake")

    row = _row(
        url="https://x.test/account/update", method="POST", status=200,
        req_headers=[("X-CSRF-Token", "deadbeef")],
        req_body=b"data=x",
    )
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert any(f.cwe == "CWE-352" for f in findings)
    # Confirm one of the probes dropped the X-CSRF-Token header entirely.
    assert any(
        not any(k.lower() == "x-csrf-token" for k, _ in hs)
        for hs in seen_headers
    )


def test_csrf_check_skipped_on_get_method():
    def responder(req: Request) -> Response:  # pragma: no cover
        raise AssertionError("responder should not be invoked")

    row = _row(url="https://x.test/?_token=abc", method="GET", status=200)
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert findings == []


def test_csrf_check_skipped_when_baseline_non_2xx():
    def responder(req: Request) -> Response:  # pragma: no cover
        raise AssertionError("responder should not be invoked")

    row = _row(
        url="https://x.test/account/update", method="POST", status=403,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"_token=valid_xyz&email=new@x.test",
    )
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert findings == []


def test_csrf_check_skipped_when_no_token_present():
    def responder(req: Request) -> Response:  # pragma: no cover
        raise AssertionError("responder should not be invoked")

    row = _row(
        url="https://x.test/account/update", method="POST", status=200,
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"email=new@x.test",
    )
    scanner = ActiveScanner(checks=[CSRFTokenValidationCheck()], sender=responder)
    findings = scanner.run_on_row(
        row, options=ActiveOptions(enabled_checks=["csrf-token-not-validated"]))
    assert findings == []
