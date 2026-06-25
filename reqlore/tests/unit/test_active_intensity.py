"""Phase 2 (Burp parity) — active-check intensity tiers.

Covers:

* :class:`reqlore.scanner.rules.RuleMeta` validates ``intensity``.
* :class:`reqlore.scanner.active.ActiveOptions` defaults to
  ``{"light", "medium"}`` and rejects unknown tiers.
* :class:`reqlore.scanner.active.ActiveScanner` filters by tier when
  ``enabled_checks`` is ``None`` and bypasses the filter when it is
  set (explicit selection always wins).
* All 28 builtin active checks have an intensity assigned per the
  Burp-parity mapping (8 light / 13 medium / 7 intrusive).
* The ``/scanner/run-active`` route honours the new form fields:
  defaults to light+medium, requires ``confirm_intrusive=yes`` when
  Intrusive is ticked, and bumps the rate-delay floor to 100 ms for
  intrusive scans.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from reqlore.config import Settings
from reqlore.engines import Request, Response
from reqlore.plugins import reset_registry
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import BUILTIN_ACTIVE_CHECKS, ActiveScanResult
from reqlore.scanner.rules import INTENSITIES, RuleMeta, intensity_for
from reqlore.storage import Project
from reqlore.web import create_app


# ---------------------------------------------------------------------------
# RuleMeta.intensity
# ---------------------------------------------------------------------------

def test_rulemeta_intensity_defaults_to_medium():
    meta = RuleMeta(id="active:demo", title="Demo")
    assert meta.intensity == "medium"


def test_rulemeta_intensity_accepts_valid_tiers():
    for tier in INTENSITIES:
        meta = RuleMeta(id="active:demo", title="Demo", intensity=tier)
        assert meta.intensity == tier


def test_rulemeta_intensity_rejects_unknown_value():
    with pytest.raises(ValueError, match="intensity"):
        RuleMeta(id="active:demo", title="Demo", intensity="extreme")


# ---------------------------------------------------------------------------
# ActiveOptions.intensity_levels
# ---------------------------------------------------------------------------

def test_active_options_default_intensity_levels_excludes_intrusive():
    opts = ActiveOptions()
    assert opts.intensity_levels == frozenset({"light", "medium"})
    assert "intrusive" not in opts.intensity_levels


def test_active_options_accepts_custom_intensity_levels():
    opts = ActiveOptions(intensity_levels=frozenset({"intrusive"}))
    assert opts.intensity_levels == frozenset({"intrusive"})


def test_active_options_rejects_unknown_intensity():
    with pytest.raises(ValueError, match="unknown tier"):
        ActiveOptions(intensity_levels=frozenset({"medium", "wat"}))


def test_active_options_rejects_empty_intensity_levels():
    with pytest.raises(ValueError, match="at least one tier"):
        ActiveOptions(intensity_levels=frozenset())


# ---------------------------------------------------------------------------
# Builtin-check coverage and Burp-parity mapping
# ---------------------------------------------------------------------------

def test_all_builtin_checks_have_intensity_assigned():
    for check in BUILTIN_ACTIVE_CHECKS:
        tier = intensity_for(check)
        assert tier in INTENSITIES, (
            f"{check.name}: intensity {tier!r} not in {INTENSITIES}"
        )


def test_intensity_counts_match_burp_mapping():
    counts = Counter(intensity_for(c) for c in BUILTIN_ACTIVE_CHECKS)
    # Baseline 28 checks (8/13/7) + Phase 6's 18 new checks (3/12/3) = 46
    # (11/25/10). Phase 19 added 2 intrusive (account-enum timing,
    # CSRF-token validation) -> 48 (11/25/12). Phase 26 added 2 more
    # intrusive auth-flow checks (MFA bypass, session fixation)
    # -> 50 (11/25/14).
    assert counts["light"] == 11, counts
    assert counts["medium"] == 25, counts
    assert counts["intrusive"] == 14, counts
    # Sanity: every check accounted for.
    assert sum(counts.values()) == len(BUILTIN_ACTIVE_CHECKS) == 50


# ---------------------------------------------------------------------------
# Scanner-level filter behaviour
# ---------------------------------------------------------------------------

def _req_bytes(method: str = "GET",
               url: str = "https://x.test/?q=1") -> bytes:
    return (f"{method} {url} HTTP/1.1\r\n\r\n").encode("latin-1")


def _resp_bytes(status: int = 200) -> bytes:
    return f"HTTP/1.1 {status} OK\r\n\r\n".encode("latin-1")


def _seed_project(tmp_path: Path) -> Project:
    proj = Project(tmp_path / "intensity.rlr")
    proj.add_history(
        host="x.test", method="GET",
        url="https://x.test/?q=1", status=200,
        duration_ms=1, engine="x",
        raw_req=_req_bytes(), raw_resp=_resp_bytes(),
    )
    return proj


@dataclass
class _StubCheck:
    """Minimal stand-in for an active check. Counts runs so we can
    assert which checks were allowed past the intensity gate."""
    name: str
    meta: RuleMeta
    description: str = "stub"
    calls: list[int] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def run(self, ctx: Any, send: Any, *, opts: Any = None):  # noqa: ARG002
        self.calls.append(1)
        return []


def _make_stub(name: str, tier: str) -> _StubCheck:
    return _StubCheck(
        name=name,
        meta=RuleMeta(id=f"active:{name}", title=name, intensity=tier),
    )


def test_scanner_filters_intrusive_by_default(tmp_path):
    """With default opts (light+medium) the intrusive stub never runs and the
    skipped_by_intensity counter goes up."""
    proj = _seed_project(tmp_path)
    try:
        light = _make_stub("stub-light", "light")
        medium = _make_stub("stub-medium", "medium")
        intrusive = _make_stub("stub-intrusive", "intrusive")
        scanner = ActiveScanner(
            checks=[light, medium, intrusive],
            sender=lambda req: Response(
                status=200, headers=[], body=b"", engine="fake",
            ),
        )
        result = scanner.run_on_project(proj, options=ActiveOptions())
        assert light.calls == [1]
        assert medium.calls == [1]
        assert intrusive.calls == []
        assert result.skipped_by_intensity >= 1
    finally:
        proj.close()


def test_enabled_checks_bypasses_intensity_filter(tmp_path):
    """Naming an intrusive check via ``enabled_checks`` runs it even if the
    default ``intensity_levels`` excludes intrusive."""
    proj = _seed_project(tmp_path)
    try:
        intrusive = _make_stub("stub-intrusive", "intrusive")
        scanner = ActiveScanner(
            checks=[intrusive],
            sender=lambda req: Response(
                status=200, headers=[], body=b"", engine="fake",
            ),
        )
        opts = ActiveOptions(enabled_checks=["stub-intrusive"])
        scanner.run_on_project(proj, options=opts)
        assert intrusive.calls == [1]
    finally:
        proj.close()


def test_intensity_levels_intrusive_runs_intrusive_checks(tmp_path):
    proj = _seed_project(tmp_path)
    try:
        intrusive = _make_stub("stub-intrusive", "intrusive")
        scanner = ActiveScanner(
            checks=[intrusive],
            sender=lambda req: Response(
                status=200, headers=[], body=b"", engine="fake",
            ),
        )
        opts = ActiveOptions(
            intensity_levels=frozenset({"light", "medium", "intrusive"}),
        )
        scanner.run_on_project(proj, options=opts)
        assert intrusive.calls == [1]
    finally:
        proj.close()


def test_run_on_row_also_filters_by_intensity():
    """``run_on_row`` shares the same gate; assert it doesn't call the
    intrusive stub when defaults are in play."""

    @dataclass
    class _Row:
        id: int
        host: str
        url: str
        method: str
        status: int
        req_blob: bytes
        resp_blob: bytes

    row = _Row(id=1, host="x.test", url="https://x.test/?q=1",
               method="GET", status=200,
               req_blob=_req_bytes(), resp_blob=_resp_bytes())
    intrusive = _make_stub("stub-intrusive", "intrusive")
    scanner = ActiveScanner(
        checks=[intrusive],
        sender=lambda req: Response(
            status=200, headers=[], body=b"", engine="fake",
        ),
    )
    scanner.run_on_row(row)
    assert intrusive.calls == []


# ---------------------------------------------------------------------------
# Web route — /scanner/run-active
# ---------------------------------------------------------------------------

@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(
        plugins_mod, "default_plugin_dirs", lambda: [tmp_path / "plugins"]
    )
    reset_registry()
    return create_app(tmp_path / "intensity.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_route_run_active_default_intensity_excludes_intrusive(
    client, app, monkeypatch,
):
    captured: dict[str, Any] = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["levels"] = options.intensity_levels
        return ActiveScanResult()

    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)
    token = _csrf(client)
    r = client.post("/scanner/run-active", data={"_csrf": token})
    assert r.status_code == 302
    assert captured["levels"] == frozenset({"light", "medium"})


def test_route_run_active_requires_confirm_for_intrusive(
    client, app, monkeypatch,
):
    started: list[int] = []

    def fake_run(self, project, *, options, host=None, limit=20):
        started.append(1)
        return ActiveScanResult()

    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)
    token = _csrf(client)
    r = client.post(
        "/scanner/run-active",
        data={
            "_csrf": token,
            "intensity_light": "1",
            "intensity_medium": "1",
            "intensity_intrusive": "1",
            # confirm_intrusive intentionally absent
        },
    )
    assert r.status_code == 302
    assert started == [], "scan must not start without intrusive confirmation"


def test_route_run_active_intrusive_with_confirm_starts_scan(
    client, app, monkeypatch,
):
    captured: dict[str, Any] = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["levels"] = options.intensity_levels
        captured["delay"] = options.rate_delay_ms
        return ActiveScanResult()

    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)
    token = _csrf(client)
    r = client.post(
        "/scanner/run-active",
        data={
            "_csrf": token,
            "intensity_intrusive": "1",
            "confirm_intrusive": "yes",
        },
    )
    assert r.status_code == 302
    assert "intrusive" in captured["levels"]


def test_route_run_active_bumps_delay_floor_for_intrusive(
    client, app, monkeypatch,
):
    """Even if the operator submits delay=0, intrusive scans run with at
    least 100 ms between probes."""
    captured: dict[str, Any] = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["delay"] = options.rate_delay_ms
        return ActiveScanResult()

    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)
    token = _csrf(client)
    r = client.post(
        "/scanner/run-active",
        data={
            "_csrf": token,
            "intensity_intrusive": "1",
            "confirm_intrusive": "yes",
            "delay": "0",
        },
    )
    assert r.status_code == 302
    assert captured["delay"] >= 100


def test_route_run_active_keeps_high_delay_for_intrusive(
    client, app, monkeypatch,
):
    """A 500 ms delay must not be reduced when intrusive is selected."""
    captured: dict[str, Any] = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["delay"] = options.rate_delay_ms
        return ActiveScanResult()

    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)
    token = _csrf(client)
    r = client.post(
        "/scanner/run-active",
        data={
            "_csrf": token,
            "intensity_intrusive": "1",
            "confirm_intrusive": "yes",
            "delay": "500",
        },
    )
    assert r.status_code == 302
    assert captured["delay"] == 500


def test_run_page_renders_intensity_fieldset(client):
    body = client.get("/scanner/run").data.decode()
    assert "Intensity tiers" in body
    for name in ("intensity_light", "intensity_medium", "intensity_intrusive"):
        assert f'name="{name}"' in body
    # Light + Medium default-checked, Intrusive opt-in.
    assert 'id="intensity-light"' in body and 'id="intensity-medium"' in body
    assert 'id="intensity-intrusive"' in body
    assert 'name="confirm_intrusive"' in body
    # Defence-in-depth a11y: never colour-only, intrusive describedby the warning.
    assert 'aria-describedby="intrusive-warning"' in body
    assert 'id="intrusive-warning"' in body
