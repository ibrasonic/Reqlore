"""Phase 18 - Per-target intercept-from-scope shortcut.

Covers:

* ``InterceptConfig.restrict_to_scope`` defaults to False and round-trips
  through ``to_dict`` / ``from_dict``.
* Old persisted blobs (without the new key) decode without error and
  default the flag to False.
* The proxy ``set_intercept_config`` form POST parses the checkbox.
* The ``_HistoryAddon.request()`` hook short-circuits the hold when the
  flag is on and the host is out of scope, AND still holds in-scope
  hosts that match every other criterion.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from reqlore.config import Settings
from reqlore.proxy.mitm import ProxyController, _HistoryAddon
from reqlore.proxy.rules import InterceptConfig
from reqlore.storage import Project
from reqlore.web import create_app

# ---------------------------------------------------------------------------
# dataclass + persistence round-trip
# ---------------------------------------------------------------------------


def test_intercept_config_default_restrict_to_scope_is_false() -> None:
    assert InterceptConfig().restrict_to_scope is False


def test_intercept_config_to_dict_includes_restrict_to_scope() -> None:
    cfg = InterceptConfig(restrict_to_scope=True)
    d = cfg.to_dict()
    assert d["restrict_to_scope"] is True


def test_intercept_config_from_dict_reads_restrict_to_scope() -> None:
    cfg = InterceptConfig.from_dict({"restrict_to_scope": True})
    assert cfg.restrict_to_scope is True


def test_intercept_config_from_dict_legacy_blob_defaults_false() -> None:
    # Forward-compat: blobs persisted before this phase have no key.
    legacy = {
        "methods": ["POST"],
        "host_regex": "",
        "path_regex": "",
        "exclude_host_regex": "",
        "exclude_path_regex": "",
    }
    cfg = InterceptConfig.from_dict(legacy)
    assert cfg.restrict_to_scope is False


def test_intercept_config_from_dict_coerces_bad_type() -> None:
    cfg = InterceptConfig.from_dict({"restrict_to_scope": "yes"})
    # bool("yes") is True; this exercises the cast path
    assert cfg.restrict_to_scope is True
    cfg2 = InterceptConfig.from_dict({"restrict_to_scope": 0})
    assert cfg2.restrict_to_scope is False


# ---------------------------------------------------------------------------
# form POST + state round-trip
# ---------------------------------------------------------------------------


def test_proxy_intercept_config_form_persists_restrict_to_scope(
    tmp_path: Path,
) -> None:
    proj_path = tmp_path / "p18_form.rlr"
    ca_dir = tmp_path / "ca"
    ctl = ProxyController(Project(proj_path), "127.0.0.1", 0, ca_dir)
    app = create_app(proj_path, Settings(), proxy=ctl)
    client = app.test_client()

    # Seed the CSRF cookie/session.
    assert client.get("/proxy/").status_code == 200
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    assert token

    r = client.post("/proxy/intercept/config", data={
        "_csrf": token,
        "method": "POST",
        "host_regex": "",
        "path_regex": "",
        "restrict_to_scope": "1",
    }, follow_redirects=True)
    assert r.status_code == 200

    project = app.extensions["reqlore_project"]
    saved = json.loads(project.get_state("intercept_config"))
    assert saved.get("restrict_to_scope") is True
    assert ctl.get_intercept_config().restrict_to_scope is True


def test_proxy_intercept_config_form_unchecked_clears_flag(
    tmp_path: Path,
) -> None:
    proj_path = tmp_path / "p18_clear.rlr"
    ca_dir = tmp_path / "ca"
    ctl = ProxyController(Project(proj_path), "127.0.0.1", 0, ca_dir)
    # Seed an already-on flag.
    ctl.set_intercept_config(InterceptConfig(restrict_to_scope=True))
    app = create_app(proj_path, Settings(), proxy=ctl)
    client = app.test_client()

    assert client.get("/proxy/").status_code == 200
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    assert token

    # Re-submit WITHOUT the restrict_to_scope checkbox.
    r = client.post("/proxy/intercept/config", data={
        "_csrf": token,
        "method": "POST",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert ctl.get_intercept_config().restrict_to_scope is False


# ---------------------------------------------------------------------------
# end-to-end through the addon hook
# ---------------------------------------------------------------------------


class _Hdrs:
    def __init__(self, d=None):
        self._d = {k.lower(): v for k, v in (d or {}).items()}

    def get(self, k, default=""):
        return self._d.get(k.lower(), default)

    def items(self):
        return list(self._d.items())

    def clear(self):
        self._d.clear()

    def __setitem__(self, k, v):
        self._d[k.lower()] = v


class _Req:
    def __init__(self, url, method="POST", host="target.example", path="/"):
        self.method = method
        self.path = path
        self.http_version = "HTTP/1.1"
        self.pretty_host = host
        self.pretty_url = url
        self.port = 443
        self.headers = _Hdrs({"Host": host})
        self.raw_content = b""

    def set_content(self, b):
        self.raw_content = b


class _Flow:
    def __init__(self, req):
        self.request = req
        self.response = None
        self.duration = 0.01

    def kill(self):
        pass


def _addon_with_rule_and_scope(project, *, restrict: bool) -> _HistoryAddon:
    cfg = InterceptConfig(methods=["GET", "POST"], restrict_to_scope=restrict)
    rules = [cfg.to_rule()]
    return _HistoryAddon(
        project, rules=rules, sync_hold=False, ui_port=8787,
        cfg_reader=lambda: cfg,
    )


def test_addon_holds_when_restrict_off(tmp_path: Path) -> None:
    """Sanity baseline: with the flag off, every matching request is
    held regardless of scope rules."""
    p = Project(tmp_path / "p18_e2e_off.rlr")
    try:
        p.add_scope("include", "in-scope.example")
        addon = _addon_with_rule_and_scope(p, restrict=False)
        flow = _Flow(_Req(url="https://out-of-scope.example/x",
                          host="out-of-scope.example"))
        asyncio.run(addon.request(flow))
        # With restrict_to_scope off, the out-of-scope request IS held
        # (one row enqueued).
        assert len(p.list_intercept()) == 1
    finally:
        p.close()


def test_addon_skips_hold_when_restrict_on_and_out_of_scope(
    tmp_path: Path,
) -> None:
    """The opt-in case: flag on, host not in scope -> request flows
    through without ever entering the hold queue."""
    p = Project(tmp_path / "p18_e2e_oos.rlr")
    try:
        p.add_scope("include", "in-scope.example")
        addon = _addon_with_rule_and_scope(p, restrict=True)
        flow = _Flow(_Req(url="https://out-of-scope.example/x",
                          host="out-of-scope.example"))
        asyncio.run(addon.request(flow))
        # Out-of-scope: the request hook returns before enqueue.
        assert p.list_intercept() == []
    finally:
        p.close()


def test_addon_still_holds_in_scope_when_restrict_on(tmp_path: Path) -> None:
    """The flag must not break the normal case: in-scope hosts still
    get held when they match every other criterion."""
    p = Project(tmp_path / "p18_e2e_is.rlr")
    try:
        p.add_scope("include", "in-scope.example")
        addon = _addon_with_rule_and_scope(p, restrict=True)
        flow = _Flow(_Req(url="https://in-scope.example/login",
                          host="in-scope.example"))
        asyncio.run(addon.request(flow))
        rows = p.list_intercept()
        assert len(rows) == 1
    finally:
        p.close()


def test_addon_empty_scope_treats_everything_as_in_scope(
    tmp_path: Path,
) -> None:
    """When the operator has no scope rules at all, restrict_to_scope
    must be a no-op (host_in_scope returns True on an empty rule set)."""
    p = Project(tmp_path / "p18_e2e_empty.rlr")
    try:
        addon = _addon_with_rule_and_scope(p, restrict=True)
        flow = _Flow(_Req(url="https://anything.example/x",
                          host="anything.example"))
        asyncio.run(addon.request(flow))
        assert len(p.list_intercept()) == 1
    finally:
        p.close()
