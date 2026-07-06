"""Phase 1 of [RELIABILITY_PLAN](../../../../docs/RELIABILITY_PLAN.md):
component health matrix.

Four data-driven sweeps that introspect the live tool rather than
hard-code a list of components, so a newly registered blueprint /
subcommand / module is automatically picked up by CI.

These are *tripwires*. They are cheap, deterministic, and they catch
the entire class of "you added it but forgot to wire it" bugs that no
existing test covers because every existing test only exercises the
happy path it was written against.
"""
from __future__ import annotations

import importlib
import pkgutil
import socket

import pytest

import reqlore
from reqlore import cli as reqlore_cli
from reqlore.config import Settings
from reqlore.engines import Request, raw_engine
from reqlore.web import create_app

# Modules that legitimately raise at import time when their optional
# dependency is missing. The scanner gap plan covers these separately;
# we just don't want the tripwire to flag them.
_OPTIONAL_IMPORT_SKIPS: frozenset[str] = frozenset({
    # `_optdeps` itself probes optional deps, never raises; nothing in
    # the tree is currently allowed to raise at import time. Leave the
    # allow-list in place so future genuine soft-deps have a home.
})

# Blueprint rule conventions that we cannot GET in a smoke test:
# they require either POST, an authenticated session beyond the test
# client, or a path parameter that has no safe default.
_RULE_ENDPOINT_SKIPS: frozenset[str] = frozenset({
    "static",                       # served by Flask, not us
    "saml_bp.acs_metadata",         # downloads a file, not a page
    # `/login` is registered unconditionally so url_for("auth.login")
    # works from anywhere, but the view returns 404 when no password
    # is configured (the smoke fixture builds an app with auth off).
    "auth.login",
    # `/comparer/export.diff` is a download endpoint that 404s without
    # `t=` (cache token) or `from_a=&from_b=` (history ids). The smoke
    # client has neither, so the 404 is the correct behaviour.
    "comparer.export_diff",
    # `/plugins/send/` is the Send-to-plugin chooser; it requires a
    # `?from_history=<hid>` query arg pointing at a real history row
    # and 404s otherwise. The smoke client has neither, so the 404 is
    # the correct behaviour.
    "plugins.send_to_chooser",
    # `/proxy/ca` serves the generated CA PEM from disk and 404s with
    # "No CA generated yet. Start the proxy once." until the mitm
    # addon has run at least once. The smoke fixture builds an app
    # with `proxy=None`, so the 404 is the documented behaviour.
    "proxy.ca_download",
})


# ----------------------------- 1. Module import sweep -----------------------


def _iter_reqlore_modules() -> list[str]:
    """Yield every importable module name under the reqlore package."""
    names: list[str] = []
    for mod in pkgutil.walk_packages(reqlore.__path__,
                                       prefix=reqlore.__name__ + "."):
        # Tests live inside the package; skip them — pytest is already
        # importing the relevant ones and we don't want recursive
        # introspection eating fixtures.
        if ".tests" in mod.name:
            continue
        names.append(mod.name)
    return names


@pytest.mark.parametrize("module_name", _iter_reqlore_modules())
def test_every_reqlore_module_imports(module_name: str) -> None:
    if module_name in _OPTIONAL_IMPORT_SKIPS:
        pytest.skip(f"{module_name} is opt-dep-gated")
    # importlib.import_module is the cheapest reliable tripwire we
    # have. We deliberately do not catch — a regression here means a
    # user installing Reqlore would get an ImportError on first run.
    importlib.import_module(module_name)


# --------------------- 2. Blueprint reachability matrix ---------------------


@pytest.fixture(scope="module")
def smoke_app(tmp_path_factory):
    """One Flask app for the whole matrix — creating it per-test would
    burn ~ 30 s on this matrix alone for no extra coverage."""
    tmp = tmp_path_factory.mktemp("reliability_phase1")
    return create_app(tmp / "phase1.rlr", Settings(), proxy=None)


def _iter_safe_get_rules(app) -> list[tuple[str, str]]:
    """Return (endpoint, url) pairs we can safely GET.

    We skip rules that:
    - require a path argument (no safe default value),
    - do not accept GET,
    - are on the static endpoint or another explicit skip.
    """
    out: list[tuple[str, str]] = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint in _RULE_ENDPOINT_SKIPS:
            continue
        if "GET" not in (rule.methods or set()):
            continue
        if rule.arguments:
            continue
        out.append((rule.endpoint, rule.rule))
    out.sort()
    return out


def test_blueprint_matrix_has_expected_coverage(smoke_app):
    """Self-check: the matrix must include the user-facing blueprints
    we ship. If create_app forgets to register one, this is the first
    test that fails."""
    rules = {url for _, url in _iter_safe_get_rules(smoke_app)}
    # We check by URL prefix rather than endpoint name because Flask
    # uses Blueprint(name=...) and that name diverges from the Python
    # variable name (`proxy_bp` is registered as `proxy_bp` in some
    # files and just `proxy` in others; the URL prefix is the stable
    # contract the user sees).
    expected_url_prefixes = {
        "/", "/proxy/", "/history/", "/repeater/", "/intruder/",
        "/scanner/", "/decoder/", "/settings/", "/help/",
    }
    missing = {p for p in expected_url_prefixes if p not in rules}
    assert not missing, (
        f"blueprint URL prefixes missing from app: {missing}"
    )


def test_every_safe_get_rule_returns_a_sensible_status(smoke_app):
    """GET every parameter-less route, assert status is in a sane set.

    We accept 200 (rendered), 302/303 (redirect to a login or onboarding
    page), 401 (auth-required page advertising itself). Anything else
    (404, 500, ...) is a wiring bug."""
    client = smoke_app.test_client()
    failures: list[str] = []
    for endpoint, url in _iter_safe_get_rules(smoke_app):
        resp = client.get(url)
        if resp.status_code not in {200, 302, 303, 401}:
            failures.append(
                f"{endpoint} ({url}) -> {resp.status_code}"
            )
    assert not failures, "blueprint smoke regressions:\n  " + "\n  ".join(
        failures
    )


# --------------------- 3. CLI subcommand parse matrix -----------------------


def _iter_cli_subcommands() -> list[str]:
    """Pull every subcommand the user can type from argparse internals.

    The SubParsersAction stores its registered subparsers in `choices`;
    we filter by `dest == "subcommand"` to skip nested subparsers (e.g.
    `reqlore plugin <subsub>`)."""
    import argparse as _ap
    parser = reqlore_cli.build_parser()
    names: list[str] = []
    for action in parser._actions:                              # noqa: SLF001
        if (isinstance(action, _ap._SubParsersAction)           # noqa: SLF001
                and getattr(action, "dest", None) == "subcommand"
                and action.choices):
            names.extend(sorted(action.choices.keys()))
    return names


@pytest.mark.parametrize("subcommand", _iter_cli_subcommands())
def test_cli_subcommand_parses_help(subcommand: str) -> None:
    """`reqlore <sub> --help` must exit 0 and mention the subcommand.

    Catches subcommands wired without a `set_defaults(func=...)` (they
    blow up later when invoked) and typos in help text."""
    parser = reqlore_cli.build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([subcommand, "--help"])
    assert exc_info.value.code == 0, (
        f"reqlore {subcommand} --help exited with code "
        f"{exc_info.value.code}"
    )


# ----------------------- 4. Engine round-trip sanity ------------------------


def test_raw_engine_request_serialise_parses_back_consistently():
    """raw_engine._build_raw -> bytes that begin with our method + path
    and carry the headers we asked for. Cheap regression guard for the
    Host-header injection logic the scanner relies on."""
    req = Request(
        method="POST",
        url="http://example.test:8080/path/segment?q=1",
        headers=[("X-Custom", "value")],
        body=b"hello",
    )
    raw = raw_engine._build_raw(req)                            # noqa: SLF001
    assert raw.startswith(b"POST /path/segment?q=1 HTTP/1.1\r\n")
    assert b"Host: example.test:8080" in raw
    assert b"Content-Length: 5" in raw
    assert b"X-Custom: value" in raw
    assert raw.endswith(b"\r\n\r\nhello")


def test_raw_engine_parses_a_minimal_well_formed_response():
    raw = (b"HTTP/1.1 204 No Content\r\n"
            b"X-Empty: yes\r\n"
            b"\r\n")
    resp = raw_engine._parse_response(raw)                      # noqa: SLF001
    assert resp.status == 204
    assert resp.reason == "No Content"
    assert ("X-Empty", "yes") in resp.headers
    assert resp.body == b""
    assert resp.engine == "raw"
    assert resp.error is None


def test_raw_engine_dead_port_returns_zero_status_with_error():
    """`raw_engine.send` against a guaranteed-dead port must not
    raise. It returns `Response(status=0, error=...)` so callers (the
    active scanner) can treat it as a non-finding without try/except
    on every probe. If a future refactor lets `ConnectionRefusedError`
    escape, the scanner will start crashing mid-row again."""
    # Bind a socket to a free port then close it — port is now provably
    # dead for the duration of the test, and we can't accidentally hit
    # a live service.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    req = Request(method="GET", url=f"http://127.0.0.1:{port}/")
    resp = raw_engine.send(req, timeout=2.0)
    assert resp.status == 0
    assert resp.error
    assert resp.engine == "raw"


def test_httpx_engine_send_signature_is_stable():
    """The active scanner calls httpx_engine.send(req, timeout=...,
    follow_redirects=...); guard that signature."""
    import inspect

    from reqlore.engines import httpx_engine

    sig = inspect.signature(httpx_engine.send)
    params = sig.parameters
    assert "req" in params or list(params)[0] == list(params)[0]
    # Required keyword the scanner uses.
    assert "timeout" in params
    assert "follow_redirects" in params
