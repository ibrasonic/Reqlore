"""Optional accessibility (axe-core) smoke tests.

These require the `[a11y]` extra: ``pip install reqlore[a11y]`` and
``python -m playwright install chromium``. If either is missing, all tests in
this module are skipped at import time so the default unit run isn't slowed
down.

The check policy is intentionally narrow: we fail the build on any axe finding
with impact ``serious`` or ``critical``. Cosmetic / minor warnings do not gate
the suite.
"""
from __future__ import annotations

from threading import Thread
from wsgiref.simple_server import make_server

import pytest

playwright = pytest.importorskip("playwright")
axe_pw = pytest.importorskip("axe_playwright_python")
from axe_playwright_python.sync_playwright import Axe  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from reqlore.config import Settings  # noqa: E402  # after pytest.importorskip guard
from reqlore.web import create_app  # noqa: E402  # after pytest.importorskip guard

ROUTES = [
    "/", "/proxy/", "/history/", "/repeater/", "/intruder/", "/scanner/",
    "/comparer/", "/decoder/", "/jwt/", "/sitemap/", "/match-replace/",
    "/search/", "/reporter/", "/plugins/", "/cues/", "/settings/", "/help/",
    "/graphql/", "/ws/", "/saml/", "/poc/", "/macros/", "/sequencer/",
    "/oast/", "/h2/", "/smuggling/",
]


@pytest.fixture(scope="module")
def app_server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("a11y_smoke")
    app = create_app(tmp / "a11y.rlr", Settings(), proxy=None)
    srv = make_server("127.0.0.1", 0, app)
    t = Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("path", ROUTES)
def test_route_has_no_serious_a11y_violations(app_server, path):
    url = app_server + path
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.goto(url, wait_until="load")
            results = Axe().run(page)
            bad = [v for v in results.response.get("violations", [])
                   if v.get("impact") in ("serious", "critical")]
            assert not bad, (
                f"{path} failed axe: " +
                ", ".join(f"{v['id']}({v['impact']})" for v in bad)
            )
        finally:
            browser.close()
