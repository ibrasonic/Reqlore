"""Phase 2 of [RELIABILITY_PLAN](../../../../docs/RELIABILITY_PLAN.md):
WCAG AAA structural matrix.

Six data-driven sweeps that GET every parameter-less route the app
exposes and assert the HTML the user actually receives obeys the
structural rules listed in
[ACCESSIBILITY.md](../../../../docs/ACCESSIBILITY.md):

  1. Exactly one ``<h1>`` per page.
  2. No skipped heading levels (e.g. no ``<h3>`` before any ``<h2>``).
  3. The base-template landmark skeleton is present (skip-link,
     ``<main id="main" tabindex="-1">``, polite live region).
  4. Every form control either has a ``<label for=>`` pointing at it
     or carries ``aria-label`` / ``aria-labelledby``.
  5. No ``tabindex > 0`` (natural tab order only).
  6. Every ``<button>`` carries an explicit ``type=``.
  7. Every ``<table>`` has a ``<caption>`` and ``<th>`` cells carry
     ``scope="col"`` or ``scope="row"``.

The matrix introspects the live ``app.url_map`` so a newly registered
blueprint is picked up automatically.
"""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


# Endpoints we cannot meaningfully GET in a smoke test. Kept in sync
# with the Phase 1 matrix; see test_reliability_phase1 for rationale.
_RULE_ENDPOINT_SKIPS: frozenset[str] = frozenset({
    "static",
    "saml_bp.acs_metadata",
    "auth.login",
    "comparer.export_diff",
})

# A few endpoints return non-HTML (CSV / JSON exports) or templated
# fragments that intentionally don't carry the full base skeleton.
# We allow-list them out of the structural checks rather than skip
# the whole route, so any *new* HTML page they grow gets reviewed.
_NON_HTML_ENDPOINT_SKIPS: frozenset[str] = frozenset({
    # add fragment / download endpoints here as they appear
})


@pytest.fixture(scope="module")
def smoke_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("reliability_phase2")
    return create_app(tmp / "phase2.rlr", Settings(), proxy=None)


def _iter_html_routes(app) -> list[tuple[str, str]]:
    """Return (endpoint, url) pairs for parameter-less GET routes."""
    out: list[tuple[str, str]] = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint in _RULE_ENDPOINT_SKIPS:
            continue
        if rule.endpoint in _NON_HTML_ENDPOINT_SKIPS:
            continue
        if "GET" not in (rule.methods or set()):
            continue
        if rule.arguments:
            continue
        out.append((rule.endpoint, rule.rule))
    out.sort()
    return out


def _fetch_html(client, url: str) -> str | None:
    """GET ``url`` and return decoded HTML, or None if not text/html.

    Routes that return 302/303 (login redirect) or non-HTML payloads
    are silently dropped so callers can still parametrise across the
    full map without conditional skips polluting the matrix.
    """
    resp = client.get(url)
    if resp.status_code not in (200, 401):
        return None
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "html" not in ctype:
        return None
    return resp.data.decode("utf-8", errors="replace")


# ----- collection helpers (one parser per check keeps them readable) --------


class _HeadingCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.levels: list[int] = []

    def handle_starttag(self, tag, attrs):
        if len(tag) == 2 and tag[0] == "h" and tag[1].isdigit():
            self.levels.append(int(tag[1]))


class _FormControlCollector(HTMLParser):
    """Collect every form control + every <label for=> target.

    A control passes if it:
      - carries `aria-label` / `aria-labelledby`, OR
      - is wrapped by an ancestor ``<label>`` (the implicit-label
        pattern -- valid per WCAG 2.1 SC 1.3.1 / 4.1.2), OR
      - some ``<label for>`` somewhere on the page targets its ``id``.

    We intentionally ignore ``type=hidden`` / ``type=submit`` /
    ``type=button`` / ``type=image`` / ``type=reset`` (the first
    carries no UI, the rest have visible button text).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.controls: list[tuple[str, dict[str, str], bool]] = []
        self.label_targets: set[str] = set()
        self._label_depth = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "label":
            self._label_depth += 1
            target = a.get("for")
            if target:
                self.label_targets.add(target)
        elif tag in {"input", "select", "textarea"}:
            t = a.get("type", "").lower()
            if tag == "input" and t in {"hidden", "submit", "button",
                                            "image", "reset"}:
                return
            self.controls.append((tag, a, self._label_depth > 0))

    def handle_endtag(self, tag):
        if tag == "label" and self._label_depth > 0:
            self._label_depth -= 1


class _TabindexCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.bad_values: list[str] = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k == "tabindex" and v is not None:
                try:
                    if int(v) > 0:
                        self.bad_values.append(v)
                except ValueError:
                    self.bad_values.append(v)


class _ButtonCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.untyped_buttons: list[dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "button":
            return
        a = {k: (v or "") for k, v in attrs}
        if not a.get("type"):
            self.untyped_buttons.append(a)


class _TableCollector(HTMLParser):
    """Track every <table> -> does it have <caption> and are its <th>
    cells scoped?"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[dict] = []
        self.tables: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "table":
            entry = {
                "attrs": a,
                "has_caption": False,
                "th_total": 0,
                "th_scoped": 0,
            }
            self._stack.append(entry)
            self.tables.append(entry)
        elif self._stack:
            top = self._stack[-1]
            if tag == "caption":
                top["has_caption"] = True
            elif tag == "th":
                top["th_total"] += 1
                if a.get("scope") in {"col", "row", "colgroup",
                                         "rowgroup"}:
                    top["th_scoped"] += 1

    def handle_endtag(self, tag):
        if tag == "table" and self._stack:
            self._stack.pop()


# ------------------------------- the matrix ----------------------------------


def _route_params(app):
    """Indirection so the matrix-as-test_id renders nicely in pytest."""
    return [
        pytest.param(url, id=f"{endpoint}::{url}")
        for endpoint, url in _iter_html_routes(app)
    ]


# We need a session-scoped app for parametrisation -- pytest evaluates
# the parametrize decorator at collection time, so we build a one-shot
# throwaway app *just* to enumerate routes. The fixture-backed `smoke_app`
# is what tests actually hit (so the project file is per-tmp).
def _collect_route_ids() -> list:
    # We build a one-shot app *just* to enumerate routes for pytest's
    # parametrize machinery (which runs at collection time, before any
    # fixture exists). On Windows the SQLite connection keeps the .rlr
    # file open, so a TemporaryDirectory().cleanup() would raise
    # PermissionError; we deliberately leak the temp dir -- it's a
    # handful of KB per test run and the OS cleans %TEMP%.
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="reqlore-phase2-collect-"))
    app = create_app(tmp / "collect.rlr", Settings(), proxy=None)
    return _route_params(app)


_ROUTES = _collect_route_ids()


@pytest.mark.parametrize("url", _ROUTES)
def test_page_has_exactly_one_h1(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _HeadingCollector()
    collector.feed(html)
    h1s = [lvl for lvl in collector.levels if lvl == 1]
    assert len(h1s) == 1, (
        f"{url}: expected exactly one <h1>, found {len(h1s)} "
        f"(heading sequence: {collector.levels})"
    )


@pytest.mark.parametrize("url", _ROUTES)
def test_page_does_not_skip_heading_levels(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _HeadingCollector()
    collector.feed(html)
    levels = collector.levels
    if not levels:
        pytest.skip(f"{url} has no headings")
    seen_max = levels[0]
    for lvl in levels[1:]:
        if lvl > seen_max + 1:
            pytest.fail(
                f"{url}: heading sequence {levels} jumps from "
                f"h{seen_max} to h{lvl} (would mute SR outline)"
            )
        seen_max = max(seen_max, lvl)


@pytest.mark.parametrize("url", _ROUTES)
def test_page_has_base_landmarks(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    assert 'class="skip-link" href="#main"' in html, (
        f"{url}: missing skip-to-main-content link"
    )
    assert 'id="main"' in html and 'tabindex="-1"' in html, (
        f"{url}: <main id=\"main\" tabindex=\"-1\"> missing"
    )
    assert 'aria-live="polite"' in html, (
        f"{url}: polite live region missing -- SR announcements "
        f"would have nowhere to land"
    )
    assert 'aria-live="assertive"' not in html, (
        f"{url}: aria-live=\"assertive\" interrupts SR speech and "
        f"is banned by ACCESSIBILITY.md"
    )


@pytest.mark.parametrize("url", _ROUTES)
def test_every_form_control_has_a_label(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _FormControlCollector()
    collector.feed(html)
    unlabelled: list[str] = []
    for tag, attrs, wrapped in collector.controls:
        cid = attrs.get("id", "")
        if attrs.get("aria-label") or attrs.get("aria-labelledby"):
            continue
        if wrapped:
            continue
        if cid and cid in collector.label_targets:
            continue
        unlabelled.append(
            f"<{tag} name={attrs.get('name', '?')!r} "
            f"id={cid!r} type={attrs.get('type', '')!r}>"
        )
    assert not unlabelled, (
        f"{url}: form control(s) missing a label / aria-label:\n  "
        + "\n  ".join(unlabelled)
    )


@pytest.mark.parametrize("url", _ROUTES)
def test_page_has_no_positive_tabindex(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _TabindexCollector()
    collector.feed(html)
    assert not collector.bad_values, (
        f"{url}: tabindex > 0 found ({collector.bad_values}); the "
        f"natural document order is the only safe tab order"
    )


@pytest.mark.parametrize("url", _ROUTES)
def test_every_button_has_an_explicit_type(smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _ButtonCollector()
    collector.feed(html)
    if collector.untyped_buttons:
        descs = [
            f"<button class={a.get('class', '')!r} "
            f"name={a.get('name', '')!r}>"
            for a in collector.untyped_buttons
        ]
        pytest.fail(
            f"{url}: <button> without type= (defaults to submit, "
            f"a common a11y bug inside non-trivial forms):\n  "
            + "\n  ".join(descs)
        )


@pytest.mark.parametrize("url", _ROUTES)
def test_every_table_has_caption_and_scoped_headers(
        smoke_app, url: str) -> None:
    html = _fetch_html(smoke_app.test_client(), url)
    if html is None:
        pytest.skip(f"{url} did not return HTML")
    collector = _TableCollector()
    collector.feed(html)
    if not collector.tables:
        pytest.skip(f"{url} has no <table>")
    failures: list[str] = []
    for idx, t in enumerate(collector.tables):
        if not t["has_caption"]:
            failures.append(f"table #{idx}: missing <caption>")
        # A header-less table is presentational; we only require scope
        # when there *are* <th> cells.
        if t["th_total"] and t["th_scoped"] != t["th_total"]:
            failures.append(
                f"table #{idx}: {t['th_total'] - t['th_scoped']} of "
                f"{t['th_total']} <th> cells missing scope="
            )
    assert not failures, f"{url}:\n  " + "\n  ".join(failures)
