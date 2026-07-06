"""Phase 3 of [RELIABILITY_PLAN](../../../../docs/RELIABILITY_PLAN.md):
screen-reader semantics matrix.

Where Phase 2 covered the *visible* HTML structure (one h1, scoped
table headers, etc.), this phase covers the *audible* one: ARIA
attributes that drive what NVDA / Orca / VoiceOver actually announce.

Two complementary surfaces:

  - Static template scan. ARIA attributes live in the templates we
    ship; they don't depend on runtime state. Walking every
    ``reqlore/web/templates/**/*.html`` catches violations that the
    GET matrix would miss because the page only renders the
    offending block on a state we cannot easily exercise from a
    test client (e.g. server-side validation errors).
  - GET matrix. Per-page checks that need a rendered page
    (accesskey collision is template-state-dependent because Jinja
    loops can multiply attributes).

Six checks per the plan; we collapse "no aria-live=assertive" and
"role=dialog must carry aria-modal" into the static scan because
both are pure attribute audits.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app

_TEMPLATES_ROOT = (Path(__file__).resolve().parents[2]
                    / "web" / "templates")


def _iter_templates() -> list[Path]:
    return sorted(_TEMPLATES_ROOT.rglob("*.html"))


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


# ----------------------- 1. No aria-live="assertive" -------------------------


_ASSERTIVE_RE = re.compile(
    r"""aria-live\s*=\s*["']\s*assertive\s*["']""", re.IGNORECASE,
)


@pytest.mark.parametrize("template",
                          [pytest.param(p, id=str(p.relative_to(
                              _TEMPLATES_ROOT)))
                           for p in _iter_templates()])
def test_template_does_not_use_assertive_live_region(
        template: Path) -> None:
    """``aria-live="assertive"`` interrupts SR speech mid-sentence and
    is banned by docs/ACCESSIBILITY.md. ``role="alert"`` already
    implies a polite-but-prompt announcement; pairing it with
    ``aria-live="assertive"`` is double-loud and disorienting."""
    text = _read(template)
    matches = _ASSERTIVE_RE.findall(text)
    assert not matches, (
        f"{template.relative_to(_TEMPLATES_ROOT)}: "
        f"aria-live=\"assertive\" is banned (interrupts SR speech). "
        f"Use role=\"alert\" alone or aria-live=\"polite\"."
    )


# ----------------------- 2. <progress> carries aria-valuetext ---------------


class _ProgressCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.bare_progress: list[dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "progress":
            return
        a = {k: (v or "") for k, v in attrs}
        if not a.get("aria-valuetext", "").strip():
            self.bare_progress.append(a)


@pytest.mark.parametrize("template",
                          [pytest.param(p, id=str(p.relative_to(
                              _TEMPLATES_ROOT)))
                           for p in _iter_templates()])
def test_progress_elements_carry_aria_valuetext(template: Path) -> None:
    """A bare ``<progress value="142" max="500">`` makes SRs announce
    only "75%". ``aria-valuetext`` is required so the operator hears
    "Sent 142 of 500 requests" instead."""
    collector = _ProgressCollector()
    collector.feed(_read(template))
    if not collector.bare_progress:
        pytest.skip("template has no <progress>")
    descs = [
        f"<progress id={a.get('id', '')!r} "
        f"aria-label={a.get('aria-label', '')!r}>"
        for a in collector.bare_progress
    ]
    pytest.fail(
        f"{template.relative_to(_TEMPLATES_ROOT)}: "
        f"<progress> without aria-valuetext (SRs would announce "
        f"only the percentage):\n  " + "\n  ".join(descs)
    )


# ----------------------- 3. role="dialog" hygiene ---------------------------


class _DialogCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.broken_dialogs: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if a.get("role") != "dialog":
            return
        problems: list[str] = []
        if a.get("aria-modal", "").lower() != "true":
            problems.append("missing aria-modal=\"true\"")
        if not (a.get("aria-labelledby") or a.get("aria-label")):
            problems.append("missing aria-labelledby/aria-label")
        if problems:
            self.broken_dialogs.append(
                f"<{tag} role=\"dialog\">: " + ", ".join(problems)
            )


@pytest.mark.parametrize("template",
                          [pytest.param(p, id=str(p.relative_to(
                              _TEMPLATES_ROOT)))
                           for p in _iter_templates()])
def test_dialog_roles_are_modal_and_labelled(template: Path) -> None:
    """Every ``role="dialog"`` must carry ``aria-modal="true"`` and a
    label. Missing either makes SRs announce the dialog as a generic
    landmark and ignore the title -- the user has no idea what
    interrupted them."""
    collector = _DialogCollector()
    collector.feed(_read(template))
    if not collector.broken_dialogs:
        pytest.skip("template has no role=\"dialog\"")
    pytest.fail(
        f"{template.relative_to(_TEMPLATES_ROOT)}:\n  "
        + "\n  ".join(collector.broken_dialogs)
    )


# --------------- 4. aria-invalid is paired with aria-describedby ------------


_ARIA_INVALID_RE = re.compile(
    r"""aria-invalid\s*=\s*["']\s*true\s*["']""", re.IGNORECASE,
)
_ARIA_DESCRIBEDBY_RE = re.compile(
    r"""aria-describedby\s*=\s*["']""", re.IGNORECASE,
)


@pytest.mark.parametrize("template",
                          [pytest.param(p, id=str(p.relative_to(
                              _TEMPLATES_ROOT)))
                           for p in _iter_templates()])
def test_aria_invalid_pairs_with_describedby(template: Path) -> None:
    """When a field carries ``aria-invalid="true"``, an
    ``aria-describedby`` must point at the inline error message, or
    SRs announce "invalid" with no explanation. We assert at the
    template level (per file) rather than per-element because the
    error span is sometimes rendered by a sibling block."""
    text = _read(template)
    if not _ARIA_INVALID_RE.search(text):
        pytest.skip("template has no aria-invalid")
    assert _ARIA_DESCRIBEDBY_RE.search(text), (
        f"{template.relative_to(_TEMPLATES_ROOT)}: aria-invalid "
        f"present but no aria-describedby anywhere on the page; "
        f"SRs would say 'invalid' with no explanation."
    )


# --------------- 5. Per-page accesskey uniqueness (GET matrix) --------------


_RULE_ENDPOINT_SKIPS: frozenset[str] = frozenset({
    "static",
    "saml_bp.acs_metadata",
    "auth.login",
    "comparer.export_diff",
})


@pytest.fixture(scope="module")
def smoke_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("reliability_phase3")
    return create_app(tmp / "phase3.rlr", Settings(), proxy=None)


def _iter_html_routes(app):
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


def _collect_routes() -> list:
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="reqlore-phase3-collect-"))
    app = create_app(tmp / "collect.rlr", Settings(), proxy=None)
    return [pytest.param(url, id=f"{ep}::{url}")
            for ep, url in _iter_html_routes(app)]


_ROUTES = _collect_routes()


class _AccesskeyCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.keys: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k == "accesskey" and v:
                self.keys.append((tag, v.lower()))


@pytest.mark.parametrize("url", _ROUTES)
def test_accesskey_letters_are_unique_per_page(
        smoke_app, url: str) -> None:
    """Two elements claiming the same ``accesskey`` is a silent dead
    letter -- the browser activates only one and SR users have no
    way to know which. We allow base-template nav to share letters
    *with itself* (it appears once per page), so we just check for
    duplicates on the rendered page."""
    resp = smoke_app.test_client().get(url)
    if resp.status_code not in (200, 401):
        pytest.skip(f"{url} -> {resp.status_code}")
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "html" not in ctype:
        pytest.skip(f"{url} not text/html")
    collector = _AccesskeyCollector()
    collector.feed(resp.data.decode("utf-8", errors="replace"))
    seen: dict[str, list[str]] = {}
    for tag, letter in collector.keys:
        seen.setdefault(letter, []).append(tag)
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    assert not dupes, (
        f"{url}: accesskey collision -- {dupes}. Two elements with "
        f"the same letter means the browser activates only one and "
        f"SR users can't tell which."
    )


# ---------- 6. data-dense tables advertise a "Read as list" companion ------


class _DenseTableCollector(HTMLParser):
    """Find every ``<table data-dense>`` and verify the sibling
    template has *some* "Read as list" affordance (a ``<details>``
    block, a button with text containing "list", or a link with the
    same)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.dense_tables = 0
        self.list_affordances = 0
        self._collecting_button: bool = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "table" and "data-dense" in a:
            self.dense_tables += 1
        if tag == "details":
            self.list_affordances += 1
        if tag in {"button", "a"}:
            self._collecting_button = True
            self._buf = []

    def handle_data(self, data):
        if self._collecting_button:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag in {"button", "a"} and self._collecting_button:
            text = "".join(self._buf).lower()
            if "read as list" in text or "list view" in text:
                self.list_affordances += 1
            self._collecting_button = False
            self._buf = []


@pytest.mark.parametrize("url", _ROUTES)
def test_dense_tables_offer_a_read_as_list_alternative(
        smoke_app, url: str) -> None:
    """Tables marked ``data-dense`` are hostile in screen-reader
    table-navigation mode. The plan requires a "Read as list"
    affordance somewhere on the page. Vacuous on pages that don't
    use the opt-in attribute -- this test starts catching bugs the
    moment the first dense table is added."""
    resp = smoke_app.test_client().get(url)
    if resp.status_code not in (200, 401):
        pytest.skip(f"{url} -> {resp.status_code}")
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "html" not in ctype:
        pytest.skip(f"{url} not text/html")
    collector = _DenseTableCollector()
    collector.feed(resp.data.decode("utf-8", errors="replace"))
    if collector.dense_tables == 0:
        pytest.skip(f"{url} has no data-dense tables")
    assert collector.list_affordances > 0, (
        f"{url} renders {collector.dense_tables} data-dense table(s) "
        f"but no <details> / 'Read as list' button -- SR users would "
        f"have no escape from table-navigation mode."
    )
