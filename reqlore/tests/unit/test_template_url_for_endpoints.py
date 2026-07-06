"""Static lint: every url_for('endpoint.name') in templates must resolve.

Catches the bug class where a template references a Flask endpoint that
doesn't exist (e.g. `history.detail` when the real name is `history.show`),
which only blows up at request time inside a conditional branch.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app

# Match url_for('endpoint.name'  or  url_for("endpoint.name"
_URL_FOR_RE = re.compile(r"""url_for\(\s*['"]([a-zA-Z_][a-zA-Z0-9_.]*)['"]""")


def _templates_root() -> Path:
    return Path(__file__).resolve().parents[2] / "web" / "templates"


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "lint.rlr", Settings(), proxy=None)


def test_all_template_url_for_endpoints_exist(app):
    known = set(app.url_map._rules_by_endpoint.keys())
    bad: list[tuple[str, int, str]] = []
    for tpl in _templates_root().rglob("*.html"):
        text = tpl.read_text(encoding="utf-8", errors="replace")
        for m in _URL_FOR_RE.finditer(text):
            endpoint = m.group(1)
            # `static` is the global builtin; also allow blueprint-scoped statics.
            if endpoint == "static" or endpoint.endswith(".static"):
                continue
            if endpoint not in known:
                line = text.count("\n", 0, m.start()) + 1
                bad.append((str(tpl.relative_to(_templates_root())), line, endpoint))
    assert not bad, (
        "Unknown Flask endpoints referenced in templates:\n  "
        + "\n  ".join(f"{p}:{ln}  url_for({ep!r})" for p, ln, ep in bad)
    )
