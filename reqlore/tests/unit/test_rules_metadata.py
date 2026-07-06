"""A.2 verification: every built-in rule / check carries a valid RuleMeta and
the engine uses it to derive ``rule_id`` consistently."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from reqlore.scanner.active import BUILTIN_ACTIVE_CHECKS
from reqlore.scanner.findings import Finding
from reqlore.scanner.passive import BUILTIN_RULES
from reqlore.scanner.rules import (
    SEVERITIES,
    RuleMeta,
    apply_meta_defaults,
    id_for,
    legacy_rule_id,
    meta_for,
    rule_meta,
)


# --------------------------------------------------------- RuleMeta itself
def test_valid_meta_constructs():
    meta = RuleMeta(
        id="passive:foo",
        title="Foo",
        default_severity="medium",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description="Detects foo.",
        remediation="Stop fooing.",
        references=("https://example/cwe-79",),
        tags=("foo", "bar"),
    )
    assert meta.id == "passive:foo"
    assert meta.references == ("https://example/cwe-79",)


@pytest.mark.parametrize("bad_id", [
    "no_colon",
    "BadSource:foo",
    "passive:",
    ":foo",
    "passive:foo bar",   # space
])
def test_invalid_id_rejected(bad_id):
    with pytest.raises(ValueError):
        RuleMeta(id=bad_id, title="x")


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        RuleMeta(id="passive:x", title="x", default_severity="catastrophic")


@pytest.mark.parametrize("bad_cwe", ["CWE_79", "cwe-79", "CWE-", "79"])
def test_invalid_cwe_rejected(bad_cwe):
    with pytest.raises(ValueError):
        RuleMeta(id="passive:x", title="x", cwe=bad_cwe)


def test_severity_set_matches_finding_model():
    # SEVERITIES tuple must exactly match the Finding model's accepted set.
    from reqlore.scanner.findings import CVSS_BAND
    assert set(SEVERITIES) == set(CVSS_BAND.keys())


# --------------------------------------------------- Built-in coverage
def test_every_passive_rule_has_meta():
    missing = [r.__name__ for r in BUILTIN_RULES if meta_for(r) is None]
    assert missing == [], f"passive rules without RuleMeta: {missing}"


def test_every_active_check_has_meta():
    missing = [c.__class__.__name__ for c in BUILTIN_ACTIVE_CHECKS
                if meta_for(c) is None]
    assert missing == [], f"active checks without RuleMeta: {missing}"


def test_builtin_ids_are_unique():
    ids = (
        [meta_for(r).id for r in BUILTIN_RULES]
        + [meta_for(c).id for c in BUILTIN_ACTIVE_CHECKS]
    )
    dupes = {x for x in ids if ids.count(x) > 1}
    assert not dupes, f"duplicate rule ids: {dupes}"


def test_passive_ids_use_passive_prefix():
    for r in BUILTIN_RULES:
        assert meta_for(r).id.startswith("passive:")


def test_active_ids_use_active_prefix():
    for c in BUILTIN_ACTIVE_CHECKS:
        assert meta_for(c).id.startswith("active:")


def test_active_meta_id_matches_check_name():
    for c in BUILTIN_ACTIVE_CHECKS:
        meta = meta_for(c)
        assert meta.id == f"active:{c.name}", (
            f"{c.__class__.__name__}: meta.id={meta.id!r} but name={c.name!r}")


def test_all_builtins_have_nonempty_title_description_remediation():
    for r in BUILTIN_RULES:
        m = meta_for(r)
        assert m.title and m.description and m.remediation, m.id
    for c in BUILTIN_ACTIVE_CHECKS:
        m = meta_for(c)
        assert m.title and m.description and m.remediation, m.id


def test_all_builtins_have_cwe():
    # Every built-in security finding must map to a CWE so the reporter and
    # CLI can produce a credible audit trail.
    for r in BUILTIN_RULES:
        m = meta_for(r)
        assert re.match(r"^CWE-\d+$", m.cwe), (m.id, m.cwe)
    for c in BUILTIN_ACTIVE_CHECKS:
        m = meta_for(c)
        assert re.match(r"^CWE-\d+$", m.cwe), (m.id, m.cwe)


# ----------------------------------------------- id_for / legacy fallback
def test_id_for_prefers_meta():
    @rule_meta(RuleMeta(id="passive:explicit", title="x"))
    def some_rule(ctx):
        return []
    assert id_for(some_rule, prefix="passive") == "passive:explicit"


def test_id_for_falls_back_to_synthesis_for_undecorated():
    def rule_no_meta(ctx):
        return []
    assert id_for(rule_no_meta, prefix="passive") == "passive:no_meta"


def test_legacy_rule_id_uses_class_name_attribute():
    class FakeCheck:
        name = "fake-check"
    assert legacy_rule_id(FakeCheck(), prefix="active") == "active:fake-check"


# ------------------------------------------------ apply_meta_defaults
def test_apply_meta_defaults_fills_empties_only():
    meta = RuleMeta(id="passive:demo", title="Demo",
                     default_severity="medium",
                     cwe="CWE-79", owasp="A03:2021-Injection",
                     remediation="default remediation",
                     references=("https://default.example",))
    f = Finding(severity="high", title="t", cwe="", owasp="",
                 remediation="", references=[])
    apply_meta_defaults(f, meta)
    assert f.cwe == "CWE-79"
    assert f.owasp == "A03:2021-Injection"
    assert f.remediation == "default remediation"
    assert f.references == ["https://default.example"]


def test_apply_meta_defaults_does_not_overwrite_set_fields():
    meta = RuleMeta(id="passive:demo", title="Demo",
                     default_severity="medium", cwe="CWE-79",
                     remediation="DEFAULT")
    f = Finding(severity="high", title="t", cwe="CWE-999",
                 remediation="EXPLICIT")
    apply_meta_defaults(f, meta)
    assert f.cwe == "CWE-999"
    assert f.remediation == "EXPLICIT"


def test_apply_meta_defaults_no_meta_is_noop():
    f = Finding(severity="low", title="t", cwe="")
    out = apply_meta_defaults(f, None)
    assert out is f
    assert f.cwe == ""


# ------------------- End-to-end: scanner uses the canonical id
def test_engine_emits_using_meta_id(tmp_path: Path, monkeypatch):
    """A passive scan against a single hand-built history row writes findings
    whose rule_id matches the corresponding RuleMeta.id."""
    from reqlore.scanner.engine import Scanner
    from reqlore.storage import Project

    p = Project(tmp_path / "meta_e2e.rlr")
    # Build a request/response that triggers the security-headers rule.
    raw_req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: pytest\r\n\r\n"
    )
    raw_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html></html>"
    )
    p.add_history(host="example.test", method="GET",
                    url="https://example.test/", status=200,
                    duration_ms=10, engine="test",
                    raw_req=raw_req, raw_resp=raw_resp, tags="")
    Scanner().scan_project(p, limit=10)
    rule_ids = {f["rule_id"] for f in p.list_findings()}
    assert "passive:missing_security_headers" in rule_ids
    assert "passive:xframe_options" in rule_ids
