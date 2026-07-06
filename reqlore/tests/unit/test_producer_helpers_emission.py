"""A.1 verification: ad-hoc producer helpers (saml, sequencer, smuggling,
graphql, oast) all flow through the unified findings ledger."""
from __future__ import annotations

from pathlib import Path

from reqlore.storage import Project


def _new(tmp_path: Path, name: str) -> Project:
    return Project(tmp_path / f"{name}.rlr")


# --------------------------------------------------------------------- SAML
def test_saml_helper_writes_findings(tmp_path: Path):
    from reqlore import saml
    p = _new(tmp_path, "saml")
    insp = saml.SAMLInspection(findings=[
        saml.SAMLFinding(severity="high",
                          title="SAML message is not signed",
                          detail="no Signature element"),
        saml.SAMLFinding(severity="medium",
                          title="Weak cryptographic algorithm: SHA1",
                          detail="rsa-sha1 in use"),
        saml.SAMLFinding(severity="medium",
                          title="No AudienceRestriction",
                          detail=""),
    ])
    ids = saml.record_saml_findings(p, insp, host="idp.example.com",
                                      url="https://idp.example.com/SSO")
    assert len(ids) == 3
    rows = {r["rule_id"]: r for r in p.list_findings()}
    assert "saml:unsigned" in rows
    assert "saml:weak-algo" in rows
    assert "saml:no-audience" in rows
    assert rows["saml:unsigned"]["severity"] == "high"
    assert rows["saml:weak-algo"]["cwe"] == "CWE-327"


# ------------------------------------------------------------- Sequencer
def test_sequencer_weak_emits_finding(tmp_path: Path):
    from reqlore import sequencer
    p = _new(tmp_path, "seq")
    # Build deterministic weak tokens (counter-style 1-character delta).
    tokens = [f"AAAA{i:04d}" for i in range(40)]
    result = sequencer.analyse(tokens)
    fid = sequencer.record_sequencer_finding(p, result,
                                               url="https://app/login")
    assert fid is not None
    row = p.get_finding(fid)
    assert row is not None
    assert row["rule_id"] == "sequencer:low-entropy"
    assert row["cwe"] == "CWE-330"


def test_sequencer_strong_records_skip(tmp_path: Path):
    import secrets

    from reqlore import sequencer
    p = _new(tmp_path, "seqstrong")
    # Use a wide alphabet (~6 bits/char) so the analyser lands in
    # "good"/"excellent" — token_hex only yields ~4 bits/char.
    tokens = [secrets.token_urlsafe(48) for _ in range(64)]
    result = sequencer.analyse(tokens)
    assert result.rating in ("good", "excellent")
    fid = sequencer.record_sequencer_finding(p, result,
                                               url="https://app/login")
    assert fid is None
    assert p.list_findings() == []
    summary = {r["rule_id"]: r for r in p.rule_run_summary()}
    row = summary.get("sequencer:low-entropy")
    assert row is not None
    assert row["fired"] == 0
    assert row["evaluated"] >= 1


# ------------------------------------------------------------- Smuggling
def test_smuggling_helper_writes_finding(tmp_path: Path):
    from reqlore import smuggling
    p = _new(tmp_path, "sm")
    test = smuggling.SmugglingTest(
        technique="cl.te", baseline_ms=100, probe_ms=1900,
        delta_ms=1800, likely_vulnerable=True,
        reason="probe took 1900 ms vs baseline 100 ms (delta 1800 ms)")
    fid = smuggling.record_smuggling_test(p, test, url="https://t/")
    assert fid is not None
    row = p.get_finding(fid)
    assert row is not None
    assert row["rule_id"] == "smuggling:cl.te"
    assert row["severity"] == "critical"
    assert row["cwe"] == "CWE-444"


def test_smuggling_negative_records_skip(tmp_path: Path):
    from reqlore import smuggling
    p = _new(tmp_path, "smneg")
    test = smuggling.SmugglingTest(
        technique="cl.te", baseline_ms=100, probe_ms=120,
        delta_ms=20, likely_vulnerable=False, reason="no delta")
    fid = smuggling.record_smuggling_test(p, test, url="https://t/")
    assert fid is None
    assert p.list_findings() == []


# ---------------------------------------------------------------- GraphQL
def test_graphql_introspection_helper(tmp_path: Path):
    from reqlore import graphql
    p = _new(tmp_path, "gql")
    introspection = {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"kind": "OBJECT", "name": "Query"},
            {"kind": "OBJECT", "name": "User"},
            {"kind": "SCALAR", "name": "String"},
        ],
    }}}
    fid = graphql.record_introspection_finding(p, introspection,
                                                  url="https://api/graphql")
    assert fid is not None
    row = p.get_finding(fid)
    assert row is not None
    assert row["rule_id"] == "graphql:introspection-enabled"
    assert row["severity"] == "medium"
    assert "3 types" in row["evidence"]


def test_graphql_introspection_disabled(tmp_path: Path):
    from reqlore import graphql
    p = _new(tmp_path, "gqloff")
    fid = graphql.record_introspection_finding(p, {"errors": ["nope"]},
                                                  url="https://api/graphql")
    assert fid is None
    assert p.list_findings() == []


# ------------------------------------------------------------------- OAST
def test_oast_helper_emits_finding_per_interaction(tmp_path: Path):
    from reqlore import oast
    p = _new(tmp_path, "oast")
    ixs = [
        oast.Interaction(ts_ms=1, token="abc123", kind="http",  # noqa: S106  # test fixture OAST token, not a real credential
                          remote="10.0.0.5", method="GET",
                          path="/abc123/x", bytes_in=12),
        oast.Interaction(ts_ms=2, token="abc123", kind="http",  # noqa: S106  # test fixture OAST token, not a real credential
                          remote="10.0.0.6", method="POST",
                          path="/abc123/y", bytes_in=24),
    ]
    ids = oast.record_oast_interactions(p, ixs,
                                          probe_url="https://t/?u=RLRCOL",
                                          probe_host="t",
                                          probe_kind="ssrf")
    assert len(ids) == 2
    rows = p.list_findings()
    assert all(r["rule_id"] == "oast:ssrf-callback" for r in rows)
    assert all(r["severity"] == "high" for r in rows)


def test_oast_helper_no_interactions(tmp_path: Path):
    from reqlore import oast
    p = _new(tmp_path, "oastempty")
    ids = oast.record_oast_interactions(p, [], probe_url="https://t/",
                                          probe_kind="ssrf")
    assert ids == []
    assert p.list_findings() == []
