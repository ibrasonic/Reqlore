"""A.6 CLI parity: `reqlore finding` and `reqlore suppression` subcommands."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reqlore.cli import build_parser, main
from reqlore.storage import Project


# ---------------- parser surface ----------------


def _parse(*argv: str):
    return build_parser().parse_args(list(argv))


def test_finding_subcommand_recognised():
    ns = _parse("finding", "list", "--project", "x.rlr")
    assert ns.subcommand == "finding"
    assert ns.finding_action == "list"


def test_finding_add_requires_title_severity_project():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["finding", "add"])


def test_finding_triage_args_parse():
    ns = _parse("finding", "triage", "--project", "x.rlr",
                "--id", "7", "--status", "false_positive",
                "--reason", "client accepts risk")
    assert ns.finding_action == "triage"
    assert ns.id == 7
    assert ns.status == "false_positive"
    assert ns.reason == "client accepts risk"


def test_suppression_subcommand_recognised():
    ns = _parse("suppression", "list", "--project", "x.rlr")
    assert ns.subcommand == "suppression"
    assert ns.suppression_action == "list"


def test_suppression_add_args_parse():
    ns = _parse("suppression", "add", "--project", "x.rlr",
                "--rule-id", "passive:hsts-missing",
                "--host", "*.example.com",
                "--url-pattern", "/api/",
                "--reason", "accepted")
    assert ns.rule_id == "passive:hsts-missing"
    assert ns.host == "*.example.com"
    assert ns.url_pattern == "/api/"
    assert ns.reason == "accepted"


# ---------------- finding add ----------------


def test_finding_add_creates_row_via_bus(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()  # initialise
    rc = main([
        "finding", "add", "--project", str(proj_path),
        "--severity", "high",
        "--title", "IDOR in /accounts",
        "--cwe", "CWE-639",
        "--host", "vt.test",
        "--url", "https://vt.test/accounts/7",
        "--evidence", "GET /accounts/7 -> 200 (foreign account)",
        "--remediation", "Authorise the requested object",
        "--reference", "https://owasp.org/x, https://example.com/y",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Recorded finding" in captured.out
    assert "manual:idor-in-accounts" in captured.out

    proj = Project(proj_path)
    try:
        rows = proj.list_findings()
        assert len(rows) == 1
        row = rows[0]
        assert row["source"] == "manual"
        assert row["rule_id"] == "manual:idor-in-accounts"
        assert row["cwe"] == "CWE-639"
        assert row["references"] == [
            "https://owasp.org/x", "https://example.com/y",
        ]
    finally:
        proj.close()


def test_finding_add_explicit_rule_id_wins(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()
    rc = main([
        "finding", "add", "--project", str(proj_path),
        "--severity", "low", "--title", "anything",
        "--rule-id", "manual:custom-id",
    ])
    assert rc == 0
    proj = Project(proj_path)
    try:
        assert proj.list_findings()[0]["rule_id"] == "manual:custom-id"
    finally:
        proj.close()


def test_finding_add_rejects_unknown_severity(tmp_path: Path):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()
    # argparse's choices= validation fires before our handler runs and exits
    # with code 2 via SystemExit.
    with pytest.raises(SystemExit) as exc:
        main([
            "finding", "add", "--project", str(proj_path),
            "--severity", "boom", "--title", "x",
        ])
    assert exc.value.code == 2


# ---------------- finding list ----------------


def test_finding_list_table_and_json(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    proj = Project(proj_path)
    proj.add_finding(severity="high", title="A", host="h", url="https://h/",
                      evidence="e", rule_id="passive:a")
    proj.add_finding(severity="low", title="B", host="h", url="https://h/",
                      evidence="e2", rule_id="passive:b")
    proj.close()

    rc = main(["finding", "list", "--project", str(proj_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "passive:a" in out and "passive:b" in out
    assert "title" in out  # header row

    rc = main(["finding", "list", "--project", str(proj_path),
                "--severity", "high", "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "passive:a"


# ---------------- finding triage ----------------


def test_finding_triage_false_positive_creates_suppression(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    proj = Project(proj_path)
    fid = proj.add_finding(severity="medium", title="T", host="vt.test",
                            url="https://vt.test/a", evidence="ev",
                            rule_id="passive:foo")
    proj.close()

    rc = main(["finding", "triage", "--project", str(proj_path),
                "--id", str(fid), "--status", "false_positive",
                "--reason", "accepted"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "false_positive" in out
    assert "suppression added" in out

    proj = Project(proj_path)
    try:
        assert proj.get_finding(fid)["status"] == "false_positive"
        sups = proj.list_finding_suppressions()
        assert any(s["rule_id"] == "passive:foo" and s["reason"] == "accepted"
                    for s in sups)
    finally:
        proj.close()


def test_finding_triage_other_status_does_not_suppress(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    proj = Project(proj_path)
    fid = proj.add_finding(severity="medium", title="T", host="h",
                            url="https://h/", evidence="ev",
                            rule_id="passive:bar")
    proj.close()

    rc = main(["finding", "triage", "--project", str(proj_path),
                "--id", str(fid), "--status", "triaged"])
    assert rc == 0
    proj = Project(proj_path)
    try:
        assert proj.get_finding(fid)["status"] == "triaged"
        assert proj.list_finding_suppressions() == []
    finally:
        proj.close()


def test_finding_triage_unknown_id_fails(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()
    rc = main(["finding", "triage", "--project", str(proj_path),
                "--id", "999", "--status", "open"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


# ---------------- finding import ----------------


def test_finding_import_bulk_via_bus(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()

    src = tmp_path / "import.json"
    src.write_text(json.dumps({
        "findings": [
            {"severity": "high", "title": "Imported A",
             "host": "h", "url": "https://h/a", "evidence": "e1"},
            {"severity": "low", "title": "Imported B",
             "rule_id": "external:my-rule", "host": "h",
             "url": "https://h/b", "evidence": "e2"},
            {"severity": "INVALID", "title": "bad"},  # rejected
            {"title": "no severity"},  # rejected
        ],
    }), encoding="utf-8")

    rc = main(["finding", "import", "--project", str(proj_path), str(src)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Imported 2 findings" in out
    assert "2 rejected" in out

    proj = Project(proj_path)
    try:
        rows = proj.list_findings()
        rule_ids = {r["rule_id"] for r in rows}
        assert "manual:imported-a" in rule_ids
        assert "external:my-rule" in rule_ids
    finally:
        proj.close()


def test_finding_import_accepts_plain_list(tmp_path: Path):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()
    src = tmp_path / "list.json"
    src.write_text(json.dumps([
        {"severity": "info", "title": "x", "host": "h",
         "url": "https://h/", "evidence": "e"},
    ]), encoding="utf-8")
    rc = main(["finding", "import", "--project", str(proj_path), str(src)])
    assert rc == 0


def test_finding_import_rejects_non_json(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()
    src = tmp_path / "bad.json"
    src.write_text("not json", encoding="utf-8")
    rc = main(["finding", "import", "--project", str(proj_path), str(src)])
    assert rc == 2
    assert "invalid JSON" in capsys.readouterr().err


# ---------------- suppression CLI ----------------


def test_suppression_add_list_delete(tmp_path: Path, capsys):
    proj_path = tmp_path / "p.rlr"
    Project(proj_path).close()

    rc = main(["suppression", "add", "--project", str(proj_path),
                "--rule-id", "passive:hsts-missing",
                "--host", "vt.test", "--reason", "client accepts"])
    assert rc == 0
    assert "Suppression added" in capsys.readouterr().out

    rc = main(["suppression", "list", "--project", str(proj_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "passive:hsts-missing" in out
    assert "vt.test" in out
    assert "client accepts" in out

    rc = main(["suppression", "list", "--project", str(proj_path),
                "--format", "json"])
    assert rc == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "passive:hsts-missing"

    rc = main(["suppression", "delete", "--project", str(proj_path),
                "--rule-id", "passive:hsts-missing", "--host", "vt.test"])
    assert rc == 0
    assert "Suppression removed" in capsys.readouterr().out

    rc = main(["suppression", "list", "--project", str(proj_path)])
    assert rc == 0
    assert "(no suppressions)" in capsys.readouterr().out


def test_suppression_add_rejects_missing_rule_id():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["suppression", "add", "--project", "x.rlr"])
