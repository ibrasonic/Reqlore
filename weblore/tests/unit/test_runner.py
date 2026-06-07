"""Phase 5 - CLI runner: YAML/JSON job execution."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from weblore.engines import Response
from weblore.runner import YAML_AVAILABLE, load_job, run_job
from weblore.storage import Project


@pytest.fixture
def project(tmp_path: Path):
    p = Project(tmp_path / "runner.weblore")
    yield p
    p.close()


def test_load_json_job(tmp_path: Path):
    f = tmp_path / "job.json"
    f.write_text(json.dumps([{"type": "set", "vars": {"a": 1}}]),
                  encoding="utf-8")
    steps = load_job(f)
    assert steps == [{"type": "set", "vars": {"a": 1}}]


def test_load_job_with_top_level_steps_key(tmp_path: Path):
    f = tmp_path / "job.json"
    f.write_text(json.dumps({"steps": [{"type": "sleep", "seconds": 0}]}),
                  encoding="utf-8")
    steps = load_job(f)
    assert steps == [{"type": "sleep", "seconds": 0}]


def test_set_then_assert_passes(project):
    steps = [
        {"type": "set", "vars": {"x": "42"}},
        {"type": "assert", "expr": "vars['x'] == '42'"},
    ]
    r = run_job(steps, project=project)
    assert r.ok
    assert r.steps[0].type == "set"
    assert r.steps[1].ok
    assert r.variables == {"x": "42"}


def test_assert_failure_propagates(project):
    steps = [
        {"type": "set", "vars": {"x": "1"}},
        {"type": "assert", "expr": "vars['x'] == '2'"},
    ]
    r = run_job(steps, project=project)
    assert not r.ok
    assert r.steps[1].error == "assertion failed"


def test_strict_mode_aborts_on_first_failure(project):
    steps = [
        {"type": "assert", "expr": "False"},
        {"type": "set", "vars": {"x": "1"}},
    ]
    r = run_job(steps, project=project, strict=True)
    assert r.aborted
    assert len(r.steps) == 1


def test_unknown_step_type_records_error(project):
    r = run_job([{"type": "nonesuch"}], project=project)
    assert not r.ok
    assert "supported: request" in r.steps[0].error


def test_substitution_walks_strings_and_lists(project):
    steps = [
        {"type": "set", "vars": {"who": "world"}},
        {"type": "set", "vars": {"msg": "hello {{who}}"}},
        {"type": "assert", "expr": "vars['msg'] == 'hello world'"},
    ]
    r = run_job(steps, project=project)
    assert r.ok


def test_report_step_writes_markdown(project, tmp_path: Path):
    project.add_finding(severity="high", title="X")
    out = tmp_path / "r.md"
    r = run_job([{"type": "report", "out": str(out), "format": "md"}],
                 project=project)
    assert r.ok
    text = out.read_text(encoding="utf-8")
    assert "X" in text


def test_scan_step_runs_passive_scanner(project):
    # Seed history so passive scanner has rows to inspect.
    project.add_history(
        host="x.test", method="GET", url="https://x.test/",
        status=200, duration_ms=5, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>",
    )
    r = run_job([{"type": "scan", "limit": 100}], project=project)
    assert r.ok
    assert "passive scan" in r.steps[0].summary


def test_yaml_load_requires_pyyaml(tmp_path: Path):
    f = tmp_path / "job.yaml"
    f.write_text("- type: sleep\n  seconds: 0\n", encoding="utf-8")
    if YAML_AVAILABLE:
        assert load_job(f) == [{"type": "sleep", "seconds": 0}]
    else:
        with pytest.raises(RuntimeError, match="PyYAML"):
            load_job(f)
