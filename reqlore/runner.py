"""Headless YAML/JSON job runner for ``reqlore run jobs/scan.yaml``.

Supported step types:

* ``request``   — send a request through the chosen engine and capture it
* ``scan``      — run the passive scanner over recorded history
* ``active``    — run the active scanner with chosen checks
* ``report``    — render a Markdown / HTML / DOCX report
* ``set``       — assign variables (``vars: {key: value}``)
* ``assert``    — fail the job if a Python expression on ``vars`` / last
                  response is false
* ``sleep``     — wait N seconds (rarely useful; mostly for OAST flows)

A job is a list of steps. The runner returns a ``JobResult`` with one
``StepResult`` per executed step. The ``--strict`` CLI flag makes any
non-zero step exit code abort the whole run.

YAML is optional — if PyYAML is missing the runner falls back to JSON
(``.json``), and a YAML file produces a clear error.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engines import Request
from .engines import httpx_engine
from .storage import Project

try:
    import yaml as _yaml
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False


@dataclass
class StepResult:
    index: int
    type: str
    ok: bool
    elapsed_ms: int
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class JobResult:
    steps: list[StepResult] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    aborted: bool = False

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps) and not self.aborted


def load_job(path: Path) -> list[dict[str, Any]]:
    """Read a job file (``.yaml`` / ``.yml`` / ``.json``)."""
    text = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML is required to load YAML jobs. "
                "Install it with `pip install pyyaml` or use a .json job.")
        data = _yaml.safe_load(text)
    else:
        data = json.loads(text)
    if isinstance(data, dict) and "steps" in data:
        data = data["steps"]
    if not isinstance(data, list):
        raise ValueError("Job file must be a list of steps "
                          "(or {'steps': [...]}).")
    return data


def _substitute(value: Any, vars_: dict[str, Any]) -> Any:
    """Replace ``{{var}}`` tokens in strings; recurse into dicts/lists."""
    import re
    if isinstance(value, str):
        return re.sub(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}",
                       lambda m: str(vars_.get(m.group(1), "")), value)
    if isinstance(value, list):
        return [_substitute(v, vars_) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, vars_) for k, v in value.items()}
    return value


def run_job(steps: list[dict[str, Any]], *, project: Project,
             strict: bool = False) -> JobResult:
    """Execute a parsed job against the supplied project."""
    result = JobResult()
    vars_: dict[str, Any] = {}
    last_response: Any = None
    t_total = time.perf_counter()

    for i, raw in enumerate(steps):
        if not isinstance(raw, dict) or "type" not in raw:
            sr = StepResult(index=i, type="?", ok=False,
                              elapsed_ms=0, summary="invalid step",
                              error="step must be a dict with a 'type' field")
            result.steps.append(sr)
            if strict:
                result.aborted = True
                break
            continue

        step = _substitute(raw, vars_)
        kind = str(step.get("type"))
        t0 = time.perf_counter()
        try:
            sr, last_response, vars_ = _dispatch(i, kind, step, vars_,
                                                  last_response, project)
        except Exception as exc:
            sr = StepResult(index=i, type=kind, ok=False,
                              elapsed_ms=int((time.perf_counter() - t0) * 1000),
                              summary=f"{kind} raised {type(exc).__name__}",
                              error=str(exc))
        else:
            sr.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        result.steps.append(sr)
        if not sr.ok and strict:
            result.aborted = True
            break

    result.elapsed_ms = int((time.perf_counter() - t_total) * 1000)
    result.variables = vars_
    return result


def _dispatch(i: int, kind: str, step: dict[str, Any], vars_: dict[str, Any],
              last_response: Any, project: Project
              ) -> tuple[StepResult, Any, dict[str, Any]]:
    if kind == "request":
        req = Request(
            method=str(step.get("method", "GET")).upper(),
            url=str(step["url"]),
            headers=[tuple(h) for h in step.get("headers", [])],
            body=(step.get("body", "") or "").encode() if isinstance(step.get("body"), str)
                  else (step.get("body") or b""),
        )
        resp = httpx_engine.send(req)
        last_response = resp
        sr = StepResult(index=i, type=kind, ok=(resp.status > 0),
                          elapsed_ms=0,
                          summary=f"{req.method} {req.url} -> {resp.status}",
                          detail={"status": resp.status,
                                   "bytes": len(resp.body)},
                          error=resp.error or "")
        if step.get("save_as"):
            vars_[str(step["save_as"])] = resp
        if step.get("capture"):
            for vname, spec in dict(step["capture"]).items():
                if not isinstance(spec, dict):
                    continue
                src = spec.get("source")
                if src == "header":
                    vars_[vname] = resp.header(spec.get("name", "")) or ""
                elif src == "json":
                    try:
                        obj = json.loads(resp.body.decode("utf-8", "replace"))
                        for part in str(spec.get("path", "")).split("."):
                            if part == "":
                                continue
                            if isinstance(obj, list):
                                obj = obj[int(part)]
                            else:
                                obj = obj[part]
                        vars_[vname] = str(obj)
                    except Exception:
                        vars_[vname] = ""
        # If asked, persist to history
        if step.get("save", False):
            project.add_history(
                host=req.url, method=req.method, url=req.url,
                status=resp.status, duration_ms=resp.timings.total_ms,
                engine=resp.engine,
                raw_req=b"", raw_resp=b"",
            )
        return sr, last_response, vars_

    if kind == "scan":
        from .scanner import BUILTIN_RULES, Scanner
        scanner = Scanner(rules=BUILTIN_RULES)
        sres = scanner.scan_project(project, limit=int(step.get("limit", 5000)))
        sr = StepResult(index=i, type=kind, ok=True, elapsed_ms=0,
                          summary=f"passive scan: {sres.findings_added} findings "
                                   f"over {sres.rows_scanned} rows",
                          detail={"by_severity": sres.by_severity})
        return sr, last_response, vars_

    if kind == "active":
        from .scanner.active import (ActiveOptions, ActiveScanner,
                                       BUILTIN_ACTIVE_CHECKS)
        opts = ActiveOptions(
            max_requests_per_check=int(step.get("max_per_check", 4)),
            rate_delay_ms=int(step.get("delay_ms", 0)),
            timeout_s=float(step.get("timeout_s", 10.0)),
            follow_redirects=bool(step.get("follow", False)),
            enabled_checks=tuple(step.get("checks") or ()) or None,
        )
        scanner = ActiveScanner(checks=list(BUILTIN_ACTIVE_CHECKS))
        ares = scanner.run_on_project(project,
                                       options=opts,
                                       host=step.get("host", "") or None,
                                       limit=int(step.get("limit", 50)))
        sr = StepResult(index=i, type=kind, ok=True, elapsed_ms=0,
                          summary=f"active scan: {ares.findings_added} findings "
                                   f"over {ares.rows_scanned} rows",
                          detail={"by_severity": ares.by_severity})
        return sr, last_response, vars_

    if kind == "report":
        from .reporter import (DOCX_AVAILABLE, render_docx, render_html,
                                 render_markdown)
        out = Path(str(step["out"])).expanduser().resolve()
        fmt = (step.get("format") or out.suffix.lstrip(".") or "md").lower()
        findings = project.list_findings(limit=10_000)
        meta = project.meta()
        if fmt in ("md", "markdown"):
            out.write_text(render_markdown(meta, findings), encoding="utf-8")
        elif fmt == "html":
            out.write_text(render_html(meta, findings), encoding="utf-8")
        elif fmt == "docx":
            if not DOCX_AVAILABLE:
                return (StepResult(index=i, type=kind, ok=False,
                                     elapsed_ms=0, summary="docx unavailable",
                                     error="python-docx not installed"),
                        last_response, vars_)
            out.write_bytes(render_docx(meta, findings))
        else:
            return (StepResult(index=i, type=kind, ok=False,
                                 elapsed_ms=0, summary=f"unknown format {fmt}",
                                 error="format must be md|html|docx"),
                    last_response, vars_)
        return (StepResult(index=i, type=kind, ok=True, elapsed_ms=0,
                            summary=f"wrote {fmt} -> {out}"),
                last_response, vars_)

    if kind == "set":
        for k, v in dict(step.get("vars") or {}).items():
            vars_[str(k)] = v
        return (StepResult(index=i, type=kind, ok=True, elapsed_ms=0,
                            summary=f"set {len(step.get('vars') or {})} vars"),
                last_response, vars_)

    if kind == "assert":
        # H-3: AST-whitelisted boolean evaluator. ``eval`` with empty
        # builtins is *not* a sandbox -- attackers controlling the job
        # file could otherwise reach ``().__class__.__bases__`` and
        # escape. ``safe_eval_bool`` parses, validates, then evaluates.
        from ._safe_eval import safe_eval_bool
        expr = str(step.get("expr", "True"))
        status = getattr(last_response, "status", 0)
        body_text = ""
        if last_response is not None:
            body_text = last_response.body.decode("utf-8", "replace")
        env = {"vars": dict(vars_), "status": status, "body_text": body_text}
        try:
            ok = safe_eval_bool(expr, env)
        except Exception as exc:
            return (StepResult(index=i, type=kind, ok=False, elapsed_ms=0,
                                 summary=f"assert raised: {exc}",
                                 error=str(exc)),
                    last_response, vars_)
        return (StepResult(index=i, type=kind, ok=ok, elapsed_ms=0,
                            summary=f"assert {'OK' if ok else 'FAIL'}: {expr}",
                            error="" if ok else "assertion failed"),
                last_response, vars_)

    if kind == "sleep":
        secs = float(step.get("seconds", 0))
        time.sleep(secs)
        return (StepResult(index=i, type=kind, ok=True, elapsed_ms=0,
                            summary=f"slept {secs:.2f}s"),
                last_response, vars_)

    return (StepResult(index=i, type=kind, ok=False, elapsed_ms=0,
                        summary=f"unknown step type {kind!r}",
                        error="supported: request|scan|active|report|set|assert|sleep"),
            last_response, vars_)
