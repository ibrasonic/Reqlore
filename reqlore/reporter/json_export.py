"""JSON export of findings.

The schema is versioned (``reqlore.findings/1``) so downstream consumers can
detect breaking changes. The exporter is pure-Python — no Flask dependency.
"""
from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable

from ._common import (
    coverage_rows,
    coverage_rows_by_host,
    reqlore_version,
    utc_now,
)

SCHEMA = "reqlore.findings/1"


def build_export(project_meta: dict, findings: Iterable[dict], *,
                  now: _dt.datetime | None = None,
                  classification: str = "",
                  coverage: Iterable[dict] | None = None,
                  coverage_by_host: Iterable[dict] | None = None,
                  include_coverage: bool = False) -> dict:
    findings = list(findings)
    payload: dict = {
        "schema": SCHEMA,
        "generator": f"reqlore {reqlore_version()}",
        "generated_at": utc_now(now).isoformat(timespec="seconds"),
        "project": {"name": project_meta.get("name", "")},
        "findings": [_normalise_finding(f) for f in findings],
    }
    if classification:
        payload["classification"] = classification
    if include_coverage:
        payload["coverage"] = coverage_rows(coverage)
        per_host = coverage_rows_by_host(coverage_by_host)
        if per_host:
            payload["coverage_by_host"] = per_host
    return payload


def render_json(project_meta: dict, findings: Iterable[dict], *,
                 now: _dt.datetime | None = None,
                 classification: str = "",
                 coverage: Iterable[dict] | None = None,
                 coverage_by_host: Iterable[dict] | None = None,
                 include_coverage: bool = False,
                 indent: int | None = 2) -> str:
    payload = build_export(
        project_meta, findings,
        now=now, classification=classification,
        coverage=coverage, coverage_by_host=coverage_by_host,
        include_coverage=include_coverage,
    )
    return json.dumps(payload, indent=indent, sort_keys=False, ensure_ascii=False)


def _normalise_finding(f: dict) -> dict:
    """Project a finding row onto the export schema with stable keys."""
    refs = f.get("references")
    if refs is None:
        refs = []
    out = {
        "id": f.get("id"),
        "uuid": f.get("uuid") or "",
        "severity": f.get("severity", "info"),
        "title": f.get("title", ""),
        "status": f.get("status", "open"),
        "source": f.get("source", ""),
        "rule_id": f.get("rule_id", ""),
        "rule_version": f.get("rule_version") or 0,
        "host": f.get("host", ""),
        "url": f.get("url", ""),
        "cwe": f.get("cwe", ""),
        "owasp": f.get("owasp", ""),
        "description": f.get("description", ""),
        "evidence": f.get("evidence", ""),
        "payload": f.get("payload", ""),
        "remediation": f.get("remediation", ""),
        "references": list(refs),
        "cvss_vector": f.get("cvss_vector") or "",
        "cvss_score": f.get("cvss_score"),
        "reproduction_token": f.get("reproduction_token") or "",
        "created_at": f.get("created_at"),
        "updated_at": f.get("updated_at"),
    }
    return out
