"""SARIF 2.1.0 export of findings.

SARIF is the industry-standard schema for static-analysis-style tools and is
consumable by GitHub Security tab, Azure DevOps, and many IDE plugins.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Iterable

from ._common import reqlore_version, utc_now

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

_SEV_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "warning",
    "info":     "note",
}


def build_sarif(project_meta: dict, findings: Iterable[dict], *,
                 now: _dt.datetime | None = None) -> dict:
    findings = list(findings)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_id = f.get("rule_id") or f"reqlore:legacy:{f.get('id', 0)}"
        if rule_id not in rules:
            rules[rule_id] = _rule_descriptor(rule_id, f)
        results.append(_result_for(rule_id, f))
    run = {
        "tool": {
            "driver": {
                "name": "reqlore",
                "version": reqlore_version(),
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            },
        },
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": utc_now(now).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }],
        "results": results,
    }
    if project_meta.get("name"):
        run["properties"] = {"project": project_meta["name"]}
    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render_sarif(project_meta: dict, findings: Iterable[dict], *,
                  now: _dt.datetime | None = None,
                  indent: int | None = 2) -> str:
    return json.dumps(
        build_sarif(project_meta, findings, now=now),
        indent=indent, ensure_ascii=False,
    )


def _rule_descriptor(rule_id: str, f: dict) -> dict:
    desc: dict = {
        "id": rule_id,
        "name": rule_id.replace(":", "_"),
        "shortDescription": {"text": f.get("title", rule_id) or rule_id},
    }
    if f.get("description"):
        desc["fullDescription"] = {"text": str(f["description"])}
    if f.get("remediation"):
        desc["help"] = {"text": str(f["remediation"])}
    props: dict = {}
    if f.get("cwe"):
        props["cwe"] = f["cwe"]
        props["tags"] = ["security", f["cwe"]]
    else:
        props["tags"] = ["security"]
    if f.get("owasp"):
        props["owasp"] = f["owasp"]
    desc["properties"] = props
    return desc


def _result_for(rule_id: str, f: dict) -> dict:
    sev = f.get("severity", "info")
    res: dict = {
        "ruleId": rule_id,
        "level": _SEV_TO_LEVEL.get(sev, "note"),
        "message": {"text": f.get("title", rule_id) or rule_id},
    }
    url = f.get("url") or ""
    if url:
        res["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": url},
            },
        }]
    props: dict = {"severity": sev}
    if f.get("uuid"):
        props["uuid"] = f["uuid"]
    if f.get("source"):
        props["source"] = f["source"]
    if f.get("cvss_score") not in (None, ""):
        props["cvss_score"] = f["cvss_score"]
    if f.get("cvss_vector"):
        props["cvss_vector"] = f["cvss_vector"]
    res["properties"] = props
    return res
