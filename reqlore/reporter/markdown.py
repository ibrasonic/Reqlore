"""Markdown report. Plain CommonMark, no GFM-only extensions."""
from __future__ import annotations

import datetime as _dt
from typing import Iterable

from ._common import (
    SEV_ORDER,
    coverage_rows,
    coverage_rows_by_host,
    curl_from_reproduction,
    reqlore_version,
    severity_counts,
    utc_now,
)

SEV_BADGE = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}


def render_markdown(project_meta: dict, findings: Iterable[dict],
                     *, title: str = "Reqlore — Security Findings",
                     now: _dt.datetime | None = None,
                     classification: str = "",
                     include_coverage: bool = False,
                     coverage: Iterable[dict] | None = None,
                     coverage_by_host: Iterable[dict] | None = None,
                     reproductions: dict[str, dict] | None = None) -> str:
    findings = list(findings)
    counts = severity_counts(findings)
    ts = utc_now(now).isoformat(timespec="seconds")
    out: list[str] = []
    out.append(f"# {title}\n")
    if classification:
        out.append(f"> **{classification}**\n")
    out.append(f"Project: **{project_meta.get('name', '?')}**  ")
    out.append(f"Generated (UTC): {ts}  ")
    out.append(f"Findings: **{len(findings)}** "
               f"(critical {counts['critical']}, high {counts['high']}, "
               f"medium {counts['medium']}, low {counts['low']}, "
               f"info {counts['info']})\n")

    out.append("\n## Summary\n")
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for sev in SEV_ORDER:
        out.append(f"| {sev.title()} | {counts[sev]} |")
    out.append("")

    if include_coverage:
        rows = coverage_rows(coverage)
        out.append("\n## Coverage\n")
        if not rows:
            out.append("_No rule runs recorded._\n")
        else:
            out.append("| Rule | Fired | Evaluated |")
            out.append("|---|---:|---:|")
            for r in rows:
                out.append(f"| `{r['rule_id']}` | {r['fired']} | {r['evaluated']} |")
            out.append("")
        per_host = coverage_rows_by_host(coverage_by_host)
        if per_host:
            out.append("\n### Coverage by host\n")
            out.append("| Rule | Host | Fired | Evaluated |")
            out.append("|---|---|---:|---:|")
            for r in per_host:
                out.append(
                    f"| `{r['rule_id']}` | `{r['host']}` | "
                    f"{r['fired']} | {r['evaluated']} |"
                )
            out.append("")

    for sev in SEV_ORDER:
        bucket = [f for f in findings if f["severity"] == sev]
        if not bucket:
            continue
        out.append(f"\n## {sev.title()} ({len(bucket)})\n")
        for f in bucket:
            out.append(f"### {SEV_BADGE[sev]} {f['title']}\n")
            chips: list[str] = []
            if f.get("rule_id"):
                chips.append(f"Rule: `{f['rule_id']}`")
            if f.get("source"):
                chips.append(f"Source: {f['source']}")
            if f.get("cwe"):
                chips.append(f"CWE: {f['cwe']}")
            if f.get("owasp"):
                chips.append(f"OWASP: {f['owasp']}")
            if f.get("cvss_score") not in (None, ""):
                vec = f.get("cvss_vector") or ""
                chips.append(
                    f"CVSS: {f['cvss_score']}" + (f" ({vec})" if vec else "")
                )
            _conf = f.get("confidence") or "firm"
            chips.append(f"Confidence: {_conf}")
            _occ = f.get("occurrence_count") or 1
            if _occ and _occ > 1:
                chips.append(f"Occurrences: {int(_occ)}")
            _tags = f.get("fingerprint_tags_list") or (
                [t for t in (f.get("fingerprint_tags") or "").split(",") if t]
            )
            if _tags:
                chips.append("Signals: " + ", ".join(_tags))
            if f.get("host"):
                chips.append(f"Host: `{f['host']}`")
            if chips:
                out.append("  ·  ".join(chips) + "\n")
            if f.get("url"):
                out.append(f"**URL:** `{f['url']}`\n")
            if f.get("status"):
                out.append(f"**Status:** {f['status']}\n")
            if f.get("description"):
                out.append("**Description:**\n")
                out.append(str(f["description"]).rstrip() + "\n")
            if f.get("evidence"):
                out.append("**Evidence:**\n")
                out.append("```")
                out.append(_clip(f["evidence"], 800))
                out.append("```\n")
            if f.get("payload"):
                out.append("**Payload:**\n")
                out.append("```")
                out.append(_clip(f["payload"], 400))
                out.append("```\n")
            curl = _curl_for(f, reproductions)
            if curl:
                out.append("**Reproduction:**\n")
                out.append("```")
                out.append(curl)
                out.append("```\n")
            if f.get("remediation"):
                out.append("**Remediation:**\n")
                out.append(str(f["remediation"]).rstrip() + "\n")
            refs = f.get("references") or []
            if refs:
                out.append("**References:**\n")
                for ref in refs:
                    out.append(f"- {ref}")
                out.append("")

    out.append(f"\n---\n_Generated by reqlore {reqlore_version()} at {ts}_\n")
    return "\n".join(out) + "\n"


def _curl_for(finding: dict, reproductions: dict[str, dict] | None) -> str:
    if not reproductions:
        return ""
    token = finding.get("reproduction_token")
    if not token:
        return ""
    repro = reproductions.get(token)
    return curl_from_reproduction(repro)


def _clip(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... ({len(s) - n} more chars)"
