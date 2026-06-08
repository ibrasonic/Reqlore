"""Markdown report. Plain CommonMark, no GFM-only extensions."""
from __future__ import annotations

import datetime as _dt
from typing import Iterable

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_BADGE = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}


def render_markdown(project_meta: dict, findings: Iterable[dict],
                     *, title: str = "Reqlore — Security Findings") -> str:
    findings = list(findings)
    counts = _counts(findings)
    out: list[str] = []
    out.append(f"# {title}\n")
    out.append(f"Project: **{project_meta.get('name', '?')}**  ")
    out.append(f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')}  ")
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

    for sev in SEV_ORDER:
        bucket = [f for f in findings if f["severity"] == sev]
        if not bucket:
            continue
        out.append(f"\n## {sev.title()} ({len(bucket)})\n")
        for f in bucket:
            out.append(f"### {SEV_BADGE[sev]} {f['title']}\n")
            meta = []
            if f.get("cwe"):
                meta.append(f"CWE: {f['cwe']}")
            if f.get("owasp"):
                meta.append(f"OWASP: {f['owasp']}")
            if f.get("host"):
                meta.append(f"Host: `{f['host']}`")
            if meta:
                out.append("  ·  ".join(meta) + "\n")
            if f.get("url"):
                out.append(f"**URL:** `{f['url']}`\n")
            if f.get("status"):
                out.append(f"**Status:** {f['status']}\n")
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
    return "\n".join(out) + "\n"


def _counts(findings) -> dict[str, int]:
    out = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity", "info")
        out[s] = out.get(s, 0) + 1
    return out


def _clip(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... ({len(s) - n} more chars)"
