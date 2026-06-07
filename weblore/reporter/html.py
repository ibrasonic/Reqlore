"""HTML report. Self-contained: no external CSS, no JavaScript.

The visual style mirrors Weblore's own a11y palette: high contrast, generous
white-space, and semantic landmarks. Tables include captions and ``<th
scope>`` for screen readers.
"""
from __future__ import annotations

import datetime as _dt
import html as _h
from typing import Iterable

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_BADGE = {
    "critical": ("background:#a51a1a;color:#fff;", "Critical"),
    "high":     ("background:#c93b00;color:#fff;", "High"),
    "medium":   ("background:#9a6a00;color:#fff;", "Medium"),
    "low":      ("background:#2a6e2a;color:#fff;", "Low"),
    "info":     ("background:#234e7a;color:#fff;", "Info"),
}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 1rem/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  margin: 0; padding: 2rem; max-width: 70rem; margin-inline: auto;
  background: Canvas; color: CanvasText;
}
h1 { margin-top: 0; }
h2 { margin-top: 2.5rem; border-bottom: 1px solid currentColor; padding-bottom: .25rem; }
h3 { margin-top: 1.75rem; }
.meta { color: GrayText; }
.badge {
  display: inline-block; padding: .15em .55em; border-radius: .25em;
  font-weight: 600; font-size: .85em; letter-spacing: .02em;
  margin-right: .5rem; vertical-align: middle;
}
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; }
caption { caption-side: top; text-align: left; padding-bottom: .25rem; font-weight: 600; }
th, td { border: 1px solid CanvasText; padding: .35rem .55rem; text-align: left; }
th { background: ButtonFace; color: ButtonText; }
pre {
  background: ButtonFace; color: ButtonText; padding: .75rem; overflow-x: auto;
  border-radius: .25rem; font: .9rem/1.4 ui-monospace, "Cascadia Code", Consolas, monospace;
}
dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; margin: .5rem 0; }
dt { font-weight: 600; }
.finding {
  border: 1px solid currentColor; border-radius: .5rem; padding: 1rem 1.25rem;
  margin: 1.25rem 0;
}
.finding p:first-of-type { margin-top: 0; }
.skip-link {
  position: absolute; left: -10000px; top: auto;
}
.skip-link:focus { position: static; }
"""


def render_html(project_meta: dict, findings: Iterable[dict],
                 *, title: str = "Weblore — Security Findings") -> str:
    findings = list(findings)
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>{_h.escape(title)}</title>")
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append('<a class="skip-link" href="#findings">Skip to findings</a>')
    parts.append(f"<h1>{_h.escape(title)}</h1>")
    parts.append('<p class="meta">')
    parts.append(f"Project: <strong>{_h.escape(project_meta.get('name', '?'))}</strong> · ")
    parts.append(f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')} · ")
    parts.append(f"Total findings: <strong>{len(findings)}</strong>")
    parts.append("</p>")

    parts.append("<h2>Summary</h2>")
    parts.append("<table><caption>Findings by severity</caption>")
    parts.append("<thead><tr><th scope=\"col\">Severity</th><th scope=\"col\">Count</th></tr></thead><tbody>")
    for sev in SEV_ORDER:
        style, label = SEV_BADGE[sev]
        parts.append(
            f'<tr><th scope="row"><span class="badge" style="{style}">{label}</span></th>'
            f"<td>{counts[sev]}</td></tr>"
        )
    parts.append("</tbody></table>")

    parts.append('<section id="findings">')
    for sev in SEV_ORDER:
        bucket = [f for f in findings if f["severity"] == sev]
        if not bucket:
            continue
        style, label = SEV_BADGE[sev]
        parts.append(f'<h2>{label} <small>({len(bucket)})</small></h2>')
        for f in bucket:
            parts.append('<article class="finding" aria-labelledby="f-' + str(f["id"]) + '">')
            parts.append(
                f'<h3 id="f-{f["id"]}"><span class="badge" style="{style}">{label}</span>'
                f"{_h.escape(f['title'])}</h3>"
            )
            parts.append("<dl>")
            if f.get("host"):
                parts.append(f"<dt>Host</dt><dd><code>{_h.escape(f['host'])}</code></dd>")
            if f.get("url"):
                parts.append(f"<dt>URL</dt><dd><code>{_h.escape(f['url'])}</code></dd>")
            if f.get("cwe"):
                parts.append(f"<dt>CWE</dt><dd>{_h.escape(f['cwe'])}</dd>")
            if f.get("owasp"):
                parts.append(f"<dt>OWASP</dt><dd>{_h.escape(f['owasp'])}</dd>")
            parts.append(f"<dt>Status</dt><dd>{_h.escape(f.get('status', 'open'))}</dd>")
            parts.append("</dl>")
            if f.get("evidence"):
                parts.append("<p><strong>Evidence</strong></p>")
                parts.append(f"<pre>{_h.escape(_clip(f['evidence'], 1000))}</pre>")
            if f.get("payload"):
                parts.append("<p><strong>Payload</strong></p>")
                parts.append(f"<pre>{_h.escape(_clip(f['payload'], 400))}</pre>")
            parts.append("</article>")
    parts.append("</section>")
    parts.append("</body></html>")
    return "".join(parts)


def _clip(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... ({len(s) - n} more chars)"
