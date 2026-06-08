"""DOCX report. Requires python-docx; falls back to Markdown otherwise."""
from __future__ import annotations

from io import BytesIO
from typing import Iterable

from .markdown import SEV_ORDER, render_markdown

try:
    from docx import Document
    from docx.shared import Pt, RGBColor
    DOCX_AVAILABLE = True
except ImportError:
    Document = None  # type: ignore[assignment]
    DOCX_AVAILABLE = False


_SEV_COLOR = {
    "critical": RGBColor(0xA5, 0x1A, 0x1A) if DOCX_AVAILABLE else None,
    "high":     RGBColor(0xC9, 0x3B, 0x00) if DOCX_AVAILABLE else None,
    "medium":   RGBColor(0x9A, 0x6A, 0x00) if DOCX_AVAILABLE else None,
    "low":      RGBColor(0x2A, 0x6E, 0x2A) if DOCX_AVAILABLE else None,
    "info":     RGBColor(0x23, 0x4E, 0x7A) if DOCX_AVAILABLE else None,
}


def render_docx(project_meta: dict, findings: Iterable[dict], *,
                 title: str = "Reqlore Security Findings") -> bytes:
    """Return the .docx file as bytes. Raises RuntimeError if python-docx is
    missing — callers should check ``DOCX_AVAILABLE`` first or fall back to
    :func:`render_markdown`.
    """
    if not DOCX_AVAILABLE:
        raise RuntimeError(
            "python-docx is not installed. Install it with "
            "'pip install python-docx' or export the report as Markdown / HTML "
            "instead."
        )
    findings = list(findings)
    doc = Document()
    doc.add_heading(title, level=0)
    p = doc.add_paragraph()
    p.add_run(f"Project: {project_meta.get('name', '?')}").bold = True
    p.add_run("    Total findings: ")
    p.add_run(str(len(findings))).bold = True

    # Summary table
    doc.add_heading("Summary", level=1)
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    table = doc.add_table(rows=1, cols=2)
    table.style = "Light Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "Count"
    for sev in SEV_ORDER:
        row = table.add_row().cells
        row[0].text = sev.title()
        row[1].text = str(counts[sev])

    # Per-severity sections
    for sev in SEV_ORDER:
        bucket = [f for f in findings if f["severity"] == sev]
        if not bucket:
            continue
        doc.add_heading(f"{sev.title()} ({len(bucket)})", level=1)
        for f in bucket:
            heading = doc.add_heading(f["title"], level=2)
            for run in heading.runs:
                run.font.color.rgb = _SEV_COLOR[sev]
            meta_bits: list[str] = []
            if f.get("host"):
                meta_bits.append(f"Host: {f['host']}")
            if f.get("url"):
                meta_bits.append(f"URL: {f['url']}")
            if f.get("cwe"):
                meta_bits.append(f"CWE: {f['cwe']}")
            if f.get("owasp"):
                meta_bits.append(f"OWASP: {f['owasp']}")
            meta_bits.append(f"Status: {f.get('status', 'open')}")
            doc.add_paragraph("    ·  ".join(meta_bits))
            if f.get("evidence"):
                doc.add_paragraph("Evidence:").runs[0].bold = True
                ev = doc.add_paragraph(_clip(f["evidence"], 1500))
                ev.runs[0].font.name = "Consolas"
                ev.runs[0].font.size = Pt(9)
            if f.get("payload"):
                doc.add_paragraph("Payload:").runs[0].bold = True
                pl = doc.add_paragraph(_clip(f["payload"], 500))
                pl.runs[0].font.name = "Consolas"
                pl.runs[0].font.size = Pt(9)

    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _clip(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... ({len(s) - n} more chars)"
