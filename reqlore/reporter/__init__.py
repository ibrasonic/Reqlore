"""Report rendering. Markdown + HTML are pure Python; DOCX requires python-docx
but falls back to a Markdown export if the dep isn't installed.

Reports are deliberately stand-alone — no JS, no external assets — so they can
be opened in any browser, mailed, or pasted into a ticket.
"""
from __future__ import annotations

from .docx import DOCX_AVAILABLE, render_docx
from .html import render_html
from .json_export import SCHEMA as JSON_SCHEMA
from .json_export import build_export as build_json_export
from .json_export import render_json
from .markdown import render_markdown
from .sarif import SARIF_VERSION, build_sarif, render_sarif

__all__ = [
    "render_markdown", "render_html", "render_docx", "DOCX_AVAILABLE",
    "render_json", "build_json_export", "JSON_SCHEMA",
    "render_sarif", "build_sarif", "SARIF_VERSION",
]
