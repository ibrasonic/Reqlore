"""Report rendering. Markdown + HTML are pure Python; DOCX requires python-docx
but falls back to a Markdown export if the dep isn't installed.

Reports are deliberately stand-alone — no JS, no external assets — so they can
be opened in any browser, mailed, or pasted into a ticket.
"""
from __future__ import annotations

from .markdown import render_markdown
from .html import render_html
from .docx import render_docx, DOCX_AVAILABLE

__all__ = ["render_markdown", "render_html", "render_docx", "DOCX_AVAILABLE"]
