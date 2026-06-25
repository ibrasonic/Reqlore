"""Finding model. Plain dataclass — no Flask, no SQLite."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]

# Phase 3 (Burp parity) — confidence tiers stamped on every finding.
# ``tentative``: pattern matched but evidence is weak (e.g. WAF-fronted,
# error-page-fronted, single-shot reflection).
# ``firm``: default — the rule's normal positive case.
# ``certain``: two independent detection techniques agree (cross-rule
# corroboration in :class:`reqlore.storage.Project`).
Confidence = Literal["tentative", "firm", "certain"]

# Map severity to a representative CVSS v3.1 base score band.
# This is a guideline only; rules may override with their own score.
CVSS_BAND = {
    "info":     0.0,
    "low":      3.1,
    "medium":   5.4,
    "high":     7.5,
    "critical": 9.3,
}


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str = ""
    cwe: str = ""           # e.g. "CWE-693"
    owasp: str = ""         # e.g. "A05:2021-Security Misconfiguration"
    host: str = ""
    url: str = ""
    request_id: int | None = None
    response_id: int | None = None
    evidence: str = ""
    payload: str = ""
    cvss: float | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    # Phase 3 — confidence tier (default ``firm``). Rules can set
    # ``tentative`` when their evidence is genuinely weak (e.g. only a
    # single benign reflection) so the bus doesn't have to demote them.
    confidence: Confidence = "firm"

    @property
    def cvss_score(self) -> float:
        return self.cvss if self.cvss is not None else CVSS_BAND[self.severity]

    @property
    def dedupe_key(self) -> str:
        return f"{self.title}|{self.host}|{self.url}|{self.evidence[:200]}"
