"""Scanner engine: iterate history, run rules (+ plugin rules), persist findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .findings import Finding
from .passive import BUILTIN_RULES, Rule, run_passive


@dataclass
class ScanResult:
    rows_scanned: int = 0
    findings_added: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    })
    elapsed_ms: int = 0


class Scanner:
    """Stateless wrapper that runs a fixed list of rules.

    Plugin rules are added by passing `extra_rules=` from the plugin registry.
    """

    def __init__(self, rules: list[Rule] | None = None,
                 extra_rules: list[Rule] | None = None):
        self.rules: list[Rule] = list(rules if rules is not None else BUILTIN_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)

    def scan_history_row(self, row) -> list[Finding]:
        return run_passive(row, self.rules)

    def scan_project(self, project, *, limit: int = 5000) -> ScanResult:
        """Run every rule against the most recent `limit` history rows and
        write the findings to the project file. Duplicates are suppressed via
        the per-finding dedupe_key."""
        import time
        t0 = time.monotonic()
        result = ScanResult()
        rows = project.list_history(limit=limit)
        for row in rows:
            result.rows_scanned += 1
            for f in self.scan_history_row(row):
                project.add_finding(
                    severity=f.severity, title=f.title, cwe=f.cwe, owasp=f.owasp,
                    host=f.host, url=f.url, request_id=f.request_id,
                    response_id=f.response_id, evidence=f.evidence, payload=f.payload,
                    dedupe_key=f.dedupe_key,
                )
                result.findings_added += 1
                result.by_severity[f.severity] = result.by_severity.get(f.severity, 0) + 1
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result
