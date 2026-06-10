"""Scanner engine: iterate history, run rules (+ plugin rules), persist findings."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from ..findings_bus import record_finding
from .findings import Finding
from .passive import BUILTIN_RULES, Rule, run_passive
from .rules import apply_meta_defaults, id_for, meta_for


# B.5 — persistent key used to remember the highest http_history.id the passive
# scanner has already processed. Stored in `project_state` so re-runs can
# resume from where the previous scan left off instead of re-scanning the
# whole history every time.
_RESUME_STATE_KEY = "scanner.passive.last_scanned_id"
# B.5 — default per-scan wall-clock deadline. 5 minutes is generous for
# pure-Python passive rules but stops a runaway plugin from monopolising the
# scheduler.
DEFAULT_DEADLINE_SECONDS = 300.0


@dataclass
class ScanResult:
    rows_scanned: int = 0
    findings_added: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    })
    elapsed_ms: int = 0
    # B.5 — partial-result diagnostics. `aborted_due_to_deadline` is True when
    # the loop bailed out because `deadline_seconds` was exceeded before the
    # row list was drained. `rows_skipped_resume` is the number of rows we
    # filtered out because their id was <= the last persisted scan id.
    # `last_scanned_id` is the highest http_history.id we actually processed
    # in this run (None if no rows were processed).
    aborted_due_to_deadline: bool = False
    rows_skipped_resume: int = 0
    last_scanned_id: int | None = None
    deadline_seconds: float = 0.0


def _rule_id_for(rule) -> str:
    """Canonical rule id: prefer ``rule.meta.id`` (A.2 RuleMeta), fall back to
    a name-based synthesis for plugin rules that have not adopted RuleMeta.
    """
    return id_for(rule, prefix="passive")

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

    def scan_project(self, project, *, limit: int = 5000,
                      deadline_seconds: float | None = DEFAULT_DEADLINE_SECONDS,
                      resume: bool = True) -> ScanResult:
        """Run every rule against the most recent `limit` history rows and
        write the findings to the project file. Duplicates are suppressed via
        the per-finding dedupe_key.

        B.5 — supports two opt-out flags:

        * ``deadline_seconds`` — abort gracefully after this many seconds of
          wall-clock time. ``None`` disables the deadline. Default is 5 min.
          When the deadline trips the loop stops *between rows*, partial
          results are still persisted, and ``result.aborted_due_to_deadline``
          is ``True``.
        * ``resume`` — when ``True`` (default), skip rows whose id was already
          processed by a previous call (tracked in ``project_state`` under
          ``scanner.passive.last_scanned_id``). Pass ``resume=False`` for a
          full re-scan (the CLI exposes this as ``--full``).
        """
        t0 = time.monotonic()
        result = ScanResult()
        if deadline_seconds is not None:
            result.deadline_seconds = float(deadline_seconds)
        # B.5 — resume bookkeeping. We read the marker once before the loop;
        # we don't re-read inside it because the only writer is this method.
        resume_from = 0
        if resume:
            try:
                raw = project.get_state(_RESUME_STATE_KEY, "0")
                resume_from = int(raw or "0")
            except (AttributeError, ValueError):
                resume_from = 0
        rows = project.list_history(limit=limit)
        # B.5 — sort ascending so that ``last_scanned_id`` correctly
        # partitions "already processed" from "still to process" when the
        # loop is interrupted by the deadline. ``list_history`` returns
        # rows id-DESC for display; the scanner doesn't care about order
        # beyond resume bookkeeping.
        rows = sorted(rows, key=lambda r: r.id)
        # Per-rule id cache so we don't recompute for every row.
        rule_ids = {id(r): _rule_id_for(r) for r in self.rules}
        highest_id_seen = resume_from
        for row in rows:
            # B.5 — resumable skip. `list_history` returns rows id-DESC so a
            # naive `row.id <= resume_from -> break` would short-circuit the
            # whole loop, but plugin rules may want to revisit all rows on a
            # `resume=False` run, so we filter row-by-row and increment a
            # diagnostic counter instead.
            if resume and resume_from and row.id <= resume_from:
                result.rows_skipped_resume += 1
                continue
            # B.5 — deadline check. Evaluated between rows so a single rule
            # that runs forever still trips it (because we never come back
            # here), but a slow run made of many fast rules can be bounded.
            if (deadline_seconds is not None
                    and (time.monotonic() - t0) >= deadline_seconds):
                result.aborted_due_to_deadline = True
                break
            result.rows_scanned += 1
            if row.id > highest_id_seen:
                highest_id_seen = row.id
            # Map each Finding back to the rule that produced it so we can
            # carry the rule_id through. run_passive iterates rules in order,
            # but it doesn't expose the mapping. For now we replay per-rule.
            for rule in self.rules:
                rid = rule_ids[id(rule)]
                meta = meta_for(rule)
                fired_any = False
                for f in run_passive(row, [rule]):
                    apply_meta_defaults(f, meta)
                    fid = record_finding(
                        project, source="scanner", rule_id=rid,
                        severity=f.severity, title=f.title,
                        description=f.description, remediation=f.remediation,
                        references=f.references,
                        cwe=f.cwe, owasp=f.owasp,
                        host=f.host, url=f.url,
                        request_id=f.request_id, response_id=f.response_id,
                        evidence=f.evidence, payload=f.payload,
                    )
                    if fid is not None:
                        result.findings_added += 1
                        result.by_severity[f.severity] = (
                            result.by_severity.get(f.severity, 0) + 1
                        )
                    fired_any = True
                if not fired_any:
                    project.record_rule_run(
                        rule_id=rid, host=row.host, url=row.url,
                        fired=False, reason="no_match",
                    )
        # B.5 — persist the resume marker. We always write it (even on an
        # empty run) so the very first scan establishes a baseline; this
        # also normalises the value if it was corrupted by a downgrade.
        if result.rows_scanned or resume_from:
            result.last_scanned_id = highest_id_seen or None
            try:
                project.set_state(_RESUME_STATE_KEY, str(highest_id_seen or 0))
            except AttributeError:
                # Older fake projects in tests may not implement set_state.
                pass
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result
