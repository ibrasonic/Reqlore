"""Scanner engine: iterate history, run rules (+ plugin rules), persist findings."""
from __future__ import annotations

import contextlib
import time
from collections import defaultdict
from dataclasses import dataclass, field

from ..findings_bus import record_finding
from .findings import Finding
from .passive import BUILTIN_RULES, Rule, _all_headers, _split_http, run_passive
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
    # Phase 1 — scope-awareness diagnostics.
    skipped_out_of_scope: int = 0
    scanned_in_scope: int = 0
    # Phase 11 — consolidation diagnostics. Zero unless the post-scan
    # consolidation pass actually rolled or collapsed anything.
    consolidation_directory_rollups: int = 0
    consolidation_findings_triaged: int = 0
    consolidation_cross_host_collapses: int = 0
    consolidation_backend_rollups: int = 0


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
                      resume: bool = True,
                      respect_scope: bool = True) -> ScanResult:
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
        * ``respect_scope`` — when ``True`` (default), rows whose host is
          out of project scope are counted in ``skipped_out_of_scope``
          and never passed to passive rules. The active scanner has
          always honoured scope; the passive scanner used to ignore it,
          which surprised operators. Pass ``respect_scope=False`` for
          unfiltered scans (CLI / tests).
        """
        t0 = time.monotonic()
        result = ScanResult()
        if deadline_seconds is not None:
            result.deadline_seconds = float(deadline_seconds)
        # Phase 1 — load scope rules once. The helper handles older
        # fake projects in tests that don't implement ``list_scope``.
        from .scope_utils import host_in_scope, load_scope_rules
        scope_rules = load_scope_rules(project) if respect_scope else []
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
            # Phase 1 — scope filter. The row counts as "scanned" only
            # if we actually ran rules against it; skipped rows roll up
            # into ``skipped_out_of_scope`` so the operator can see why
            # the totals don't match the history table.
            if respect_scope and not host_in_scope(row.host or "", scope_rules):
                result.skipped_out_of_scope += 1
                continue
            result.scanned_in_scope += 1
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
                        confidence=getattr(f, "confidence", "firm"),
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
            # Older fake projects in tests may not implement set_state.
            with contextlib.suppress(AttributeError):
                project.set_state(_RESUME_STATE_KEY, str(highest_id_seen or 0))
        # Phase 1b item #16 — sequencer auto-feed. Cross-row aggregation of
        # Set-Cookie token samples; emits a finding when the entropy
        # rating is "weak" with at least the minimum sample count.
        try:
            scanned, fired = _scan_session_entropy(project, limit=limit)
            result.findings_added += fired
            if fired:
                result.by_severity["medium"] = (
                    result.by_severity.get("medium", 0) + fired
                )
        except Exception:  # noqa: S110  # sequencer aggregation is best-effort; a bad sample must never abort the scan (rule_runs row records "no_match")
            # Sequencer is best-effort: a bad sample must never abort the
            # scan. Failures are intentionally silent here; the
            # rule_runs row records "no_match" which is enough.
            pass
        # Phase 11 — issue noise reduction. Same defensive posture as
        # the sequencer above: a consolidation failure must never
        # mask a successful scan, so we trap broadly and move on.
        try:
            from .consolidation import (
                consolidate_frequent_findings,
                load_settings,
            )
            cs = load_settings(project)
            if cs.enabled:
                cres = consolidate_frequent_findings(project, settings=cs)
                result.consolidation_directory_rollups = cres.directory_rollups
                result.consolidation_findings_triaged = cres.findings_triaged
                result.consolidation_cross_host_collapses = (
                    cres.cross_host_collapses
                )
                result.consolidation_backend_rollups = cres.backend_rollups
        except Exception:  # noqa: S110  # noise-reduction consolidation is best-effort post-processing; a failure here must not mask an otherwise successful scan
            pass
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result


# Phase 1b item #16 — minimum number of distinct token samples we need
# before running the sequencer. Below this the entropy estimate is
# meaningless (a single token is always 0 bits of position entropy).
_SEQUENCER_MIN_SAMPLES = 8
_SEQUENCER_RULE_ID = "passive:weak-session-entropy"
# Cookie names that look like session / auth tokens. Other names are
# skipped because flagging entropy on a tracking pixel ID is noise.
_SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "sid",
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspxauth",
    "auth", "authentication", "auth_token", "authtoken",
    "token", "access_token", "id_token", "csrf", "xsrf-token",
    "remember_token", "remember_me", "_session", "_session_id",
}


def _looks_like_session_cookie(name: str) -> bool:
    n = (name or "").lower().strip()
    if not n:
        return False
    if n in _SESSION_COOKIE_NAMES:
        return True
    # Generic shape: contains "session" or "auth" or ends with "_token".
    return ("session" in n) or ("auth" in n) or n.endswith("_token")


def _parse_set_cookie(raw: str) -> tuple[str, str] | None:
    """Return (name, value) from a single Set-Cookie header value, or
    None if it does not parse."""
    if not raw:
        return None
    head = raw.split(";", 1)[0]
    if "=" not in head:
        return None
    name, value = head.split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        return None
    return name, value


def _scan_session_entropy(project, *, limit: int = 5000) -> tuple[int, int]:
    """Aggregate Set-Cookie tokens across the recorded history and emit a
    finding for any (host, cookie_name) group whose Sequencer rating
    comes back as ``"weak"``.

    Returns ``(samples_examined, findings_emitted)``. ``rule_runs`` is
    updated for every group we evaluated so the coverage page can show
    why a group did not fire.
    """
    from ..sequencer import analyse as sequencer_analyse

    samples: dict[tuple[str, str], list[str]] = defaultdict(list)
    seen_per_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    last_url: dict[tuple[str, str], str] = {}
    total_samples = 0

    rows = project.list_history(limit=limit)
    for row in rows:
        try:
            _, headers, _ = _split_http(row.resp_blob or b"")
        except Exception:  # noqa: S112  # skip malformed history row (unparseable HTTP blob), continue aggregating remaining rows
            continue
        for raw in _all_headers(headers, "set-cookie"):
            parsed = _parse_set_cookie(raw)
            if not parsed:
                continue
            name, value = parsed
            if not _looks_like_session_cookie(name):
                continue
            key = (row.host or "", name)
            # Only count distinct values per (host, name); duplicates from
            # repeated visits should not inflate the entropy estimate.
            if value in seen_per_key[key]:
                continue
            seen_per_key[key].add(value)
            samples[key].append(value)
            last_url[key] = row.url or ""
            total_samples += 1

    fired = 0
    for (host, name), tokens in samples.items():
        if len(tokens) < _SEQUENCER_MIN_SAMPLES:
            project.record_rule_run(
                rule_id=_SEQUENCER_RULE_ID, host=host,
                url=last_url.get((host, name), ""),
                fired=False,
                reason=f"only_{len(tokens)}_samples",
            )
            continue
        seq = sequencer_analyse(tokens)
        if seq.rating != "weak":
            project.record_rule_run(
                rule_id=_SEQUENCER_RULE_ID, host=host,
                url=last_url.get((host, name), ""),
                fired=False,
                reason=f"rating_{seq.rating}",
            )
            continue
        evidence = (
            f"{seq.sample_count} samples; "
            f"{seq.overall_entropy_bits_per_token:.1f} bits/token; "
            f"weak positions={len(seq.weak_positions)}; "
            f"min_hamming={seq.min_hamming}"
        )
        fid = record_finding(
            project, source="scanner", rule_id=_SEQUENCER_RULE_ID,
            severity="medium",
            title=f"Weak session token entropy ({name})",
            description=(
                "The Sequencer's statistical analyser rated the session "
                f"token '{name}' on {host or '(unknown host)'} as "
                "WEAK. Low-entropy session identifiers can be guessed "
                "or brute-forced; consecutive tokens may differ by a "
                "single byte (counter-style IDs)."
            ),
            remediation=(
                "Generate session tokens with a CSPRNG (e.g. Python "
                "`secrets.token_urlsafe(32)`, Node `crypto."
                "randomBytes(32).toString('hex')`); never derive them "
                "from sequential counters or hashes of low-entropy "
                "inputs."
            ),
            cwe="CWE-330", owasp="A07:2021-Identification and Authentication Failures",
            host=host, url=last_url.get((host, name), ""),
            evidence=evidence,
        )
        if fid is not None:
            fired += 1
    return total_samples, fired
