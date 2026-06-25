"""Reqlore passive scanner.

Audits already-recorded HTTP history without sending a single byte. Each rule
inspects a (request, response) pair and emits zero or more :class:`Finding`
records. Active scanners come in phase 4.

Design rules:
    * deterministic: same input -> same findings
    * cheap: O(n) byte scans, no regex catastrophic backtracking
    * dedupe-friendly: every finding sets a stable dedupe_key
    * no network IO, no subprocess

Public surface::

    from reqlore.scanner import Finding, Scanner, BUILTIN_RULES, run_passive

    scanner = Scanner(rules=BUILTIN_RULES)
    findings = scanner.scan_history_row(row)
"""
from __future__ import annotations

from .findings import Finding, Severity
from .passive import BUILTIN_RULES, Rule, RuleContext, run_passive
from .engine import Scanner, ScanResult
from .active import (
    ActiveCheck, ActiveContext, ActiveOptions, ActiveScanResult, ActiveScanner,
    BUILTIN_ACTIVE_CHECKS,
)
# Phase 6 — import for side-effect: appends 18 new checks onto
# BUILTIN_ACTIVE_CHECKS via register_phase6_checks() at module load.
from . import phase6_checks as _phase6_checks  # noqa: F401
from .scope_utils import host_in_scope, load_scope_rules
from .live import LiveScanWorker, DEFAULT_QUEUE_MAXSIZE
from .presets import (
    PRESET_NAMES,
    DEFAULT_PRESET,
    SCAN_PRESETS,
    PRESET_DESCRIPTIONS,
    apply_preset,
    preset_summary,
    all_summaries,
)
from .auth_session import (
    AuthCredentials,
    AuthSession,
    AuthSessionConfig,
    AuthSessionStats,
    build_auth_session_from_state,
)
from .consolidation import (
    ConsolidationResult,
    ConsolidationSettings,
    consolidate_frequent_findings,
    extract_backend_signature,
    load_settings as load_consolidation_settings,
    save_settings as save_consolidation_settings,
    should_use_lightweight_mode,
)
from .prioritise import (
    InterestFactors,
    RowScore,
    ScoringWeights,
    insertion_point_keys,
    interest_level,
    is_state_changing,
    prioritise_queue,
    request_carries_auth,
    score_row,
)
from .js_pipeline import (
    DEFAULT_JS_ANALYSIS_MODE,
    JS_ANALYSIS_MODES,
    JSPipelineResult,
    extract_inline_scripts,
    is_html_response,
    is_javascript_response,
    run_js_pipeline,
)

__all__ = [
    "Finding",
    "Severity",
    "Rule",
    "RuleContext",
    "BUILTIN_RULES",
    "Scanner",
    "ScanResult",
    "run_passive",
    "ActiveCheck",
    "ActiveContext",
    "ActiveOptions",
    "ActiveScanResult",
    "ActiveScanner",
    "BUILTIN_ACTIVE_CHECKS",
    "host_in_scope",
    "load_scope_rules",
    "LiveScanWorker",
    "DEFAULT_QUEUE_MAXSIZE",
    "PRESET_NAMES",
    "DEFAULT_PRESET",
    "SCAN_PRESETS",
    "PRESET_DESCRIPTIONS",
    "apply_preset",
    "preset_summary",
    "all_summaries",
    "AuthCredentials",
    "AuthSession",
    "AuthSessionConfig",
    "AuthSessionStats",
    "build_auth_session_from_state",
    "ConsolidationResult",
    "ConsolidationSettings",
    "consolidate_frequent_findings",
    "extract_backend_signature",
    "load_consolidation_settings",
    "save_consolidation_settings",
    "should_use_lightweight_mode",
    "InterestFactors",
    "RowScore",
    "ScoringWeights",
    "insertion_point_keys",
    "interest_level",
    "is_state_changing",
    "prioritise_queue",
    "request_carries_auth",
    "score_row",
    "DEFAULT_JS_ANALYSIS_MODE",
    "JS_ANALYSIS_MODES",
    "JSPipelineResult",
    "extract_inline_scripts",
    "is_html_response",
    "is_javascript_response",
    "run_js_pipeline",
]
