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
]
