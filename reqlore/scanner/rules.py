"""Rule metadata: single source of truth for ``rule_id``, default severity,
CWE/OWASP tags, and remediation copy for every passive rule and active check.

Rules and checks own their own :class:`RuleMeta`. The scanner engine and the
findings bus read ``meta_for(rule_or_check).id`` instead of synthesising ids
from function or class names. Plugins that have not adopted ``RuleMeta`` fall
back to the legacy synthesis path so nothing breaks.

Usage on a passive rule (function)::

    from reqlore.scanner.rules import RuleMeta, rule_meta

    @rule_meta(RuleMeta(
        id="passive:my_rule",
        title="My rule",
        default_severity="medium",
        cwe="CWE-200",
        ...
    ))
    def rule_my_rule(ctx):
        ...

Usage on an active check (class)::

    class MyCheck(ActiveCheck):
        meta = RuleMeta(id="active:my-check", title="My check", ...)
        name = "my-check"
        ...
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import Finding

Severity = str   # narrowed by SEVERITIES below

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# rule_id must look like "<source>:<slug>" where source is one of the values
# the findings bus accepts and slug is a non-empty token.
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*:[A-Za-z][A-Za-z0-9._-]*$")

# CWE strings should be either empty or "CWE-<digits>".
_CWE_RE = re.compile(r"^CWE-\d+$")


@dataclass(frozen=True)
class RuleMeta:
    """Static description of a passive rule or active check."""
    id: str
    title: str
    default_severity: Severity = "info"
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    remediation: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)
    version: int = 1

    def __post_init__(self) -> None:
        # Validation is cheap and prevents typos from drifting into the
        # findings ledger where they would create permanent dedupe noise.
        if not _RULE_ID_RE.match(self.id):
            raise ValueError(f"RuleMeta.id {self.id!r} must match "
                              f"{_RULE_ID_RE.pattern!r}")
        if self.default_severity not in SEVERITIES:
            raise ValueError(
                f"RuleMeta(id={self.id!r}).default_severity "
                f"{self.default_severity!r} must be one of {SEVERITIES}"
            )
        if self.cwe and not _CWE_RE.match(self.cwe):
            raise ValueError(
                f"RuleMeta(id={self.id!r}).cwe {self.cwe!r} must be empty "
                "or match 'CWE-<digits>'"
            )
        if self.version < 1:
            raise ValueError(
                f"RuleMeta(id={self.id!r}).version must be >= 1"
            )


def rule_meta(meta: RuleMeta):
    """Decorator that attaches ``meta`` to a passive rule callable."""
    def _deco(fn):
        fn.meta = meta
        return fn
    return _deco


def meta_for(rule_or_check) -> RuleMeta | None:
    """Return the :class:`RuleMeta` attached to a passive rule (function) or
    an active check (class instance or class), or ``None`` if it hasn't been
    given one. Legacy callers can use this to detect plugin rules without
    metadata and fall back to id synthesis."""
    return getattr(rule_or_check, "meta", None)


def legacy_rule_id(rule_or_check, *, prefix: str) -> str:
    """Synthesise a rule id for callables / checks that have no RuleMeta yet.

    ``prefix`` is the bus source — e.g. ``"passive"`` or ``"active"``.
    For passive rules: ``rule_xframe_options`` -> ``passive:xframe_options``.
    For active checks: ``ReflectedXSSCheck`` with ``name="xss-reflected"`` ->
    ``active:xss-reflected``; falls back to the class name in lower-snake.
    """
    name = getattr(rule_or_check, "name", None)
    if not name:
        name = getattr(rule_or_check, "__name__", None) \
            or rule_or_check.__class__.__name__
        if name.startswith("rule_"):
            name = name[5:]
    return f"{prefix}:{name}"


def id_for(rule_or_check, *, prefix: str) -> str:
    """Return the canonical rule id for ``rule_or_check``: prefer
    ``meta.id`` if present, otherwise fall back to :func:`legacy_rule_id`.
    """
    meta = meta_for(rule_or_check)
    if meta is not None:
        return meta.id
    return legacy_rule_id(rule_or_check, prefix=prefix)


def apply_meta_defaults(finding: Finding, meta: RuleMeta | None) -> Finding:
    """Fill empty CWE / OWASP / remediation on ``finding`` from ``meta``.

    Returns the same dataclass instance (Finding is mutable). Severity and
    title are already required on Finding so we never overwrite them — the
    rule's emit-time value wins.
    """
    if meta is None:
        return finding
    if not finding.cwe and meta.cwe:
        finding.cwe = meta.cwe
    if not finding.owasp and meta.owasp:
        finding.owasp = meta.owasp
    if not finding.remediation and meta.remediation:
        finding.remediation = meta.remediation
    if not finding.references and meta.references:
        finding.references = list(meta.references)
    return finding
