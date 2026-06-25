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

# Active-check intensity tiers (Burp Suite Pro parity). The active scanner
# filters checks by ``ActiveOptions.intensity_levels`` so an operator can
# opt out of expensive or noisy classes of probe without disabling each
# check by name. The taxonomy mirrors Burp's "audit checks" intensity:
#
# * ``light``     — read-only or single-shot probes (CORS, JWT alg-none,
#                   open-redirect, OAuth redirect-uri, GraphQL
#                   introspection, default-creds read-only, cloud-blob,
#                   prototype-pollution).
# * ``medium``    — single-parameter mutation probes (XSS, SQLi-error,
#                   SSTI, NoSQLi, XXE-classic, LFI, deserialisation,
#                   forced-browsing, cache-deception, subdomain-takeover,
#                   TLS-active, GraphQL-active).
# * ``intrusive`` — time-based, parallel, or stateful probes that may
#                   create resources / lock accounts / take noticeable
#                   wall-clock time (OS-cmd time, OAST-SSRF, smuggling,
#                   XSS-stored, XSS-DOM, IDOR-alt-identity, race).
#
# A plugin whose ``RuleMeta`` predates this field is treated as
# ``"medium"`` (default value) — neither blocked by the conservative
# default nor allowed to fire intrusive probes unannounced.
Intensity = str
INTENSITIES: tuple[str, ...] = ("light", "medium", "intrusive")

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
    # Phase 2 — active-check intensity tier. Passive rules ignore this
    # field (they always fire). ``"medium"`` is the safe default so
    # legacy plugins without a tier set don't suddenly run intrusive
    # probes, and don't get silently filtered out of conservative
    # scans either.
    intensity: Intensity = "medium"

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
        if self.intensity not in INTENSITIES:
            raise ValueError(
                f"RuleMeta(id={self.id!r}).intensity {self.intensity!r} "
                f"must be one of {INTENSITIES}"
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


def intensity_for(rule_or_check) -> Intensity:
    """Return the intensity tier for an active check (or rule).

    Looks at ``meta.intensity`` first; falls back to ``"medium"`` so a
    plugin whose :class:`RuleMeta` predates the field is neither
    silently filtered out of conservative scans nor allowed to behave
    like an intrusive probe by accident. Active checks without any
    ``meta`` at all also default to ``"medium"``.
    """
    meta = meta_for(rule_or_check)
    if meta is None:
        return "medium"
    value = getattr(meta, "intensity", "medium")
    return value if value in INTENSITIES else "medium"


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
