"""Match & Replace engine: rewrites HTTP messages in flight.

Rules live in storage (`match_replace` table). Each rule:
    where      : 'req_header' | 'req_body' | 'resp_header' | 'resp_body'
    pattern    : literal string OR regex (when is_regex=1)
    replacement: replacement text (regex groups supported when is_regex=1)
    host_regex : optional regex filter on flow host
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import _safe_regex


# H-5: hard cap on match-replace output size to neutralise rules whose
# replacement explodes the body (deliberate or accidental). 100 MiB is
# more than any sane HTTP message; if a rule produces more, we drop the
# rewrite and forward the original payload untouched.
_MAX_OUTPUT_BYTES = 100 * 1024 * 1024
# Per-rule expansion ratio cap: a rewrite that grows the input by more
# than 10x is almost certainly a mis-authored backreference.
_MAX_EXPANSION_RATIO = 10


@dataclass
class MRRule:
    id: int
    enabled: bool
    where: str
    is_regex: bool
    host_regex: str
    pattern: str
    replacement: str


def from_row(row: dict) -> MRRule:
    return MRRule(
        id=row["id"], enabled=row["enabled"], where=row["where"],
        is_regex=row["is_regex"], host_regex=row["host_regex"],
        pattern=row["pattern"], replacement=row["replacement"],
    )


def _host_matches(rule: MRRule, host: str) -> bool:
    if not rule.host_regex:
        return True
    return _safe_regex.safe_search(rule.host_regex, host or "") is not None


def _apply_text(rule: MRRule, text: str) -> str:
    if not rule.enabled:
        return text
    if rule.is_regex:
        new = _safe_regex.safe_sub(rule.pattern, rule.replacement, text)
    else:
        new = text.replace(rule.pattern, rule.replacement)
    # Reject pathological growth: keep the original payload so a
    # mis-authored rule cannot exhaust memory or saturate the proxy.
    if len(new) > _MAX_OUTPUT_BYTES:
        return text
    if text and len(new) > _MAX_EXPANSION_RATIO * len(text):
        return text
    return new


def apply_request(rules: list[MRRule], host: str,
                   headers: list[tuple[str, str]], body: bytes
                   ) -> tuple[list[tuple[str, str]], bytes]:
    """Apply 'req_*' rules; returns possibly-rewritten (headers, body)."""
    h = list(headers)
    b = body
    for rule in rules:
        if not rule.enabled:
            continue
        if not _host_matches(rule, host):
            continue
        if rule.where == "req_header":
            joined = "\n".join(f"{k}: {v}" for k, v in h)
            new = _apply_text(rule, joined)
            if new != joined:
                h = _parse_header_lines(new)
        elif rule.where == "req_body":
            try:
                s = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            b = _apply_text(rule, s).encode("utf-8")
    return h, b


def apply_response(rules: list[MRRule], host: str,
                    headers: list[tuple[str, str]], body: bytes
                    ) -> tuple[list[tuple[str, str]], bytes]:
    h = list(headers)
    b = body
    for rule in rules:
        if not rule.enabled:
            continue
        if not _host_matches(rule, host):
            continue
        if rule.where == "resp_header":
            joined = "\n".join(f"{k}: {v}" for k, v in h)
            new = _apply_text(rule, joined)
            if new != joined:
                h = _parse_header_lines(new)
        elif rule.where == "resp_body":
            try:
                s = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            b = _apply_text(rule, s).encode("utf-8")
    return h, b


def _parse_header_lines(s: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in s.splitlines():
        if ":" not in line or not line.strip():
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out
