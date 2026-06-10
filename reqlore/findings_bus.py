"""Single chokepoint that every finding-producing module funnels through.

Why this exists
---------------
Before A.1, the only callers of ``Project.add_finding`` were the passive and
active scanners. Other modules (Intruder, smuggling, sequencer, SAML, OAST,
GraphQL, the proxy, manual UI entries, plugin output, JSON imports) generated
finding-shaped data but never wrote it to the ``issues`` table, so the Reporter
could not see them.

``record_finding`` is the unified write path. It:

1. honours per-(rule_id, host, url) suppressions from
   :meth:`Project.is_suppressed` (returning ``None`` when suppressed);
2. records a row in ``rule_runs`` so the Reporter can answer
   "which rules ran and which fired" later;
3. optionally stores the raw request/response bytes via
   :meth:`Project.add_reproduction` and passes the resulting token to
   :meth:`Project.add_finding`;
4. delegates the actual insert to :meth:`Project.add_finding`, which already
   handles dedupe on the stable ``rule_id|host|url|sha256(evidence)[:16]`` key.

Returns the integer finding id on success, ``None`` when suppressed.
"""
from __future__ import annotations

from typing import Sequence


Reproduction = tuple[bytes, bytes, str, str, int, int]
# (request_blob, response_blob, method, url, status, elapsed_ms)


def record_finding(project, *, source: str, severity: str, title: str,
                    rule_id: str = "", rule_version: int = 0,
                    description: str = "", remediation: str = "",
                    references: Sequence[str] | None = None,
                    cwe: str = "", owasp: str = "",
                    cvss_vector: str | None = None,
                    cvss_score: float | None = None,
                    host: str = "", url: str = "",
                    request_id: int | None = None,
                    response_id: int | None = None,
                    evidence: str = "", payload: str = "",
                    reproduction: Reproduction | None = None,
                    extra_targets: Sequence[tuple[str, str]] | None = None,
                    ) -> int | None:
    """Insert a finding through the bus. Returns the finding id, or ``None``
    when a suppression matches.

    ``project`` is a :class:`reqlore.storage.Project` (kept untyped here to
    avoid a circular import). ``source`` should be one of
    :attr:`Project.SOURCES`. ``rule_id`` is optional but strongly recommended:
    suppressions, dedupe quality, and rule-run telemetry all key off it.
    """
    if project.is_suppressed(rule_id=rule_id, host=host, url=url):
        project.record_rule_run(
            rule_id=rule_id, rule_version=rule_version,
            host=host, url=url, fired=False, reason="suppressed",
        )
        return None

    token: str | None = None
    if reproduction is not None:
        req_blob, resp_blob, method, repro_url, status, elapsed_ms = reproduction
        token = project.add_reproduction(
            request_blob=req_blob, response_blob=resp_blob,
            method=method, url=repro_url or url,
            status=status, elapsed_ms=elapsed_ms,
        )

    fid = project.add_finding(
        severity=severity, title=title, cwe=cwe, owasp=owasp,
        host=host, url=url, request_id=request_id, response_id=response_id,
        evidence=evidence, payload=payload,
        source=source, rule_id=rule_id, rule_version=rule_version,
        description=description, remediation=remediation,
        references=list(references or []),
        cvss_vector=cvss_vector, cvss_score=cvss_score,
        reproduction_token=token,
        extra_targets=list(extra_targets or []),
    )
    project.record_rule_run(
        rule_id=rule_id, rule_version=rule_version,
        host=host, url=url, fired=True,
    )
    return fid


def record_no_finding(project, *, rule_id: str, rule_version: int = 0,
                       host: str = "", url: str = "",
                       reason: str = "no_match") -> None:
    """Record that a rule ran and did not fire. Cheap; safe to call in tight
    loops. ``reason`` should be one of ``"no_match"``, ``"not_applicable"``,
    ``"out_of_scope"``, or a custom short string.
    """
    project.record_rule_run(
        rule_id=rule_id, rule_version=rule_version,
        host=host, url=url, fired=False, reason=reason,
    )
