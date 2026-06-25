"""Shared scope-evaluation helpers.

Lifted out of ``scanner/active.py`` so the passive scanner and the live
worker can apply the *same* boundary the active scanner has always
honoured. The semantics match what the Sitemap / Scope UI documents:

    * No enabled ``include`` rules → everything is in-scope.
    * Any enabled ``exclude`` rule that matches → out of scope
      (exclude wins over include).
    * Otherwise: must match at least one enabled ``include`` rule.

Only ``target == "host"`` rules participate. Path-shaped scope is
honoured elsewhere (the scanners run per-row keyed on host); URL-target
rules are intentionally ignored here so this helper stays cheap to call
on every recorded response.
"""
from __future__ import annotations

import fnmatch
from typing import Iterable


def host_in_scope(host: str, scope_rules: Iterable[dict]) -> bool:
    """Return True iff ``host`` is in scope per the given rules.

    ``scope_rules`` is the list returned by ``Project.list_scope()``. The
    function is defensive: missing keys default to permissive values so a
    half-written rule never crashes a scan. Empty / falsy hosts are
    treated as "no host known yet" and considered in scope so the live
    worker never silently swallows traffic before the request line is
    fully parsed.
    """
    if not host:
        return True
    rules = list(scope_rules or ())
    if not rules:
        return True
    includes = [r for r in rules
                if r.get("enabled") and r.get("kind") == "include"
                and (r.get("target") or "host") == "host"]
    excludes = [r for r in rules
                if r.get("enabled") and r.get("kind") == "exclude"
                and (r.get("target") or "host") == "host"]
    for r in excludes:
        pat = r.get("pattern") or ""
        if pat and fnmatch.fnmatch(host, pat):
            return False
    if not includes:
        return True
    return any(
        (r.get("pattern") or "")
        and fnmatch.fnmatch(host, r["pattern"])
        for r in includes
    )


def load_scope_rules(project) -> list[dict]:
    """Fetch scope rules from a project. Returns an empty list on a
    project that doesn't implement ``list_scope`` (older fakes in
    tests)."""
    try:
        return list(project.list_scope())
    except AttributeError:
        return []
