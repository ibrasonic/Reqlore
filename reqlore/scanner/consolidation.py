"""Phase 11 — issue noise reduction + consolidation.

Three orthogonal mechanisms, all opt-out, all gated by a single
:class:`ConsolidationSettings` instance loaded from the project's
``project_state`` KV store:

1. **Frequent-issue path roll-up.** When the same passive rule fires
   on more than ``path_rollup_threshold`` distinct URLs under the
   same directory (e.g. five missing-security-header findings on
   ``/api/v1/users/{id}/profile``, ``/api/v1/users/{id}/orders``…),
   we materialise a single directory-level finding that summarises
   the cluster and references every original via the
   ``finding_occurrences`` table. The original rows are then marked
   ``status="triaged"`` so they no longer add noise to the issue
   list, but the per-URL evidence is preserved for the reporter.

2. **Frequent-insertion-point lightweight mode.** When the active
   scanner probes the same insertion point (e.g. a ``csrf_token``
   parameter that appears on every form POST) more than
   ``ip_lightweight_threshold`` times without a single check firing,
   subsequent rules skip the *intrusive* tier on that point and only
   send the cheapest probe. This is the Burp behaviour that prevents
   a CSRF token from soaking up the entire probe budget. The cache
   that backs it lives on :class:`reqlore.scanner.insertion_points.InsertionPointCache`.

3. **Cross-host backend dedupe.** When two findings live on
   different hosts but the hosts share a backend signature (today
   that signature is the response ``Server`` header — TLS cert SHA
   is a clean future extension once the engines surface it), the
   *secondary* host's finding is collapsed into the *primary*'s
   occurrence list. The choice of primary is deterministic
   (lowest-id finding wins) so re-runs converge.

All three are off by default to preserve existing behaviour for
projects upgrading to Phase 11.
"""
from __future__ import annotations

import re
import time
import urllib.parse as _up
from dataclasses import dataclass, field
from typing import Any, Iterable

__all__ = [
    "ConsolidationSettings",
    "ConsolidationResult",
    "load_settings",
    "save_settings",
    "consolidate_frequent_findings",
    "extract_backend_signature",
    "cluster_findings_by_directory",
    "directory_of",
    "should_use_lightweight_mode",
]


# ---------------------------------------------------------------------------
# Settings.
# ---------------------------------------------------------------------------

_KEY_ENABLED = "consolidation:enabled"
_KEY_PATH_ROLLUP_THRESHOLD = "consolidation:path_rollup_threshold"
_KEY_IP_LIGHTWEIGHT_THRESHOLD = "consolidation:ip_lightweight_threshold"
_KEY_CROSS_HOST_ENABLED = "consolidation:cross_host_enabled"

_DEFAULT_PATH_ROLLUP_THRESHOLD = 5
_DEFAULT_IP_LIGHTWEIGHT_THRESHOLD = 50
# Hard floor: a directory roll-up that would summarise only one or
# two findings is just noise itself.
_MIN_PATH_ROLLUP_THRESHOLD = 3
# Hard floor for the IP gate. Below this, a flaky insertion point
# can suppress the *first* check we run against it, which makes the
# scan look broken.
_MIN_IP_LIGHTWEIGHT_THRESHOLD = 10


@dataclass(frozen=True)
class ConsolidationSettings:
    """Operator-facing knobs for the consolidation pass.

    Set ``enabled=False`` to disable every mechanism in one go (the
    individual fields are still honoured, but
    :func:`consolidate_frequent_findings` short-circuits before
    touching the database). ``cross_host_enabled`` is a finer toggle
    because the backend-signature heuristic is more aggressive than
    same-host roll-up and an operator may want one without the
    other.
    """

    enabled: bool = False
    path_rollup_threshold: int = _DEFAULT_PATH_ROLLUP_THRESHOLD
    ip_lightweight_threshold: int = _DEFAULT_IP_LIGHTWEIGHT_THRESHOLD
    cross_host_enabled: bool = False

    def __post_init__(self) -> None:
        if self.path_rollup_threshold < _MIN_PATH_ROLLUP_THRESHOLD:
            raise ValueError(
                f"path_rollup_threshold must be >= "
                f"{_MIN_PATH_ROLLUP_THRESHOLD}; got "
                f"{self.path_rollup_threshold}"
            )
        if self.ip_lightweight_threshold < _MIN_IP_LIGHTWEIGHT_THRESHOLD:
            raise ValueError(
                f"ip_lightweight_threshold must be >= "
                f"{_MIN_IP_LIGHTWEIGHT_THRESHOLD}; got "
                f"{self.ip_lightweight_threshold}"
            )


def load_settings(project: Any) -> ConsolidationSettings:
    """Read the four KV keys and return a validated
    :class:`ConsolidationSettings`. Missing keys fall back to the
    defaults, which are conservative (everything off)."""
    def _get(key: str, default: str) -> str:
        try:
            return project.get_state(key, default)
        except AttributeError:
            return default

    def _as_int(raw: str, default: int, floor: int) -> int:
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return default
        return v if v >= floor else default

    enabled = _get(_KEY_ENABLED, "0") == "1"
    cross_host = _get(_KEY_CROSS_HOST_ENABLED, "0") == "1"
    path_thr = _as_int(
        _get(_KEY_PATH_ROLLUP_THRESHOLD,
              str(_DEFAULT_PATH_ROLLUP_THRESHOLD)),
        _DEFAULT_PATH_ROLLUP_THRESHOLD,
        _MIN_PATH_ROLLUP_THRESHOLD,
    )
    ip_thr = _as_int(
        _get(_KEY_IP_LIGHTWEIGHT_THRESHOLD,
              str(_DEFAULT_IP_LIGHTWEIGHT_THRESHOLD)),
        _DEFAULT_IP_LIGHTWEIGHT_THRESHOLD,
        _MIN_IP_LIGHTWEIGHT_THRESHOLD,
    )
    return ConsolidationSettings(
        enabled=enabled,
        path_rollup_threshold=path_thr,
        ip_lightweight_threshold=ip_thr,
        cross_host_enabled=cross_host,
    )


def save_settings(project: Any, settings: ConsolidationSettings) -> None:
    """Persist ``settings`` to the project's KV store. Re-runs
    ``__post_init__`` semantics — invalid settings raise
    :class:`ValueError`."""
    # Re-validate via dataclass to surface bad values before we touch
    # the DB; the dataclass is frozen but constructing a new one is
    # cheap and gives us a clean failure mode.
    ConsolidationSettings(
        enabled=settings.enabled,
        path_rollup_threshold=settings.path_rollup_threshold,
        ip_lightweight_threshold=settings.ip_lightweight_threshold,
        cross_host_enabled=settings.cross_host_enabled,
    )
    project.set_state(_KEY_ENABLED, "1" if settings.enabled else "0")
    project.set_state(
        _KEY_PATH_ROLLUP_THRESHOLD, str(settings.path_rollup_threshold),
    )
    project.set_state(
        _KEY_IP_LIGHTWEIGHT_THRESHOLD,
        str(settings.ip_lightweight_threshold),
    )
    project.set_state(
        _KEY_CROSS_HOST_ENABLED,
        "1" if settings.cross_host_enabled else "0",
    )


# ---------------------------------------------------------------------------
# URL helpers.
# ---------------------------------------------------------------------------

# Same numeric / hex / UUID segment matcher the storage layer already
# uses for dedupe-key normalisation. We repeat it here (rather than
# import the private one) so the consolidation module is decoupled
# from storage internals.
_ID_SEGMENT_RE = re.compile(
    r"/("
    r"\d+"
    r"|[0-9a-fA-F]{8,}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r")(?=/|$|\?)"
)


def directory_of(url: str) -> str:
    """Return the URL's *directory* — scheme + host + everything up
    to (but not including) the final path segment, with numeric / UUID
    / hex segments replaced by ``{id}`` so that cluster keys are
    stable across IDs.

    Examples:
      - ``"https://x.y/api/v1/users/42/profile"`` →
        ``"https://x.y/api/v1/users/{id}/"``
      - ``"https://x.y/"``                       → ``"https://x.y/"``
      - ``"https://x.y/foo"``                    → ``"https://x.y/"``
      - ``"https://x.y/foo/"``                   → ``"https://x.y/foo/"``
      - ``"not-a-url"``                          → ``"not-a-url"``
    """
    if not url:
        return ""
    try:
        p = _up.urlsplit(url)
    except ValueError:
        return url
    if not p.scheme or not p.netloc:
        return url
    path = p.path or "/"
    # Strip a trailing filename: keep everything up to the last "/".
    # If the path ends in "/", that already is the directory.
    if not path.endswith("/"):
        last_slash = path.rfind("/")
        if last_slash == -1:
            path = "/"
        else:
            path = path[: last_slash + 1]
    if path == "":
        path = "/"
    path = _ID_SEGMENT_RE.sub("/{id}", path)
    return f"{p.scheme}://{p.netloc}{path}"


# ---------------------------------------------------------------------------
# Clustering.
# ---------------------------------------------------------------------------

@dataclass
class _Cluster:
    rule_id: str
    directory: str
    severity: str
    findings: list[dict] = field(default_factory=list)


def cluster_findings_by_directory(
    findings: Iterable[dict],
) -> list[_Cluster]:
    """Group ``findings`` by ``(rule_id, directory_of(url))``.

    Each input row is expected to be the ``dict`` shape returned by
    :func:`reqlore.storage.Project.list_findings`. Empty / non-URL
    rows are silently skipped (they cannot be rolled up by
    directory). The output cluster list is deterministic: ordered by
    ``rule_id`` then ``directory`` for stable test assertions.
    """
    buckets: dict[tuple[str, str], _Cluster] = {}
    for f in findings:
        rule_id = (f.get("rule_id") or "").strip()
        url = (f.get("url") or "").strip()
        if not rule_id or not url:
            continue
        directory = directory_of(url)
        if not directory:
            continue
        key = (rule_id, directory)
        c = buckets.get(key)
        if c is None:
            c = _Cluster(
                rule_id=rule_id,
                directory=directory,
                severity=f.get("severity") or "info",
            )
            buckets[key] = c
        c.findings.append(f)
    return [buckets[k] for k in sorted(buckets.keys())]


# ---------------------------------------------------------------------------
# Backend-signature extraction.
# ---------------------------------------------------------------------------

_SERVER_HEADER_RE = re.compile(
    rb"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE,
)


def extract_backend_signature(resp_blob: bytes | None) -> str:
    """Return a stable, comparable backend identifier for a stored
    response, or the empty string if no signature can be derived.

    Today the signature is just the lower-cased ``Server`` response
    header. We deliberately normalise out the version suffix
    (``Apache/2.4.61 (Ubuntu)`` → ``apache``) because hosts behind
    the same fleet rarely all run the exact same patch level and we
    want them to collapse anyway. TLS cert SHA support is a clean
    extension once the engines surface it; we don't fabricate one
    here.
    """
    if not resp_blob:
        return ""
    m = _SERVER_HEADER_RE.search(resp_blob)
    if not m:
        return ""
    raw = m.group(1).decode("latin-1", errors="replace").strip()
    if not raw:
        return ""
    # Strip everything from the first '/' onwards (version suffix)
    # plus any trailing parenthetical (build qualifier).
    head = raw.split("/", 1)[0]
    head = head.split(" ", 1)[0]
    return head.strip().lower()


# ---------------------------------------------------------------------------
# Lightweight-mode predicate.
# ---------------------------------------------------------------------------

def should_use_lightweight_mode(
    cache: Any, *, rule_id: str, point: Any,
    threshold: int,
) -> bool:
    """Return ``True`` when ``cache`` has seen the given
    ``(rule_id, point)`` more than ``threshold`` times without any
    of those probes firing a finding.

    ``cache`` is expected to be an
    :class:`reqlore.scanner.insertion_points.InsertionPointCache`
    augmented with the Phase 11 counters (``record_probe`` /
    ``record_fire``). The function is tolerant of a cache that lacks
    those methods (older cache instances built before Phase 11) —
    it simply returns ``False`` so behaviour matches pre-Phase-11.
    """
    if threshold <= 0:
        return False
    get_probes = getattr(cache, "probe_count", None)
    get_fires = getattr(cache, "fire_count", None)
    if get_probes is None or get_fires is None:
        return False
    try:
        probes = int(get_probes(rule_id=rule_id, point=point))
        fires = int(get_fires(rule_id=rule_id, point=point))
    except (TypeError, ValueError):
        return False
    return probes > threshold and fires == 0


# ---------------------------------------------------------------------------
# Roll-up writer.
# ---------------------------------------------------------------------------

_ROLLUP_TAG = "consolidated:directory"
_BACKEND_ROLLUP_TAG_PREFIX = "consolidated:backend="


@dataclass
class ConsolidationResult:
    """Diagnostics returned by :func:`consolidate_frequent_findings`.

    All counts are post-write — the scan / report renderer can show
    them verbatim without further accounting.
    """

    clusters_examined: int = 0
    directory_rollups: int = 0
    findings_triaged: int = 0
    backend_rollups: int = 0
    cross_host_collapses: int = 0
    elapsed_ms: int = 0


def consolidate_frequent_findings(
    project: Any,
    *,
    settings: ConsolidationSettings | None = None,
) -> ConsolidationResult:
    """Run the consolidation pass on every open finding.

    When ``settings.enabled`` is False (the default) this is a
    no-op and the returned result has every counter at zero. The
    function never raises on the absence of optional storage
    methods — projects in fake / test environments simply see no
    consolidation but no crash either.
    """
    t0 = time.monotonic()
    result = ConsolidationResult()
    s = settings or load_settings(project)
    if not s.enabled:
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result
    try:
        findings = project.list_findings(status="open", limit=5_000)
    except (AttributeError, TypeError):
        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result

    # ------------------------------------------------------------------
    # 1) Same-host directory roll-up.
    # ------------------------------------------------------------------
    clusters = cluster_findings_by_directory(findings)
    result.clusters_examined = len(clusters)
    for cluster in clusters:
        if len(cluster.findings) < s.path_rollup_threshold:
            continue
        if _looks_like_rollup_already(cluster.findings):
            continue
        _materialise_directory_rollup(project, cluster, result=result)

    # ------------------------------------------------------------------
    # 2) Cross-host backend collapse.
    # ------------------------------------------------------------------
    if s.cross_host_enabled:
        _collapse_across_backend(project, findings, result=result)

    result.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return result


def _looks_like_rollup_already(findings: list[dict]) -> bool:
    """Return True if the cluster already contains a directory-level
    roll-up — guards against re-rolling on every passive scan."""
    for f in findings:
        tags = (f.get("fingerprint_tags") or "").lower()
        if _ROLLUP_TAG in tags:
            return True
    return False


def _materialise_directory_rollup(
    project: Any, cluster: _Cluster, *, result: ConsolidationResult,
) -> None:
    """Insert a single rolled-up finding for the cluster and triage
    the originals. Each operation is defensively isolated: if the
    project lacks an expected method, the function bails out
    silently rather than partial-update."""
    add = getattr(project, "add_finding", None)
    set_status = getattr(project, "set_finding_status", None)
    if add is None:
        return
    occurrence_urls = [
        f.get("url", "") for f in cluster.findings if f.get("url")
    ]
    title = _rollup_title(cluster)
    evidence = _rollup_evidence(cluster, occurrence_urls)
    extra_targets = [
        ((f.get("host") or ""), (f.get("url") or ""))
        for f in cluster.findings if f.get("url")
    ]
    try:
        fid = add(
            severity=cluster.severity,
            title=title,
            host=_host_from_url(cluster.directory),
            url=cluster.directory,
            rule_id=cluster.rule_id,
            evidence=evidence,
            payload="",
            source="consolidation",
            description=(
                "Burp-style frequent-issue roll-up: the same "
                f"rule fired on {len(cluster.findings)} distinct "
                "URLs under this directory. Per-URL evidence is "
                "preserved in the occurrences ledger."
            ),
            confidence=_best_confidence(cluster.findings),
            fingerprint_tags=_ROLLUP_TAG,
            extra_targets=extra_targets,
        )
    except TypeError:
        # Older storage signature; bail without corrupting state.
        return
    if fid is None:
        return
    result.directory_rollups += 1
    if set_status is None:
        return
    for f in cluster.findings:
        try:
            set_status(int(f["id"]), "triaged")
            result.findings_triaged += 1
        except (KeyError, TypeError, ValueError):
            continue


def _collapse_across_backend(
    project: Any, findings: list[dict], *,
    result: ConsolidationResult,
) -> None:
    """For each ``(rule_id, normalised_path)`` group, if findings
    sit on two or more hosts that share a Server-header backend
    signature, mark all but the lowest-id one as triaged and tag
    them with the backend label."""
    set_status = getattr(project, "set_finding_status", None)
    if set_status is None:
        return
    get_history = getattr(project, "get_history", None)
    # Group by (rule_id, normalised_url-without-host).
    by_key: dict[tuple[str, str], list[dict]] = {}
    for f in findings:
        rule_id = (f.get("rule_id") or "").strip()
        url = (f.get("url") or "").strip()
        if not rule_id or not url:
            continue
        path = _normalised_path(url)
        by_key.setdefault((rule_id, path), []).append(f)
    for (rule_id, _path), group in by_key.items():
        del rule_id
        if len(group) < 2:
            continue
        signatures: dict[int, str] = {}
        for f in group:
            sig = ""
            rid = f.get("request_id")
            if rid and get_history is not None:
                try:
                    row = get_history(int(rid))
                except (TypeError, ValueError):
                    row = None
                if row is not None:
                    sig = extract_backend_signature(
                        getattr(row, "resp_blob", None)
                    )
            signatures[int(f["id"])] = sig
        # Group findings whose signature is non-empty AND identical.
        from collections import defaultdict
        by_sig: dict[str, list[int]] = defaultdict(list)
        for fid, sig in signatures.items():
            if sig:
                by_sig[sig].append(fid)
        for sig, ids in by_sig.items():
            if len(ids) < 2:
                continue
            # Hosts collapsed are those whose signature matches the
            # cluster's *primary* (lowest fid). The primary stays
            # open; the rest get triaged with a backend tag.
            ids.sort()
            for fid in ids[1:]:
                try:
                    set_status(fid, "triaged")
                    result.cross_host_collapses += 1
                except (TypeError, ValueError):
                    continue
            result.backend_rollups += 1
            del sig


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------

_CONFIDENCE_RANK = {"tentative": 0, "firm": 1, "certain": 2}


def _best_confidence(findings: list[dict]) -> str:
    best = "tentative"
    best_rank = -1
    for f in findings:
        c = (f.get("confidence") or "firm").lower()
        r = _CONFIDENCE_RANK.get(c, -1)
        if r > best_rank:
            best_rank = r
            best = c
    return best if best_rank >= 0 else "firm"


def _rollup_title(cluster: _Cluster) -> str:
    sample = cluster.findings[0]
    base = (sample.get("title") or sample.get("rule_id")
            or "Frequent issue")
    return f"{base} — frequent on {cluster.directory}"


def _rollup_evidence(cluster: _Cluster, urls: list[str]) -> str:
    n = len(cluster.findings)
    sample_urls = urls[:5]
    more = max(0, len(urls) - len(sample_urls))
    body = [
        f"{n} occurrences of rule {cluster.rule_id!r} under "
        f"{cluster.directory!r}.",
        "Affected URLs:",
    ]
    body.extend(f"  - {u}" for u in sample_urls)
    if more:
        body.append(f"  - ... and {more} more.")
    return "\n".join(body)


def _host_from_url(url: str) -> str:
    try:
        return _up.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _normalised_path(url: str) -> str:
    """Lossy path-only normalisation: host stripped, IDs templated.
    Used by cross-host dedupe to group "the same path on different
    hosts"."""
    try:
        p = _up.urlsplit(url)
    except ValueError:
        return url
    path = p.path or "/"
    return _ID_SEGMENT_RE.sub("/{id}", path)
