"""Phase 11 — issue noise reduction + consolidation.

The Burp-parity consolidation pass has three orthogonal mechanisms,
each individually testable:

1. Same-host directory roll-up (the most user-visible win).
2. Frequent-insertion-point lightweight gating.
3. Cross-host backend dedupe via the ``Server`` header.

All three are opt-in. The tests below cover settings round-trip,
URL clustering, backend signature extraction, the insertion-point
cache extension, and end-to-end scanner integration.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.scanner.consolidation import (
    ConsolidationResult,
    ConsolidationSettings,
    cluster_findings_by_directory,
    consolidate_frequent_findings,
    directory_of,
    extract_backend_signature,
    load_settings,
    save_settings,
    should_use_lightweight_mode,
)
from reqlore.scanner.engine import Scanner
from reqlore.scanner.insertion_points import (
    InsertionPoint,
    InsertionPointCache,
)
from reqlore.storage import Project

# ---------------------------------------------------------------------------
# 1) ConsolidationSettings dataclass validation.
# ---------------------------------------------------------------------------

class TestConsolidationSettings:

    def test_defaults_are_conservative(self) -> None:
        s = ConsolidationSettings()
        assert s.enabled is False
        assert s.cross_host_enabled is False
        assert s.path_rollup_threshold == 5
        assert s.ip_lightweight_threshold == 50

    def test_rejects_path_threshold_below_floor(self) -> None:
        with pytest.raises(ValueError, match="path_rollup_threshold"):
            ConsolidationSettings(path_rollup_threshold=2)

    def test_rejects_ip_threshold_below_floor(self) -> None:
        with pytest.raises(ValueError, match="ip_lightweight_threshold"):
            ConsolidationSettings(ip_lightweight_threshold=9)

    def test_high_values_accepted(self) -> None:
        s = ConsolidationSettings(
            path_rollup_threshold=999,
            ip_lightweight_threshold=10_000,
        )
        assert s.path_rollup_threshold == 999
        assert s.ip_lightweight_threshold == 10_000


# ---------------------------------------------------------------------------
# 2) Settings persistence via project_state KV.
# ---------------------------------------------------------------------------

class TestSettingsRoundTrip:

    def test_defaults_when_unset(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        s = load_settings(proj)
        assert s == ConsolidationSettings()

    def test_save_then_load(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        save_settings(proj, ConsolidationSettings(
            enabled=True,
            path_rollup_threshold=7,
            ip_lightweight_threshold=80,
            cross_host_enabled=True,
        ))
        loaded = load_settings(proj)
        assert loaded.enabled is True
        assert loaded.path_rollup_threshold == 7
        assert loaded.ip_lightweight_threshold == 80
        assert loaded.cross_host_enabled is True

    def test_save_rejects_invalid(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        # Bypass __post_init__ would be cheating; pass a fresh value
        # that the dataclass refuses to construct.
        with pytest.raises(ValueError):
            save_settings(proj, ConsolidationSettings(
                path_rollup_threshold=1,
            ))

    def test_garbage_int_in_kv_falls_back_to_default(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        proj.set_state("consolidation:path_rollup_threshold", "not-a-number")
        s = load_settings(proj)
        assert s.path_rollup_threshold == 5

    def test_below_floor_in_kv_falls_back_to_default(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        proj.set_state("consolidation:path_rollup_threshold", "1")
        s = load_settings(proj)
        assert s.path_rollup_threshold == 5


# ---------------------------------------------------------------------------
# 3) URL helpers.
# ---------------------------------------------------------------------------

class TestDirectoryOf:

    def test_strips_trailing_filename(self) -> None:
        assert directory_of(
            "https://x.y/api/v1/users/42/profile"
        ) == "https://x.y/api/v1/users/{id}/"

    def test_preserves_trailing_slash_directory(self) -> None:
        assert directory_of(
            "https://x.y/api/v1/users/42/"
        ) == "https://x.y/api/v1/users/{id}/"

    def test_root_path(self) -> None:
        assert directory_of("https://x.y/") == "https://x.y/"

    def test_no_path(self) -> None:
        # urlsplit treats missing path as "" which we normalise to "/".
        assert directory_of("https://x.y") == "https://x.y/"

    def test_uuid_segment_is_templated(self) -> None:
        d = directory_of(
            "https://x.y/items/12345678-1234-1234-1234-123456789abc/edit"
        )
        assert d == "https://x.y/items/{id}/"

    def test_empty_string(self) -> None:
        assert directory_of("") == ""

    def test_invalid_url_returned_verbatim(self) -> None:
        assert directory_of("not-a-url") == "not-a-url"


# ---------------------------------------------------------------------------
# 4) Clustering.
# ---------------------------------------------------------------------------

class TestClusterFindings:

    @staticmethod
    def _f(rid: str, url: str, sev: str = "low") -> dict:
        return {"id": 1, "rule_id": rid, "url": url,
                "severity": sev, "host": "x.y"}

    def test_groups_by_rule_and_directory(self) -> None:
        rows = [
            self._f("R1", "https://x.y/api/users/1/profile"),
            self._f("R1", "https://x.y/api/users/2/profile"),
            self._f("R1", "https://x.y/api/users/3/profile"),
            self._f("R2", "https://x.y/api/users/1/profile"),
        ]
        out = cluster_findings_by_directory(rows)
        # Two clusters: (R1, .../users/{id}/) and (R2, .../users/{id}/).
        assert len(out) == 2
        by_rule = {c.rule_id: c for c in out}
        assert len(by_rule["R1"].findings) == 3
        assert len(by_rule["R2"].findings) == 1

    def test_skips_rows_missing_rule_or_url(self) -> None:
        rows = [
            self._f("", "https://x.y/x"),
            self._f("R1", ""),
            {"rule_id": "R1", "url": None},
            self._f("R1", "https://x.y/a/1"),
        ]
        out = cluster_findings_by_directory(rows)
        assert len(out) == 1
        assert len(out[0].findings) == 1


# ---------------------------------------------------------------------------
# 5) Backend signature extraction.
# ---------------------------------------------------------------------------

class TestExtractBackendSignature:

    def test_basic_apache(self) -> None:
        resp = (b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4.61 (Ubuntu)\r\n"
                b"Content-Length: 0\r\n\r\n")
        assert extract_backend_signature(resp) == "apache"

    def test_basic_nginx(self) -> None:
        resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\n\r\n"
        assert extract_backend_signature(resp) == "nginx"

    def test_no_server_header(self) -> None:
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        assert extract_backend_signature(resp) == ""

    def test_empty_blob(self) -> None:
        assert extract_backend_signature(b"") == ""
        assert extract_backend_signature(None) == ""

    def test_case_insensitive(self) -> None:
        resp = b"HTTP/1.1 200 OK\r\nSERVER: Cloudflare\r\n\r\n"
        assert extract_backend_signature(resp) == "cloudflare"


# ---------------------------------------------------------------------------
# 6) InsertionPointCache — Phase 11 counters.
# ---------------------------------------------------------------------------

class TestInsertionPointCacheCounters:

    @staticmethod
    def _point(name: str = "id") -> InsertionPoint:
        return InsertionPoint(
            ip_type="query", name=name, value="v",
            location="query",
        )

    def test_probe_and_fire_counts_start_zero(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        assert c.probe_count(rule_id="R", point=p) == 0
        assert c.fire_count(rule_id="R", point=p) == 0

    def test_record_probe_increments(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        c.record_probe(rule_id="R", point=p)
        c.record_probe(rule_id="R", point=p)
        c.record_probe(rule_id="R", point=p)
        assert c.probe_count(rule_id="R", point=p) == 3
        assert c.fire_count(rule_id="R", point=p) == 0

    def test_record_fire_independent(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        c.record_probe(rule_id="R", point=p)
        c.record_fire(rule_id="R", point=p)
        assert c.probe_count(rule_id="R", point=p) == 1
        assert c.fire_count(rule_id="R", point=p) == 1

    def test_counts_keyed_by_rule_id(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        c.record_probe(rule_id="R1", point=p)
        c.record_probe(rule_id="R2", point=p)
        assert c.probe_count(rule_id="R1", point=p) == 1
        assert c.probe_count(rule_id="R2", point=p) == 1
        assert c.probe_count(rule_id="R3", point=p) == 0

    def test_counts_keyed_by_point_name(self) -> None:
        c = InsertionPointCache()
        c.record_probe(rule_id="R", point=self._point("a"))
        c.record_probe(rule_id="R", point=self._point("b"))
        assert c.probe_count(rule_id="R", point=self._point("a")) == 1
        assert c.probe_count(rule_id="R", point=self._point("b")) == 1


class TestLightweightModePredicate:

    @staticmethod
    def _point() -> InsertionPoint:
        return InsertionPoint(
            ip_type="query", name="csrf", value="v",
            location="query",
        )

    def test_false_below_threshold(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        for _ in range(10):
            c.record_probe(rule_id="R", point=p)
        assert should_use_lightweight_mode(
            c, rule_id="R", point=p, threshold=50,
        ) is False

    def test_true_above_threshold_and_no_fires(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        for _ in range(51):
            c.record_probe(rule_id="R", point=p)
        assert should_use_lightweight_mode(
            c, rule_id="R", point=p, threshold=50,
        ) is True

    def test_false_when_at_least_one_fire(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        for _ in range(100):
            c.record_probe(rule_id="R", point=p)
        c.record_fire(rule_id="R", point=p)
        assert should_use_lightweight_mode(
            c, rule_id="R", point=p, threshold=50,
        ) is False

    def test_false_for_legacy_cache_without_counters(self) -> None:
        class _Old:
            pass
        assert should_use_lightweight_mode(
            _Old(), rule_id="R", point=self._point(), threshold=50,
        ) is False

    def test_false_for_zero_threshold(self) -> None:
        c = InsertionPointCache()
        p = self._point()
        for _ in range(1000):
            c.record_probe(rule_id="R", point=p)
        assert should_use_lightweight_mode(
            c, rule_id="R", point=p, threshold=0,
        ) is False


# ---------------------------------------------------------------------------
# 7) consolidate_frequent_findings — end-to-end on a real Project.
# ---------------------------------------------------------------------------

def _seed_findings(
    proj: Project, *, rule_id: str, host: str,
    base_url: str, count: int,
) -> list[int]:
    """Helper: insert ``count`` findings with the same rule_id under
    a directory but on distinct URLs, each with a distinct evidence
    string so dedupe does NOT collapse them at storage time."""
    ids: list[int] = []
    for i in range(count):
        url = f"{base_url}/{i}/profile"
        fid = proj.add_finding(
            severity="medium",
            title="Missing X-Foo header",
            host=host,
            url=url,
            rule_id=rule_id,
            evidence=f"distinct-evidence-{i}",
            payload="",
        )
        ids.append(fid)
    return ids


class TestConsolidateFrequentFindingsDirectoryRollup:

    def test_disabled_is_noop(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        _seed_findings(
            proj, rule_id="R1", host="x.y",
            base_url="https://x.y/api/users", count=10,
        )
        before = len(proj.list_findings(limit=500))
        res = consolidate_frequent_findings(
            proj, settings=ConsolidationSettings(enabled=False),
        )
        after = len(proj.list_findings(limit=500))
        assert res.directory_rollups == 0
        assert res.findings_triaged == 0
        assert before == after

    def test_below_threshold_no_rollup(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        _seed_findings(
            proj, rule_id="R1", host="x.y",
            base_url="https://x.y/api/users", count=4,
        )
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, path_rollup_threshold=5,
            ),
        )
        assert res.directory_rollups == 0
        assert res.findings_triaged == 0
        opens = proj.list_findings(status="open", limit=500)
        assert len(opens) == 4

    def test_above_threshold_creates_rollup_and_triages(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        _seed_findings(
            proj, rule_id="R1", host="x.y",
            base_url="https://x.y/api/users", count=6,
        )
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, path_rollup_threshold=5,
            ),
        )
        assert res.directory_rollups == 1
        assert res.findings_triaged == 6
        opens = proj.list_findings(status="open", limit=500)
        assert len(opens) == 1
        rollup = opens[0]
        assert rollup["source"] == "consolidation"
        assert rollup["url"] == "https://x.y/api/users/{id}/"
        assert "consolidated:directory" in (
            rollup.get("fingerprint_tags") or ""
        )

    def test_different_rules_never_merge(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        _seed_findings(
            proj, rule_id="R1", host="x.y",
            base_url="https://x.y/api/users", count=6,
        )
        _seed_findings(
            proj, rule_id="R2", host="x.y",
            base_url="https://x.y/api/users", count=6,
        )
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, path_rollup_threshold=5,
            ),
        )
        # One rollup per rule.
        assert res.directory_rollups == 2

    def test_idempotent_second_call_does_not_re_roll(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        _seed_findings(
            proj, rule_id="R1", host="x.y",
            base_url="https://x.y/api/users", count=6,
        )
        settings = ConsolidationSettings(
            enabled=True, path_rollup_threshold=5,
        )
        first = consolidate_frequent_findings(proj, settings=settings)
        assert first.directory_rollups == 1
        # Second call sees only the freshly-created rollup as "open";
        # all originals are now triaged so the cluster has size 1 and
        # is below threshold.
        second = consolidate_frequent_findings(proj, settings=settings)
        assert second.directory_rollups == 0


class TestConsolidateCrossHost:

    def _seed_cross_host(
        self, proj: Project, hosts: list[str], server: str,
    ) -> None:
        """Seed one history row per host with the given Server header,
        then insert a finding referencing that history row."""
        for h in hosts:
            raw_req = b"GET / HTTP/1.1\r\nHost: " + h.encode() + b"\r\n\r\n"
            raw_resp = (b"HTTP/1.1 200 OK\r\n"
                        b"Server: " + server.encode() + b"\r\n"
                        b"Content-Length: 0\r\n\r\n")
            hid = proj.add_history(
                host=h, method="GET", url=f"https://{h}/dash",
                status=200, duration_ms=1, engine="test",
                raw_req=raw_req, raw_resp=raw_resp,
            )
            proj.add_finding(
                severity="low", title="Cookie missing Secure flag",
                host=h, url=f"https://{h}/dash",
                rule_id="R-cookie",
                request_id=hid,
                evidence=f"cookie-evidence-{h}",
            )

    def test_disabled_keeps_hosts_separate(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        self._seed_cross_host(proj, ["a.x", "b.x", "c.x"], "Apache/2.4")
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, cross_host_enabled=False,
            ),
        )
        assert res.cross_host_collapses == 0
        opens = proj.list_findings(status="open", limit=500)
        assert len(opens) == 3

    def test_enabled_collapses_shared_backend(self, tmp_path: Path) -> None:
        proj = Project(tmp_path / "p.rlr")
        self._seed_cross_host(proj, ["a.x", "b.x", "c.x"], "Apache/2.4")
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, cross_host_enabled=True,
            ),
        )
        assert res.backend_rollups == 1
        assert res.cross_host_collapses == 2
        opens = proj.list_findings(status="open", limit=500)
        # Two collapsed → one survivor per backend cluster.
        assert len(opens) == 1

    def test_enabled_but_distinct_backends_no_collapse(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        self._seed_cross_host(proj, ["a.x"], "Apache/2.4")
        self._seed_cross_host(proj, ["b.x"], "nginx/1.27")
        res = consolidate_frequent_findings(
            proj,
            settings=ConsolidationSettings(
                enabled=True, cross_host_enabled=True,
            ),
        )
        assert res.cross_host_collapses == 0
        opens = proj.list_findings(status="open", limit=500)
        assert len(opens) == 2


# ---------------------------------------------------------------------------
# 8) Scanner integration: post-scan hook runs and mirrors counters.
# ---------------------------------------------------------------------------

class TestScannerPostScanHook:

    def test_disabled_consolidation_yields_zero_counters(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        scanner = Scanner(rules=[])  # no rules → no findings
        res = scanner.scan_project(
            proj, limit=10, deadline_seconds=2.0,
            respect_scope=False,
        )
        assert res.consolidation_directory_rollups == 0
        assert res.consolidation_findings_triaged == 0
        assert res.consolidation_cross_host_collapses == 0
        assert res.consolidation_backend_rollups == 0

    def test_enabled_hook_runs_when_findings_exceed_threshold(
        self, tmp_path: Path,
    ) -> None:
        proj = Project(tmp_path / "p.rlr")
        # Pre-seed findings so the hook has something to consolidate.
        _seed_findings(
            proj, rule_id="R-x", host="x.y",
            base_url="https://x.y/api/users", count=6,
        )
        save_settings(proj, ConsolidationSettings(
            enabled=True, path_rollup_threshold=5,
        ))
        scanner = Scanner(rules=[])
        res = scanner.scan_project(
            proj, limit=10, deadline_seconds=2.0,
            respect_scope=False,
        )
        assert res.consolidation_directory_rollups == 1
        assert res.consolidation_findings_triaged == 6


# ---------------------------------------------------------------------------
# 9) ConsolidationResult dataclass.
# ---------------------------------------------------------------------------

class TestConsolidationResult:

    def test_defaults_are_zero(self) -> None:
        r = ConsolidationResult()
        assert r.clusters_examined == 0
        assert r.directory_rollups == 0
        assert r.findings_triaged == 0
        assert r.backend_rollups == 0
        assert r.cross_host_collapses == 0
        assert r.elapsed_ms == 0
