"""SQLite-backed project file. Single facade for all reads + writes."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid as _uuid
import zlib
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_VERSION = 6

_SCHEMA = """
CREATE TABLE IF NOT EXISTS project (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    settings_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS http_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER NOT NULL,
    len_req INTEGER NOT NULL,
    len_resp INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    engine TEXT NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    req_blob BLOB NOT NULL,
    resp_blob BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON http_history(ts);
CREATE INDEX IF NOT EXISTS idx_history_host ON http_history(host);
CREATE INDEX IF NOT EXISTS idx_history_status ON http_history(status);
CREATE INDEX IF NOT EXISTS idx_history_method ON http_history(method);

CREATE TABLE IF NOT EXISTS intercept_q (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                -- 'request' | 'response'
    req_blob BLOB NOT NULL,
    hold_reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    flow_id TEXT,                      -- mitmproxy flow id when sync-held
    decision TEXT,                     -- NULL | 'forward' | 'drop' | 'forward_edited'
    edited_blob BLOB,
    parent_intercept_id INTEGER        -- Phase 15: redirect chain linkage
);
CREATE INDEX IF NOT EXISTS idx_intercept_flow ON intercept_q(flow_id);

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL,            -- info | low | medium | high | critical
    cwe TEXT,
    owasp TEXT,
    title TEXT NOT NULL,
    host TEXT,
    url TEXT,
    request_id INTEGER,
    response_id INTEGER,
    evidence TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,              -- 'history' | 'issue' | 'project'
    target_id INTEGER,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    author TEXT NOT NULL DEFAULT 'me'
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                -- 'include' | 'exclude'
    pattern TEXT NOT NULL,             -- regex on host or full URL
    target TEXT NOT NULL DEFAULT 'host',  -- 'host' | 'url'
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS match_replace (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enabled INTEGER NOT NULL DEFAULT 1,
    where_ TEXT NOT NULL,              -- 'req_header' | 'req_body' | 'resp_header' | 'resp_body'
    is_regex INTEGER NOT NULL DEFAULT 0,
    host_regex TEXT NOT NULL DEFAULT '',
    pattern TEXT NOT NULL,
    replacement TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intruder_attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    attack_type TEXT NOT NULL,         -- sniper | battering | pitchfork | clusterbomb
    template_blob BLOB NOT NULL,       -- raw HTTP req with §marker§ positions
    positions_json TEXT NOT NULL,      -- JSON array of (start, end) byte offsets per marker
    payloads_json TEXT NOT NULL,       -- JSON array of payload-set arrays
    options_json TEXT NOT NULL DEFAULT '{}',  -- {concurrency, delay_ms, encode, grep, sort_by}
    url TEXT NOT NULL,
    engine TEXT NOT NULL DEFAULT 'httpx',
    status TEXT NOT NULL DEFAULT 'idle',  -- idle | running | paused | done | cancelled | errored
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS intruder_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    payloads_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    len_resp INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    grep_hits TEXT NOT NULL DEFAULT '',
    history_id INTEGER,                -- link to http_history row
    FOREIGN KEY (attack_id) REFERENCES intruder_attacks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_intr_attack ON intruder_results(attack_id);

CREATE TABLE IF NOT EXISTS finding_targets (
    finding_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    host TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (finding_id, host, url)
);

CREATE TABLE IF NOT EXISTS finding_suppressions (
    rule_id TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    url_pattern TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (rule_id, host, url_pattern)
);

-- Phase 3 (Burp parity): every duplicate that hits an existing dedupe
-- key appends a row here so we can show "issue fired N times across
-- these specific URLs / requests" without inflating ``issues`` itself.
CREATE TABLE IF NOT EXISTS finding_occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    url TEXT NOT NULL DEFAULT '',
    request_id INTEGER,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_focc_fid ON finding_occurrences(finding_id);

CREATE TABLE IF NOT EXISTS finding_reproductions (
    token TEXT PRIMARY KEY,
    request_blob BLOB,
    response_blob BLOB,
    method TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER NOT NULL,
    elapsed_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL DEFAULT 0,
    host TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    fired INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    run_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rule_runs_host ON rule_runs(host, rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_runs_rule ON rule_runs(rule_id);

CREATE TABLE IF NOT EXISTS dom_hunter_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    page_url TEXT NOT NULL DEFAULT '',
    frame_url TEXT NOT NULL DEFAULT '',
    sink TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    canary_seen INTEGER NOT NULL DEFAULT 0,
    value TEXT NOT NULL DEFAULT '',
    stack TEXT NOT NULL DEFAULT '',
    dedupe_key TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dom_hunter_dedupe ON dom_hunter_findings(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_dom_hunter_ts ON dom_hunter_findings(ts);
CREATE INDEX IF NOT EXISTS idx_dom_hunter_sev ON dom_hunter_findings(severity);

CREATE TABLE IF NOT EXISTS dom_hunter_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    page_url TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '',
    has_canary INTEGER NOT NULL DEFAULT 0,
    handler_stack TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dom_hunter_msg_ts ON dom_hunter_messages(ts);

CREATE TABLE IF NOT EXISTS sequencer_captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    template_blob BLOB NOT NULL,        -- raw HTTP request to replay
    engine TEXT NOT NULL DEFAULT 'httpx',
    extractor_kind TEXT NOT NULL,       -- cookie | header | regex | json
    extractor_arg TEXT NOT NULL DEFAULT '',
    max_samples INTEGER NOT NULL DEFAULT 200,
    delay_ms INTEGER NOT NULL DEFAULT 0,
    concurrency INTEGER NOT NULL DEFAULT 1,
    significance TEXT NOT NULL DEFAULT '0.01',
    status TEXT NOT NULL DEFAULT 'idle', -- idle|running|paused|done|cancelled|errored
    stop_reason TEXT NOT NULL DEFAULT '',
    error_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sequencer_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    token TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    captured_at INTEGER NOT NULL,
    FOREIGN KEY (capture_id) REFERENCES sequencer_captures(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_seqcap_capture ON sequencer_samples(capture_id);

-- Phase 1.1 — live passive scan backlog. Rows that overflow the in-
-- memory queue (or that were enqueued during a previous run that
-- exited before processing them) are parked here so the worker can
-- drain them on idle. Nothing is ever silently dropped.
--
-- ``retries`` lets a misbehaving rule's row be skipped after repeated
-- failures rather than wedging the backlog forever. ``ts`` is the
-- monotonic enqueue time so we can drain FIFO (oldest first) — which
-- is the opposite of the in-memory queue's drop policy: when we are
-- catching up from disk we want the foundational early traffic
-- (login, security headers) processed first.
CREATE TABLE IF NOT EXISTS live_scan_backlog (
    hid INTEGER PRIMARY KEY,            -- history-row id; UNIQUE on its own
    ts INTEGER NOT NULL,                -- epoch seconds when parked
    retries INTEGER NOT NULL DEFAULT 0,
    -- 0 == idle / claimable; >0 == "claimed at epoch seconds N" by a
    -- worker that is scanning the row right now. We never DELETE on
    -- pop, only set claimed_at; that way a worker crash mid-scan
    -- leaves the row recoverable on restart (claims are reset).
    claimed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_live_scan_backlog_ts ON live_scan_backlog(ts);
CREATE INDEX IF NOT EXISTS idx_live_scan_backlog_claim
    ON live_scan_backlog(claimed_at, ts);

-- Phase 16 — Plugin Apps. Each row is one execution of one plugin
-- app (identified by slug). ``settings_json`` is the validated form
-- dict at run time, ``results_json`` is a JSON list of result rows
-- the plugin appended live, ``log`` is a plain-text scroll-back. We
-- store all of it in one row so a polling endpoint can produce a
-- consistent snapshot with a single SELECT.
--
-- ``status`` transitions: pending -> running -> ok | error |
-- cancelled | timeout. ``error`` carries an exception summary when
-- status == error (everything else leaves it empty).
CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL,
    settings_json TEXT NOT NULL,
    log TEXT NOT NULL DEFAULT '',
    results_json TEXT NOT NULL DEFAULT '[]',
    progress_done INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    progress_msg TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    -- Phase 16+ — history id the run was seeded from (Send-to-plugin).
    -- NULL when the operator launched the plugin from its own page.
    seed_history_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_plugin_runs_slug_started
    ON plugin_runs(slug, started_at);
CREATE INDEX IF NOT EXISTS idx_plugin_runs_status
    ON plugin_runs(status);

-- Phase 17 — Auth Matrix.
--
-- Named authentication identities the operator can replay history
-- requests under. ``kind`` enumerates the substitution shape:
--   * ``cookie``     — payload is the Cookie header value
--   * ``bearer``     — payload is "Bearer <token>" (or just the token)
--   * ``header``     — payload is a single ``Name: Value`` line
--   * ``multi``      — payload is one ``Name: Value`` per line
--   * ``anon``       — payload is empty; sends with NO auth headers
-- ``payload_blob`` is encrypted with the per-project key derived in
-- :mod:`reqlore.auth_matrix.crypto`. Plaintext is never written.
CREATE TABLE IF NOT EXISTS auth_matrix_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload_blob BLOB NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    source_hid INTEGER,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_auth_matrix_sessions_active
    ON auth_matrix_sessions(active);

-- One row per launched Auth Matrix run (active replay or shadow
-- pickup). ``mode`` is ``active`` (operator-chosen rows × sessions)
-- or ``shadow`` (one passive cell per proxied response).
--
-- ``baseline_session_id`` is the identity whose responses every
-- compare cell is normalised against (NULL when there is no
-- baseline — every cell stands alone).
--
-- ``compare_session_ids_json`` is the ordered JSON list of session
-- ids that form the compare columns.
--
-- ``options_json`` carries similarity threshold, privileged-path
-- hints, normaliser toggles, engine + delay (see auth_matrix.RunOptions).
CREATE TABLE IF NOT EXISTS auth_matrix_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    baseline_session_id INTEGER,
    compare_session_ids_json TEXT NOT NULL DEFAULT '[]',
    history_ids_json TEXT NOT NULL DEFAULT '[]',
    options_json TEXT NOT NULL DEFAULT '{}',
    progress_done INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    progress_msg TEXT NOT NULL DEFAULT '',
    log TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    verdict_counts_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_auth_matrix_runs_mode_started
    ON auth_matrix_runs(mode, started_at);
CREATE INDEX IF NOT EXISTS idx_auth_matrix_runs_status
    ON auth_matrix_runs(status);

-- One cell per (run, history_id, session) pair. ``baseline_status``
-- and ``baseline_len`` reflect the baseline session's response for
-- the same request; NULL when no baseline is configured.
--
-- ``similarity_pct`` is 0-100 after the normaliser ran on both
-- bodies. ``verdict`` is the heuristic label
-- (``bypass-suspect``, ``denied-correctly``, ``denied-status-only``,
-- ``different-payload``, ``error``, ``dismissed``). ``finding_id``
-- links to the issues row when the verdict warranted one.
--
-- ``response_blob`` is the truncated raw response (capped at 64 KiB)
-- so the cell-detail diff page can render side-by-side without
-- re-sending. ``request_blob`` is the exact bytes sent (post
-- session substitution).
CREATE TABLE IF NOT EXISTS auth_matrix_cells (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES auth_matrix_runs(id) ON DELETE CASCADE,
    history_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    body_len INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    baseline_status INTEGER,
    baseline_len INTEGER,
    similarity_pct INTEGER NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    request_blob BLOB,
    response_blob BLOB,
    baseline_response_blob BLOB,
    finding_id INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_matrix_cells_run
    ON auth_matrix_cells(run_id, history_id);
CREATE INDEX IF NOT EXISTS idx_auth_matrix_cells_verdict
    ON auth_matrix_cells(run_id, verdict);
"""


def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=6) if data else b""


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data) if data else b""


def _row_to_plugin_run(r: tuple) -> dict:
    """Materialise a ``plugin_runs`` row tuple into a dict. JSON
    columns are decoded defensively — a corrupt row never crashes the
    caller."""
    try:
        settings = json.loads(r[5]) if r[5] else {}
        if not isinstance(settings, dict):
            settings = {}
    except (TypeError, ValueError):
        settings = {}
    try:
        results = json.loads(r[7]) if r[7] else []
        if not isinstance(results, list):
            results = []
    except (TypeError, ValueError):
        results = []
    seed_hid = None
    # Column 12 only exists on schema >= 5; tuples from older selects
    # that don't list the column will be 12-long and we'll skip this.
    if len(r) > 12 and r[12] is not None:
        try:
            seed_hid = int(r[12])
        except (TypeError, ValueError):
            seed_hid = None
    return {
        "id": int(r[0]),
        "slug": r[1] or "",
        "started_at": int(r[2] or 0),
        "finished_at": int(r[3]) if r[3] is not None else None,
        "status": r[4] or "",
        "settings": settings,
        "log": r[6] or "",
        "results": results,
        "progress_done": int(r[8] or 0),
        "progress_total": int(r[9] or 0),
        "progress_msg": r[10] or "",
        "error": r[11] or "",
        "seed_history_id": seed_hid,
    }


def _host_matches(pattern: str, host: str) -> bool:
    """Match a suppression host pattern against a candidate host.

    Empty pattern matches any host. A leading ``*.`` matches the literal host
    and any subdomain. Otherwise an exact (case-insensitive) match is required.
    """
    if not pattern:
        return True
    p = pattern.lower()
    h = (host or "").lower()
    if p.startswith("*."):
        suffix = p[1:]
        return h == p[2:] or h.endswith(suffix)
    return h == p


@dataclass
class HistoryRow:
    id: int
    ts: int
    host: str
    method: str
    url: str
    status: int
    len_req: int
    len_resp: int
    duration_ms: int
    engine: str
    flags: str
    tags: str
    req_blob: bytes = field(repr=False)
    resp_blob: bytes = field(repr=False)


@dataclass
class InterceptRow:
    id: int
    kind: str
    req_blob: bytes = field(repr=False)
    hold_reason: str = ""
    created_at: int = 0
    parent_intercept_id: int | None = None


class Project:
    """Thread-safe SQLite facade for one .rlr file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        first_open = not self.path.exists()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None,  # autocommit
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # M-4: overwrite freed pages so deleted history / findings
        # cannot be carved out of the database file by a forensic
        # analysis after the fact. Cheap on the small write volumes
        # Reqlore generates.
        self._conn.execute("PRAGMA secure_delete=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        if first_open or self._conn.execute("SELECT COUNT(*) FROM project").fetchone()[0] == 0:
            self._conn.execute(
                "INSERT INTO project(name, created_at, schema_version) VALUES (?, ?, ?)",
                (self.path.stem, int(time.time()), SCHEMA_VERSION),
            )
        else:
            self._conn.execute(
                "UPDATE project SET schema_version=? WHERE schema_version<?",
                (SCHEMA_VERSION, SCHEMA_VERSION),
            )

    def _migrate(self) -> None:
        """Idempotent ALTERs for columns added after v1."""
        adds = [
            ("intercept_q", "flow_id", "TEXT"),
            ("intercept_q", "decision", "TEXT"),
            ("intercept_q", "edited_blob", "BLOB"),
            # Phase 15 — redirect chain linkage. Nullable: pre-existing
            # rows and any unrelated held request keep NULL.
            ("intercept_q", "parent_intercept_id", "INTEGER"),
            # Phase 16+ — Send-to-plugin link from history/intercept into
            # a plugin app run. Nullable: launches from the plugin's own
            # page never set this.
            ("plugin_runs", "seed_history_id", "INTEGER"),
            ("scope_rules", "target", "TEXT NOT NULL DEFAULT 'host'"),
            ("intruder_results", "body_md5", "TEXT NOT NULL DEFAULT ''"),
            ("intruder_results", "matched", "INTEGER NOT NULL DEFAULT 0"),
            ("issues", "uuid", "TEXT"),
            ("issues", "source", "TEXT NOT NULL DEFAULT 'scanner'"),
            ("issues", "rule_id", "TEXT NOT NULL DEFAULT ''"),
            ("issues", "rule_version", "INTEGER NOT NULL DEFAULT 0"),
            ("issues", "description", "TEXT NOT NULL DEFAULT ''"),
            ("issues", "remediation", "TEXT NOT NULL DEFAULT ''"),
            ("issues", "references_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("issues", "cvss_vector", "TEXT"),
            ("issues", "cvss_score", "REAL"),
            ("issues", "reproduction_token", "TEXT"),
            ("issues", "updated_at", "INTEGER"),
            ("issues", "dedupe_key", "TEXT"),
            # Phase 3 (v4) ---------------------------------------------------
            # Burp-parity confidence model. Default is ``"firm"`` so any
            # finding written before this migration ran shows up as
            # ``firm`` (the historical assumption) rather than
            # ``tentative``.
            ("issues", "confidence", "TEXT NOT NULL DEFAULT 'firm'"),
            # Number of times this dedupe key has fired. Starts at 1 on
            # first insert and is bumped on every duplicate that would
            # otherwise be silently dropped \u2014 surfaces "this issue is
            # everywhere" in the UI without inflating the issue list.
            ("issues", "occurrence_count", "INTEGER NOT NULL DEFAULT 1"),
            # Comma-separated tags from response fingerprinting (e.g.
            # ``"behind_waf:cloudflare,error_page:flask_debug"``). Empty
            # when nothing matched.
            ("issues", "fingerprint_tags", "TEXT NOT NULL DEFAULT ''"),
            # Timestamp of the most recent occurrence (separate from
            # ``updated_at`` which also moves on triage changes).
            ("issues", "last_seen_at", "INTEGER"),
            # ----------------------------------------------------------------
            ("live_scan_backlog", "claimed_at",
             "INTEGER NOT NULL DEFAULT 0"),
        ]
        for table, col, decl in adds:
            cols = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                with suppress(sqlite3.OperationalError):
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        # Indices we want even on freshly-migrated databases.
        for ddl in (
            "CREATE INDEX IF NOT EXISTS idx_issues_source ON issues(source)",
            "CREATE INDEX IF NOT EXISTS idx_issues_uuid ON issues(uuid)",
            "CREATE INDEX IF NOT EXISTS idx_issues_rule ON issues(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_issues_dedupe ON issues(dedupe_key)",
        ):
            with suppress(sqlite3.OperationalError):
                self._conn.execute(ddl)
        # Backfill uuid + updated_at for any pre-v3 rows.
        try:
            rows = self._conn.execute(
                "SELECT id, created_at FROM issues WHERE uuid IS NULL OR uuid = ''"
            ).fetchall()
            for rid, created in rows:
                self._conn.execute(
                    "UPDATE issues SET uuid=?, updated_at=COALESCE(updated_at,?) WHERE id=?",
                    (_uuid.uuid4().hex, created, rid),
                )
        except sqlite3.OperationalError:
            pass

    # ---- low-level helpers ----
    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            # M-4: roll the WAL into the main DB and switch back to a
            # rollback journal before closing, so leftover ``-wal`` /
            # ``-shm`` sidecars do not retain plaintext copies of
            # rows that ``secure_delete`` has already overwritten in
            # the main file.
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.execute("PRAGMA journal_mode=DELETE")
            except sqlite3.OperationalError:
                pass
            self._conn.close()

    # ---- project meta ----
    def meta(self) -> dict:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT name, created_at, schema_version, settings_json "
                "FROM project"
            ).fetchone()
        return {"name": r[0], "created_at": r[1], "schema_version": r[2],
                "settings": json.loads(r[3])}

    def get_state(self, key: str, default: str = "") -> str:
        with self._cursor() as cur:
            r = cur.execute("SELECT value FROM project_state WHERE key=?", (key,)).fetchone()
        return r[0] if r else default

    def set_state(self, key: str, value: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO project_state(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ---- history ----
    def add_history(
        self, *, host: str, method: str, url: str, status: int,
        duration_ms: int, engine: str, raw_req: bytes, raw_resp: bytes,
        flags: str = "", tags: str = "",
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO http_history(ts,host,method,url,status,len_req,len_resp,"
                "duration_ms,engine,flags,tags,req_blob,resp_blob) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (int(time.time()), host, method, url, status,
                 len(raw_req), len(raw_resp), duration_ms, engine, flags, tags,
                 _compress(raw_req), _compress(raw_resp)),
            )
            return int(cur.lastrowid or 0)

    def list_history(
        self, *, limit: int = 200, offset: int = 0,
        host: str | None = None, q: str | None = None,
        method: str | None = None,
        host_mode: str = "exact",
        q_regex: bool = False,
        methods: list[str] | None = None,
        statuses: list[str] | None = None,
        engines: list[str] | None = None,
        len_min: int | None = None, len_max: int | None = None,
        dur_min: int | None = None, dur_max: int | None = None,
    ) -> list[HistoryRow]:
        sql = ("SELECT id,ts,host,method,url,status,len_req,len_resp,duration_ms,"
               "engine,flags,tags,req_blob,resp_blob FROM http_history WHERE 1=1")
        where, args = self._history_filters(
            host=host, q=q, method=method, host_mode=host_mode,
            q_regex=q_regex, methods=methods, statuses=statuses,
            engines=engines,
            len_min=len_min, len_max=len_max,
            dur_min=dur_min, dur_max=dur_max,
        )
        sql += where
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        out = [HistoryRow(*r[:12], _decompress(r[12]), _decompress(r[13])) for r in rows]  # type: ignore[call-arg]  # mypy can't verify r[:12] length; slice yields exactly 12 by SELECT above
        # Regex URL filter is applied in Python because SQLite's REGEXP
        # operator is not bundled by default. The candidate set is
        # already narrowed by every other clause + LIKE, so this stays
        # fast even on large tables.
        if q_regex and q:
            try:
                pat = __import__("re").compile(q)
            except Exception:  # noqa: BLE001 — invalid regex falls back to LIKE-only
                return out
            out = [r for r in out if pat.search(r.url)]
        return out

    def get_history(self, hid: int) -> HistoryRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,ts,host,method,url,status,len_req,len_resp,duration_ms,"
                "engine,flags,tags,req_blob,resp_blob FROM http_history WHERE id=?",
                (hid,),
            ).fetchone()
        if not r:
            return None
        return HistoryRow(*r[:12], _decompress(r[12]), _decompress(r[13]))  # type: ignore[call-arg]  # mypy can't verify r[:12] length; slice yields exactly 12 by SELECT above

    def history_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute("SELECT COUNT(*) FROM http_history").fetchone()[0])

    def count_history_after(
        self, since: int, *,
        host: str | None = None, q: str | None = None,
        method: str | None = None,
        host_mode: str = "exact",
        q_regex: bool = False,
        methods: list[str] | None = None,
        statuses: list[str] | None = None,
        engines: list[str] | None = None,
        len_min: int | None = None, len_max: int | None = None,
        dur_min: int | None = None, dur_max: int | None = None,
    ) -> tuple[int, int]:
        """Return (new_count, max_id) for rows with id > since matching filters.

        max_id is the overall MAX(id) under the same filters (0 if empty), so
        the client can advance its "since" cursor monotonically.

        ``q_regex`` is honoured by post-filtering the candidate set in
        Python; on a busy proxy the cost is negligible because the
        SQL clauses already narrow the pool.
        """
        base = " FROM http_history WHERE 1=1"
        where, args = self._history_filters(
            host=host, q=q, method=method, host_mode=host_mode,
            q_regex=q_regex, methods=methods, statuses=statuses,
            engines=engines,
            len_min=len_min, len_max=len_max,
            dur_min=dur_min, dur_max=dur_max,
        )
        base += where
        with self._cursor() as cur:
            if q_regex and q:
                # Need to inspect URLs to apply the regex — fall back to
                # selecting id+url and counting matches in Python.
                rows = cur.execute(
                    "SELECT id,url" + base, args).fetchall()
                try:
                    pat = __import__("re").compile(q)
                    matched = [r for r in rows if pat.search(r[1])]
                except Exception:  # noqa: BLE001
                    matched = rows
                max_id = max((r[0] for r in matched), default=0)
                new_count = sum(1 for r in matched if r[0] > int(since))
                return new_count, int(max_id)
            max_id = int(cur.execute("SELECT COALESCE(MAX(id), 0)" + base, args).fetchone()[0])
            new_count = int(cur.execute(
                "SELECT COUNT(*)" + base + " AND id > ?", args + [int(since)],
            ).fetchone()[0])
        return new_count, max_id

    @staticmethod
    def _history_filters(
        *, host: str | None, q: str | None, method: str | None,
        host_mode: str, q_regex: bool,
        methods: list[str] | None, statuses: list[str] | None,
        engines: list[str] | None,
        len_min: int | None, len_max: int | None,
        dur_min: int | None, dur_max: int | None,
    ) -> tuple[str, list]:
        """Build the shared WHERE-clause fragment + bound args for the
        history list/count queries. Every value is bound with a ``?``
        placeholder — no string interpolation — so this is safe even
        though the column list grew.

        ``methods`` / ``statuses`` / ``engines`` are multi-select; an
        empty list (or ``None``) means "don't constrain". ``statuses``
        accepts both buckets (``2xx``, ``3xx``…) and exact codes
        (``401``, ``500``); they OR together.
        """
        where = ""
        args: list = []
        if host:
            if host_mode == "contains":
                where += " AND host LIKE ?"
                args.append(f"%{host}%")
            else:
                where += " AND host = ?"
                args.append(host)
        # Singular ``method`` kept for backwards-compat with old
        # bookmarks; the multi-select ``methods`` is preferred.
        if methods:
            placeholders = ",".join(["?"] * len(methods))
            where += f" AND method IN ({placeholders})"
            args.extend(m.upper() for m in methods)
        elif method:
            where += " AND method = ?"
            args.append(method.upper())
        if statuses:
            clauses: list[str] = []
            for tok in statuses:
                tok = tok.strip().lower()
                if not tok:
                    continue
                if len(tok) == 3 and tok[0].isdigit() and tok.endswith("xx"):
                    lo = int(tok[0]) * 100
                    clauses.append("(status >= ? AND status < ?)")
                    args.extend([lo, lo + 100])
                else:
                    try:
                        clauses.append("status = ?")
                        args.append(int(tok))
                    except ValueError:
                        # Silently drop garbage tokens — the form layer
                        # also validates, so this is defence in depth.
                        continue
            if clauses:
                where += " AND (" + " OR ".join(clauses) + ")"
        if engines:
            placeholders = ",".join(["?"] * len(engines))
            where += f" AND engine IN ({placeholders})"
            args.extend(engines)
        if len_min is not None:
            where += " AND len_resp >= ?"
            args.append(int(len_min))
        if len_max is not None:
            where += " AND len_resp <= ?"
            args.append(int(len_max))
        if dur_min is not None:
            where += " AND duration_ms >= ?"
            args.append(int(dur_min))
        if dur_max is not None:
            where += " AND duration_ms <= ?"
            args.append(int(dur_max))
        # URL substring — LIKE is skipped when q_regex is set so the
        # regex pattern (which may use anchors / character classes) is
        # the sole authority. Otherwise we use a case-insensitive
        # substring match.
        if q and not q_regex:
            where += " AND url LIKE ?"
            args.append(f"%{q}%")
        return where, args

    def clear_history(self) -> int:
        """Delete all recorded HTTP history. Returns the number of rows removed."""
        with self._cursor() as cur:
            n = int(cur.execute("SELECT COUNT(*) FROM http_history").fetchone()[0])
            cur.execute("DELETE FROM http_history")
        return n

    # ---- intercept queue ----
    # M-3: hard cap on the intercept queue depth. Without this a runaway
    # "hold everything" rule can grow the table without bound until the
    # SQLite file fills the disk. 5000 entries is well above any normal
    # operator workflow but keeps total worst-case storage bounded.
    INTERCEPT_QUEUE_MAX = 5000

    def enqueue_intercept(self, kind: str, raw: bytes, reason: str,
                           parent_intercept_id: int | None = None) -> int:
        with self._cursor() as cur:
            depth = int(cur.execute(
                "SELECT COUNT(*) FROM intercept_q").fetchone()[0])
            if depth >= self.INTERCEPT_QUEUE_MAX:
                # Drop the new entry instead of unbounded growth. The
                # caller treats id=0 as "not enqueued".
                return 0
            cur.execute(
                "INSERT INTO intercept_q(kind,req_blob,hold_reason,created_at,parent_intercept_id) "
                "VALUES (?,?,?,?,?)",
                (kind, _compress(raw), reason, int(time.time()),
                 parent_intercept_id),
            )
            return int(cur.lastrowid or 0)

    def list_intercept(self) -> list[InterceptRow]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at,parent_intercept_id "
                "FROM intercept_q ORDER BY id"
            ).fetchall()
        return [InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4], r[5]) for r in rows]

    def get_intercept(self, iid: int) -> InterceptRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at,parent_intercept_id "
                "FROM intercept_q WHERE id=?",
                (iid,),
            ).fetchone()
        if not r:
            return None
        return InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4], r[5])

    def drop_intercept(self, iid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM intercept_q WHERE id=?", (iid,))

    def intercept_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM intercept_q WHERE decision IS NULL"
            ).fetchone()[0])

    # ---- intercept: synchronous hold support ----
    def enqueue_intercept_sync(self, kind: str, raw: bytes, reason: str,
                                flow_id: str,
                                parent_intercept_id: int | None = None) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intercept_q(kind,req_blob,hold_reason,"
                "created_at,flow_id,parent_intercept_id) "
                "VALUES (?,?,?,?,?,?)",
                (kind, _compress(raw), reason, int(time.time()), flow_id,
                 parent_intercept_id),
            )
            return int(cur.lastrowid or 0)

    def get_intercept_by_flow(self, flow_id: str) -> InterceptRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at,"
                "parent_intercept_id FROM intercept_q "
                "WHERE flow_id=? AND decision IS NULL",
                (flow_id,),
            ).fetchone()
        if not r:
            return None
        return InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4], r[5])

    def get_intercept_decision(self, iid: int) -> tuple[str | None, bytes | None]:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT decision, edited_blob FROM intercept_q WHERE id=?", (iid,),
            ).fetchone()
        if not r:
            return None, None
        return r[0], (_decompress(r[1]) if r[1] else None)

    def decide_intercept(self, iid: int, decision: str,
                          edited: bytes | None = None) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE intercept_q SET decision=?, edited_blob=? WHERE id=?",
                (decision, _compress(edited) if edited else None, iid),
            )

    # ---- scope rules ----
    def list_scope(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,kind,pattern,target,enabled FROM scope_rules ORDER BY id"
            ).fetchall()
        return [
            {"id": r[0], "kind": r[1], "pattern": r[2], "target": r[3], "enabled": bool(r[4])}
            for r in rows
        ]

    def add_scope(self, kind: str, pattern: str, target: str = "host") -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO scope_rules(kind,pattern,target,enabled) VALUES(?,?,?,1)",
                (kind, pattern, target),
            )
            return int(cur.lastrowid or 0)

    def delete_scope(self, sid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM scope_rules WHERE id=?", (sid,))

    def toggle_scope(self, sid: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE scope_rules SET enabled = 1 - enabled WHERE id=?", (sid,),
            )

    # ---- match & replace rules ----
    def list_mr(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,enabled,where_,is_regex,host_regex,pattern,replacement,comment,"
                "created_at FROM match_replace ORDER BY id"
            ).fetchall()
        return [
            {
                "id": r[0], "enabled": bool(r[1]), "where": r[2], "is_regex": bool(r[3]),
                "host_regex": r[4], "pattern": r[5], "replacement": r[6],
                "comment": r[7], "created_at": r[8],
            }
            for r in rows
        ]

    def add_mr(self, *, where: str, pattern: str, replacement: str,
               is_regex: bool, host_regex: str = "", comment: str = "") -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO match_replace(enabled,where_,is_regex,host_regex,pattern,"
                "replacement,comment,created_at) VALUES (1,?,?,?,?,?,?,?)",
                (where, int(is_regex), host_regex, pattern, replacement, comment,
                 int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def delete_mr(self, mid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM match_replace WHERE id=?", (mid,))

    def toggle_mr(self, mid: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE match_replace SET enabled = 1 - enabled WHERE id=?", (mid,),
            )

    # ---- sitemap (derived from http_history) ----
    def sitemap(self, *, host: str | None = None) -> list[dict]:
        sql = (
            "SELECT host, url, method, COUNT(*), MAX(status), MAX(ts) "
            "FROM http_history WHERE 1=1"
        )
        args: list = []
        if host:
            sql += " AND host=?"
            args.append(host)
        sql += " GROUP BY host, url, method ORDER BY host, url"
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [
            {"host": r[0], "url": r[1], "method": r[2],
             "count": r[3], "status": r[4], "last_ts": r[5]}
            for r in rows
        ]

    def hosts(self) -> list[str]:
        with self._cursor() as cur:
            return [r[0] for r in cur.execute(
                "SELECT DISTINCT host FROM http_history WHERE host<>'' ORDER BY host"
            ).fetchall()]

    # ---- project-wide search ----
    def search(self, q: str, *, limit: int = 200, where: str = "any") -> list[dict]:
        """Search http_history req+resp bodies + url. `where` in {any,url,req,resp}."""
        if not q:
            return []
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id, ts, host, method, url, status, len_resp, req_blob, resp_blob "
                "FROM http_history ORDER BY id DESC LIMIT 5000"
            ).fetchall()
        out: list[dict] = []
        ql = q.lower().encode("utf-8", errors="ignore")
        for r in rows:
            hits: list[str] = []
            if where in ("any", "url") and q.lower() in (r[4] or "").lower():
                hits.append("url")
            if where in ("any", "req") and ql in _decompress(r[7]).lower():
                hits.append("request")
            if where in ("any", "resp") and ql in _decompress(r[8]).lower():
                hits.append("response")
            if hits:
                out.append({
                    "id": r[0], "ts": r[1], "host": r[2], "method": r[3],
                    "url": r[4], "status": r[5], "len_resp": r[6],
                    "where": ",".join(hits),
                })
            if len(out) >= limit:
                break
        return out

    # ---- saved payloads ----
    def list_payloads(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id, name, kind, body FROM saved_payloads ORDER BY name"
            ).fetchall()
        return [{"id": r[0], "name": r[1], "kind": r[2], "body": r[3]} for r in rows]

    def save_payload(self, name: str, kind: str, body: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO saved_payloads(name, kind, body) VALUES (?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, body=excluded.body",
                (name, kind, body),
            )
            return int(cur.lastrowid or 0)

    def delete_payload(self, pid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM saved_payloads WHERE id=?", (pid,))

    # ---- intruder ----
    def create_intruder(self, *, name: str, attack_type: str, template: bytes,
                        positions: list[tuple[int, int]],
                        payloads: list[list[str]], options: dict,
                        url: str, engine: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intruder_attacks(name,attack_type,template_blob,positions_json,"
                "payloads_json,options_json,url,engine,status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?, 'idle', ?)",
                (name, attack_type, _compress(template),
                 json.dumps(positions), json.dumps(payloads), json.dumps(options),
                 url, engine, int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def list_intruder(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,name,attack_type,url,engine,status,created_at FROM intruder_attacks "
                "ORDER BY id DESC"
            ).fetchall()
        return [
            {"id": r[0], "name": r[1], "attack_type": r[2], "url": r[3],
             "engine": r[4], "status": r[5], "created_at": r[6]}
            for r in rows
        ]

    def get_intruder(self, aid: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,name,attack_type,template_blob,positions_json,payloads_json,"
                "options_json,url,engine,status,created_at FROM intruder_attacks WHERE id=?",
                (aid,),
            ).fetchone()
        if not r:
            return None
        return {
            "id": r[0], "name": r[1], "attack_type": r[2],
            "template": _decompress(r[3]),
            "positions": json.loads(r[4]),
            "payloads": json.loads(r[5]),
            "options": json.loads(r[6]),
            "url": r[7], "engine": r[8], "status": r[9], "created_at": r[10],
        }

    def set_intruder_status(self, aid: int, status: str) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE intruder_attacks SET status=? WHERE id=?", (status, aid))

    def add_intruder_result(self, *, attack_id: int, seq: int, payloads: list[str],
                             status: int, len_resp: int, duration_ms: int,
                             grep_hits: str, history_id: int | None,
                             body_md5: str = "", matched: bool = False) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intruder_results(attack_id,seq,payloads_json,status,len_resp,"
                "duration_ms,grep_hits,history_id,body_md5,matched) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (attack_id, seq, json.dumps(payloads), status, len_resp, duration_ms,
                 grep_hits, history_id, body_md5, 1 if matched else 0),
            )
            return int(cur.lastrowid or 0)

    def list_intruder_results(self, attack_id: int, *, sort: str = "seq",
                               desc: bool = False) -> list[dict]:
        order_col = {
            "seq": "seq", "status": "status", "len": "len_resp",
            "time": "duration_ms", "grep": "grep_hits", "matched": "matched",
        }.get(sort, "seq")
        direction = "DESC" if desc else "ASC"
        with self._cursor() as cur:
            rows = cur.execute(
                f"SELECT id,seq,payloads_json,status,len_resp,duration_ms,grep_hits,history_id,"  # noqa: S608  # order_col whitelisted via dict above, direction is a compile-time literal, attack_id is parameterised
                f"body_md5,matched FROM intruder_results WHERE attack_id=? "
                f"ORDER BY {order_col} {direction}",
                (attack_id,),
            ).fetchall()
        return [
            {"id": r[0], "seq": r[1], "payloads": json.loads(r[2]), "status": r[3],
             "len_resp": r[4], "duration_ms": r[5], "grep_hits": r[6], "history_id": r[7],
             "body_md5": r[8] or "", "matched": bool(r[9])}
            for r in rows
        ]

    def delete_intruder(self, aid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM intruder_results WHERE attack_id=?", (aid,))
            cur.execute("DELETE FROM intruder_attacks WHERE id=?", (aid,))

    # ---- sequencer live captures ----
    def create_sequencer_capture(
        self, *, name: str, url: str, template: bytes, engine: str,
        extractor_kind: str, extractor_arg: str, max_samples: int,
        delay_ms: int, concurrency: int, significance: str,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO sequencer_captures(name,url,template_blob,engine,"
                "extractor_kind,extractor_arg,max_samples,delay_ms,concurrency,"
                "significance,status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?, 'idle', ?)",
                (name, url, _compress(template), engine, extractor_kind,
                 extractor_arg, int(max_samples), int(delay_ms),
                 int(concurrency), significance, int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def list_sequencer_captures(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,name,url,engine,extractor_kind,extractor_arg,"
                "max_samples,status,stop_reason,error_count,significance,created_at "
                "FROM sequencer_captures ORDER BY id DESC"
            ).fetchall()
        return [
            {"id": r[0], "name": r[1], "url": r[2], "engine": r[3],
             "extractor_kind": r[4], "extractor_arg": r[5],
             "max_samples": r[6], "status": r[7], "stop_reason": r[8],
             "error_count": r[9], "significance": r[10], "created_at": r[11]}
            for r in rows
        ]

    def get_sequencer_capture(self, cid: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,name,url,template_blob,engine,extractor_kind,"
                "extractor_arg,max_samples,delay_ms,concurrency,significance,"
                "status,stop_reason,error_count,created_at "
                "FROM sequencer_captures WHERE id=?", (cid,),
            ).fetchone()
        if not r:
            return None
        return {
            "id": r[0], "name": r[1], "url": r[2],
            "template": _decompress(r[3]),
            "engine": r[4], "extractor_kind": r[5], "extractor_arg": r[6],
            "max_samples": r[7], "delay_ms": r[8], "concurrency": r[9],
            "significance": r[10], "status": r[11], "stop_reason": r[12],
            "error_count": r[13], "created_at": r[14],
        }

    def set_sequencer_capture_status(
        self, cid: int, status: str, *, stop_reason: str | None = None,
        error_count: int | None = None,
    ) -> None:
        sets = ["status=?"]
        args: list = [status]
        if stop_reason is not None:
            sets.append("stop_reason=?")
            args.append(stop_reason)
        if error_count is not None:
            sets.append("error_count=?")
            args.append(int(error_count))
        args.append(cid)
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE sequencer_captures SET {', '.join(sets)} WHERE id=?",  # noqa: S608  # `sets` entries are hardcoded `col=?` fragments assembled locally; all values pass through `args`
                args,
            )

    def add_sequencer_sample(
        self, *, capture_id: int, seq: int, token: str, status: int,
        duration_ms: int,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO sequencer_samples(capture_id,seq,token,status,"
                "duration_ms,captured_at) VALUES (?,?,?,?,?,?)",
                (capture_id, int(seq), token, int(status), int(duration_ms),
                 int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def count_sequencer_samples(self, cid: int) -> int:
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM sequencer_samples WHERE capture_id=?",
                (cid,),
            ).fetchone()[0])

    def list_sequencer_samples(
        self, cid: int, *, limit: int | None = None,
    ) -> list[dict]:
        sql = ("SELECT id,seq,token,status,duration_ms,captured_at "
               "FROM sequencer_samples WHERE capture_id=? ORDER BY seq ASC")
        args: list = [cid]
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [
            {"id": r[0], "seq": r[1], "token": r[2], "status": r[3],
             "duration_ms": r[4], "captured_at": r[5]}
            for r in rows
        ]

    def list_sequencer_tokens(self, cid: int) -> list[str]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT token FROM sequencer_samples WHERE capture_id=? "
                "ORDER BY seq ASC", (cid,),
            ).fetchall()
        return [r[0] for r in rows]

    def delete_sequencer_capture(self, cid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM sequencer_samples WHERE capture_id=?", (cid,))
            cur.execute("DELETE FROM sequencer_captures WHERE id=?", (cid,))

    # ---- findings (scanner output) ----
    SEVERITIES = ("info", "low", "medium", "high", "critical")
    STATUSES = ("open", "triaged", "false_positive", "fixed")
    SOURCES = (
        "scanner", "intruder", "smuggling", "sequencer", "saml",
        "graphql", "oast", "proxy", "manual", "plugin", "imported",
    )

    _ISSUES_COLS = (
        "id", "severity", "cwe", "owasp", "title", "host", "url",
        "request_id", "response_id", "evidence", "payload", "status",
        "created_at", "uuid", "source", "rule_id", "rule_version",
        "description", "remediation", "references_json",
        "cvss_vector", "cvss_score", "reproduction_token",
        "updated_at", "dedupe_key",
        # Phase 3 — confidence + consolidation + fingerprinting.
        "confidence", "occurrence_count", "fingerprint_tags",
        "last_seen_at",
    )

    # Phase 3 — valid confidence tiers. Burp uses exactly this 3-level model.
    CONFIDENCES = ("tentative", "firm", "certain")

    # Phase 3 — ordering used when a duplicate finding arrives with a higher
    # confidence: keep the strongest, never demote silently.
    _CONFIDENCE_RANK = {"tentative": 0, "firm": 1, "certain": 2}

    # Phase 3 — cross-rule corroboration. When a finding lands on the same
    # (host, normalised_url) and one of these *partner* rules has already
    # fired there, both findings are promoted to ``"certain"`` because two
    # independent detection techniques agree on the vulnerability. Pairs
    # are symmetric.
    _CORROBORATION_PAIRS: tuple[tuple[str, str], ...] = (
        # SQLi: time-based confirms error-based and vice versa.
        ("active:sqli-error", "active:os-cmd-time"),
        # OS-cmd-time + OAST-SSRF firing on the same param = command
        # injection that also exfiltrates DNS.
        ("active:os-cmd-time", "active:oast-ssrf"),
        # XSS: reflected + DOM agreeing = exploitable XSS.
        ("active:xss-reflected", "active:xss-dom"),
        # XSS: reflected via body + via header on the same target.
        ("active:xss-reflected", "active:xss-reflected-headers"),
        # SSTI + reflected XSS on the same param — template engine confirmed.
        ("active:ssti", "active:xss-reflected"),
        # Path traversal + os-cmd-time on same param.
        ("active:path-traversal-lfi", "active:os-cmd-time"),
    )

    @classmethod
    def _partner_rules(cls, rule_id: str) -> tuple[str, ...]:
        """Return the rule ids that *corroborate* ``rule_id`` (symmetric)."""
        if not rule_id:
            return ()
        partners: list[str] = []
        for a, b in cls._CORROBORATION_PAIRS:
            if a == rule_id:
                partners.append(b)
            elif b == rule_id:
                partners.append(a)
        return tuple(partners)

    @staticmethod
    def _row_to_finding(r) -> dict:
        out = dict(zip(Project._ISSUES_COLS, r, strict=False))
        try:
            out["references"] = json.loads(out.pop("references_json") or "[]")
        except (ValueError, TypeError):
            out["references"] = []
            out.pop("references_json", None)
        # Phase 3 — expose fingerprint tags as a list for templates and the
        # reporter. Stored as a single comma-separated string so the SQL
        # stays simple; never raise on malformed data.
        raw_tags = out.get("fingerprint_tags") or ""
        out["fingerprint_tags_list"] = [
            t.strip() for t in raw_tags.split(",") if t.strip()
        ]
        return out

    # Phase 3 \u2014 path-segment normalisations used to compute a dedupe key
    # that groups "the same issue on different IDs" together. Burp does
    # the same trick so a SQLi on ``/users/1/profile`` and
    # ``/users/2/profile`` consolidates into one finding.
    _ID_SEGMENT_RE = re.compile(
        r"/("
        # all-digit segment
        r"\d+"
        # OR hex/uuid (\u22658 hex chars or canonical UUID)
        r"|[0-9a-fA-F]{8,}"
        r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        r")(?=/|$|\?)"
    )

    @staticmethod
    def _normalize_url_for_consolidation(url: str) -> str:
        """Return ``url`` with numeric / UUID / hex path segments replaced
        by ``{id}`` so dedupe groups across "the same path, different
        IDs". Query string is preserved verbatim \u2014 callers that want
        to consolidate on query keys should strip the query first.
        Defensive: any failure returns the original URL unchanged.
        """
        if not url:
            return url
        try:
            # Split off query / fragment so we only template the path.
            base, sep, tail = url.partition("?")
            templated = Project._ID_SEGMENT_RE.sub("/{id}", base)
            return templated + sep + tail
        except (TypeError, ValueError):
            return url

    @staticmethod
    def _compute_dedupe_key(*, rule_id: str, title: str, host: str,
                             url: str, evidence: str) -> str:
        # Phase 3 \u2014 normalise URL path segments so "the same issue with a
        # different numeric ID" consolidates. Existing rows with the old
        # raw-URL key are left alone; new findings dedupe against the
        # normalised key only.
        normalised_url = Project._normalize_url_for_consolidation(url)
        ev_hash = hashlib.sha256(evidence.encode("utf-8", "replace")).hexdigest()[:16]
        key_id = rule_id or f"legacy:{title}"
        return f"{key_id}|{host}|{normalised_url}|{ev_hash}"

    def add_finding(self, *, severity: str, title: str, cwe: str = "",
                    owasp: str = "", host: str = "", url: str = "",
                    request_id: int | None = None, response_id: int | None = None,
                    evidence: str = "", payload: str = "",
                    source: str = "scanner", rule_id: str = "",
                    rule_version: int = 0, description: str = "",
                    remediation: str = "", references: list[str] | None = None,
                    cvss_vector: str | None = None, cvss_score: float | None = None,
                    reproduction_token: str | None = None,
                    extra_targets: list[tuple[str, str]] | None = None,
                    dedupe_key: str | None = None,
                    confidence: str = "firm",
                    fingerprint_tags: str = "") -> int:
        """Insert a finding. If a finding with the same dedupe_key already
        exists, bump its ``occurrence_count`` + ``last_seen_at`` and return
        its id instead of inserting a duplicate (Phase 3 behaviour; pre-Phase
        3 this returned the existing id with no side-effect).
        """
        # Defensive: clamp ``confidence`` to a known tier so a forged or
        # buggy caller can't poison the column.
        if confidence not in self.CONFIDENCES:
            confidence = "firm"
        key = dedupe_key or self._compute_dedupe_key(
            rule_id=rule_id, title=title, host=host, url=url, evidence=evidence,
        )
        now = int(time.time())
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id, confidence, fingerprint_tags "
                "FROM issues WHERE dedupe_key=? LIMIT 1", (key,),
            ).fetchone()
            if r:
                fid = int(r[0])
                self._bump_occurrence(
                    cur, fid, url=url, request_id=request_id, ts=now,
                    incoming_confidence=confidence,
                    stored_confidence=r[1] or "firm",
                    incoming_tags=fingerprint_tags,
                    stored_tags=r[2] or "",
                )
                if extra_targets:
                    self._add_finding_targets(cur, fid, extra_targets)
                return fid
            # Legacy fallback: pre-v3 rows have NULL dedupe_key.
            r = cur.execute(
                "SELECT id, confidence, fingerprint_tags FROM issues "
                "WHERE title=? AND COALESCE(host,'')=? "
                "AND COALESCE(url,'')=? AND substr(evidence,1,200)=substr(?,1,200) "
                "AND (dedupe_key IS NULL OR dedupe_key='') LIMIT 1",
                (title, host, url, evidence),
            ).fetchone()
            if r:
                fid = int(r[0])
                cur.execute(
                    "UPDATE issues SET dedupe_key=? WHERE id=?", (key, fid),
                )
                self._bump_occurrence(
                    cur, fid, url=url, request_id=request_id, ts=now,
                    incoming_confidence=confidence,
                    stored_confidence=r[1] or "firm",
                    incoming_tags=fingerprint_tags,
                    stored_tags=r[2] or "",
                )
                if extra_targets:
                    self._add_finding_targets(cur, fid, extra_targets)
                return fid
            refs_json = json.dumps(list(references or []))
            cur.execute(
                "INSERT INTO issues(severity,cwe,owasp,title,host,url,request_id,"
                "response_id,evidence,payload,status,created_at,uuid,source,"
                "rule_id,rule_version,description,remediation,references_json,"
                "cvss_vector,cvss_score,reproduction_token,updated_at,dedupe_key,"
                "confidence,occurrence_count,fingerprint_tags,last_seen_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,1,?,?)",
                (severity, cwe, owasp, title, host, url, request_id, response_id,
                 evidence, payload, now,
                 _uuid.uuid4().hex, source, rule_id, rule_version,
                 description, remediation, refs_json,
                 cvss_vector, cvss_score, reproduction_token, now, key,
                 confidence, fingerprint_tags, now),
            )
            fid = int(cur.lastrowid or 0)
            # Seed the occurrence ledger so the count column and the
            # finding_occurrences table stay consistent.
            cur.execute(
                "INSERT INTO finding_occurrences(finding_id,url,request_id,ts) "
                "VALUES (?,?,?,?)",
                (fid, url or "", request_id, now),
            )
            if extra_targets:
                self._add_finding_targets(cur, fid, extra_targets)
            # Phase 3 — cross-rule corroboration. Run after insert so we
            # can include the just-created row in the upgrade set.
            self._corroborate(
                cur, fid=fid, rule_id=rule_id, host=host, url=url,
                ts=now,
            )
            return fid

    def _corroborate(self, cur, *, fid: int, rule_id: str,
                      host: str, url: str, ts: int) -> None:
        """Phase 3 — if a partner rule already has a finding on the same
        (host, normalised-url), promote both this finding and the partner
        finding(s) to ``"certain"``.

        The lookup uses the consolidation-normalised URL so an
        ``/users/1/profile`` finding corroborates an
        ``/users/2/profile`` partner finding.
        """
        partners = self._partner_rules(rule_id)
        if not partners:
            return
        normalised = self._normalize_url_for_consolidation(url or "")
        placeholders = ",".join("?" * len(partners))
        try:
            rows = cur.execute(
                f"SELECT id, url, confidence FROM issues "  # noqa: S608  # `placeholders` is a comma-joined string of `?` markers; rule ids and host are parameterised
                f"WHERE rule_id IN ({placeholders}) "
                f"AND COALESCE(host,'')=? AND status='open'",
                (*partners, host or ""),
            ).fetchall()
        except sqlite3.OperationalError:
            return
        upgraded_partners: list[int] = []
        for pid, purl, pconfidence in rows:
            # Compare normalised URLs so /users/1 corroborates /users/2.
            if self._normalize_url_for_consolidation(purl or "") != normalised:
                continue
            if self._CONFIDENCE_RANK.get(pconfidence or "firm", 1) < 2:
                upgraded_partners.append(int(pid))
        if not upgraded_partners:
            return
        # Upgrade partners.
        ph = ",".join("?" * len(upgraded_partners))
        cur.execute(
            f"UPDATE issues SET confidence='certain', updated_at=? "  # noqa: S608  # `ph` is a comma-joined string of `?` markers; ids/timestamp are parameterised
            f"WHERE id IN ({ph})",
            (ts, *upgraded_partners),
        )
        # Upgrade self.
        cur.execute(
            "UPDATE issues SET confidence='certain', updated_at=? "
            "WHERE id=? AND confidence != 'certain'",
            (ts, fid),
        )

    def _bump_occurrence(self, cur, fid: int, *, url: str,
                          request_id: int | None, ts: int,
                          incoming_confidence: str,
                          stored_confidence: str,
                          incoming_tags: str,
                          stored_tags: str) -> None:
        """Phase 3 \u2014 update the on-row consolidation state for a duplicate
        finding: bump count, refresh ``last_seen_at``, log the occurrence,
        upgrade confidence if the incoming evidence is stronger, and merge
        fingerprint tags (set union).
        """
        # Merge fingerprint tags (set union, deterministic order).
        merged_tags = stored_tags
        if incoming_tags:
            existing = {t for t in stored_tags.split(",") if t}
            for tag in incoming_tags.split(","):
                tag = tag.strip()
                if tag and tag not in existing:
                    existing.add(tag)
            merged_tags = ",".join(sorted(existing))
        # Upgrade confidence: keep the higher rank, never demote.
        rank = self._CONFIDENCE_RANK
        if (rank.get(incoming_confidence, 1)
                > rank.get(stored_confidence, 1)):
            new_confidence = incoming_confidence
        else:
            new_confidence = stored_confidence
        cur.execute(
            "UPDATE issues SET occurrence_count = occurrence_count + 1, "
            "last_seen_at = ?, updated_at = ?, "
            "confidence = ?, fingerprint_tags = ? WHERE id = ?",
            (ts, ts, new_confidence, merged_tags, fid),
        )
        cur.execute(
            "INSERT INTO finding_occurrences(finding_id,url,request_id,ts) "
            "VALUES (?,?,?,?)",
            (fid, url or "", request_id, ts),
        )

    def list_finding_occurrences(self, fid: int, *, limit: int = 200
                                  ) -> list[dict]:
        """Return per-occurrence rows for a finding, newest first.

        Used by the detail page to render "this issue also fired on
        these URLs / requests".
        """
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id, url, request_id, ts FROM finding_occurrences "
                "WHERE finding_id=? ORDER BY ts DESC, id DESC LIMIT ?",
                (fid, limit),
            ).fetchall()
        return [
            {"id": r[0], "url": r[1], "request_id": r[2], "ts": r[3]}
            for r in rows
        ]

    @staticmethod
    def _add_finding_targets(cur, fid: int,
                              targets: list[tuple[str, str]]) -> None:
        for h, u in targets:
            cur.execute(
                "INSERT OR IGNORE INTO finding_targets(finding_id,host,url) "
                "VALUES (?,?,?)", (fid, h or "", u or ""),
            )

    def list_finding_targets(self, fid: int) -> list[tuple[str, str]]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT host,url FROM finding_targets WHERE finding_id=? "
                "ORDER BY host,url", (fid,),
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def list_findings(self, *, severity: str | None = None, status: str | None = None,
                       host: str | None = None, source: str | None = None,
                       rule_id: str | None = None,
                       confidence: str | None = None,
                       waf_tagged: bool = False,
                       limit: int = 500) -> list[dict]:
        cols = ",".join(self._ISSUES_COLS)
        sql = f"SELECT {cols} FROM issues WHERE 1=1"  # noqa: S608  # `cols` is joined from the class-level _ISSUES_COLS whitelist; filters below use ? placeholders
        args: list = []
        if severity:
            sql += " AND severity=?"
            args.append(severity)
        if status:
            sql += " AND status=?"
            args.append(status)
        if host:
            sql += " AND host=?"
            args.append(host)
        if source:
            sql += " AND source=?"
            args.append(source)
        if rule_id:
            sql += " AND rule_id=?"
            args.append(rule_id)
        if confidence:
            sql += " AND confidence=?"
            args.append(confidence)
        if waf_tagged:
            # Phase 4 — surface only findings where a WAF / error-page
            # signature was attached by the fingerprint pipeline.
            sql += " AND fingerprint_tags LIKE ?"
            args.append("%behind_waf:%")
        sql += " ORDER BY CASE severity "
        sql += "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        sql += "WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT ?"
        args.append(limit)
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_finding(self, fid: int) -> dict | None:
        cols = ",".join(self._ISSUES_COLS)
        with self._cursor() as cur:
            r = cur.execute(
                f"SELECT {cols} FROM issues WHERE id=?", (fid,),  # noqa: S608  # `cols` is joined from the class-level _ISSUES_COLS whitelist; fid is parameterised
            ).fetchone()
        if not r:
            return None
        return self._row_to_finding(r)

    def set_finding_status(self, fid: int, status: str) -> None:
        if status not in self.STATUSES:
            raise ValueError(f"unknown status: {status}")
        with self._cursor() as cur:
            cur.execute(
                "UPDATE issues SET status=?, updated_at=? WHERE id=?",
                (status, int(time.time()), fid),
            )

    def delete_finding(self, fid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM issues WHERE id=?", (fid,))

    def findings_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute("SELECT COUNT(*) FROM issues").fetchone()[0])

    def findings_summary(self) -> dict[str, int]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT severity, COUNT(*) FROM issues WHERE status='open' GROUP BY severity"
            ).fetchall()
        out = dict.fromkeys(self.SEVERITIES, 0)
        for sev, n in rows:
            out[sev] = n
        return out

    # ---- finding suppressions ----
    def add_finding_suppression(self, *, rule_id: str, host: str = "",
                                  url_pattern: str = "", reason: str = "") -> None:
        if not rule_id:
            raise ValueError("rule_id is required")
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO finding_suppressions("
                "rule_id,host,url_pattern,reason,created_at) VALUES (?,?,?,?,?)",
                (rule_id, host or "", url_pattern or "", reason or "",
                 int(time.time())),
            )

    def list_finding_suppressions(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT rule_id,host,url_pattern,reason,created_at "
                "FROM finding_suppressions ORDER BY rule_id, host, url_pattern"
            ).fetchall()
        return [
            {"rule_id": r[0], "host": r[1], "url_pattern": r[2],
             "reason": r[3], "created_at": r[4]}
            for r in rows
        ]

    def delete_finding_suppression(self, *, rule_id: str, host: str = "",
                                     url_pattern: str = "") -> None:
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM finding_suppressions WHERE rule_id=? "
                "AND host=? AND url_pattern=?",
                (rule_id, host or "", url_pattern or ""),
            )

    def is_suppressed(self, *, rule_id: str, host: str = "", url: str = "") -> bool:
        """A suppression matches when its rule_id equals the candidate's, its
        host is empty (= any) or equals/glob-matches the candidate's host, and
        its url_pattern is empty (= any) or appears as a substring of url."""
        if not rule_id:
            return False
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT host,url_pattern FROM finding_suppressions WHERE rule_id=?",
                (rule_id,),
            ).fetchall()
        for sup_host, sup_url in rows:
            if sup_host and not _host_matches(sup_host, host or ""):
                continue
            if sup_url and (sup_url not in (url or "")):
                continue
            return True
        return False

    def suppression_suggestions(self, *, threshold: int = 5,
                                 limit: int = 50) -> list[dict]:
        """Phase 3 \u2014 surface "this rule fires constantly on the same template,
        do you want to suppress?" candidates.

        Groups by ``(rule_id, host, normalised-url-template)``. Any group
        with ``threshold`` or more *open* findings is a candidate.

        Returns rows like:
        ``{"rule_id":..., "host":..., "url_pattern":..., "count":N,
           "example_url":..., "example_finding_id":...}``.

        ``url_pattern`` is the normalised template (e.g. ``/users/{id}``)
        so it can be passed straight into ``add_finding_suppression`` as a
        substring match.

        Defensive: returns ``[]`` if anything goes wrong rather than
        breaking the suppressions page.
        """
        if threshold < 2:
            threshold = 2
        try:
            with self._cursor() as cur:
                # Pull (id, rule_id, host, url) for open findings only;
                # we group + normalise in Python so the regex stays in
                # one place. Cheap up to a few thousand rows.
                rows = cur.execute(
                    "SELECT id, rule_id, COALESCE(host,''), COALESCE(url,'') "
                    "FROM issues WHERE status='open' AND rule_id != ''"
                ).fetchall()
        except sqlite3.OperationalError:
            return []
        buckets: dict[tuple[str, str, str], dict] = {}
        for fid, rid, host, url in rows:
            template = self._normalize_url_for_consolidation(url)
            # Strip the query string off the pattern \u2014 suppressions are
            # substring matches and the query rarely repeats.
            template = template.partition("?")[0]
            if not template:
                continue
            key = (rid, host, template)
            slot = buckets.get(key)
            if slot is None:
                slot = {
                    "rule_id": rid, "host": host,
                    "url_pattern": template,
                    "count": 0,
                    "example_url": url,
                    "example_finding_id": fid,
                }
                buckets[key] = slot
            slot["count"] += 1
        candidates = [v for v in buckets.values() if v["count"] >= threshold]
        candidates.sort(key=lambda v: (-v["count"], v["rule_id"]))
        return candidates[:limit]

    # ---- reproduction blobs ----
    def add_reproduction(self, *, request_blob: bytes, response_blob: bytes,
                          method: str = "", url: str = "", status: int = 0,
                          elapsed_ms: int = 0) -> str:
        token = _uuid.uuid4().hex
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO finding_reproductions(token,request_blob,response_blob,"
                "method,url,status,sent_at,elapsed_ms) VALUES (?,?,?,?,?,?,?,?)",
                (token, _compress(request_blob), _compress(response_blob),
                 method or "", url or "", int(status), int(time.time()),
                 int(elapsed_ms)),
            )
        return token

    def get_reproduction(self, token: str) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT token,request_blob,response_blob,method,url,status,"
                "sent_at,elapsed_ms FROM finding_reproductions WHERE token=?",
                (token,),
            ).fetchone()
        if not r:
            return None
        return {
            "token": r[0],
            "request_blob": _decompress(r[1]),
            "response_blob": _decompress(r[2]),
            "method": r[3], "url": r[4], "status": r[5],
            "sent_at": r[6], "elapsed_ms": r[7],
        }

    # ---- rule run telemetry ----
    def record_rule_run(self, *, rule_id: str, rule_version: int = 0,
                          host: str = "", url: str = "", fired: bool,
                          reason: str = "") -> None:
        if not rule_id:
            return
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO rule_runs(rule_id,rule_version,host,url,fired,reason,"
                "run_at) VALUES (?,?,?,?,?,?,?)",
                (rule_id, int(rule_version), host or "", url or "",
                 1 if fired else 0, reason or "", int(time.time())),
            )

    def rule_run_summary(self) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT rule_id, "
                "SUM(CASE WHEN fired=1 THEN 1 ELSE 0 END) AS fired, "
                "COUNT(*) AS evaluated "
                "FROM rule_runs GROUP BY rule_id ORDER BY rule_id"
            ).fetchall()
        return [
            {"rule_id": r[0], "fired": int(r[1] or 0), "evaluated": int(r[2] or 0)}
            for r in rows
        ]

    def rule_run_summary_by_host(self) -> list[dict]:
        """Per-(rule_id, host) coverage. Sorted by rule_id then host so the
        renderers can group rows under each rule heading."""
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT rule_id, COALESCE(host,'') AS host, "
                "SUM(CASE WHEN fired=1 THEN 1 ELSE 0 END) AS fired, "
                "COUNT(*) AS evaluated "
                "FROM rule_runs GROUP BY rule_id, host "
                "ORDER BY rule_id, host"
            ).fetchall()
        return [
            {"rule_id": r[0], "host": r[1] or "",
             "fired": int(r[2] or 0), "evaluated": int(r[3] or 0)}
            for r in rows
        ]

    def rule_last_fire_map(self) -> dict[str, int]:
        """Phase 4 — return ``{rule_id: last_fire_unixtime}`` for every
        rule that has fired at least once. Used by the coverage panel
        to surface a "Last fire" column without changing the shape of
        :meth:`rule_run_summary` (which tests assert dict-equal).
        """
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT rule_id, MAX(run_at) FROM rule_runs "
                "WHERE fired=1 GROUP BY rule_id"
            ).fetchall()
        return {r[0]: int(r[1] or 0) for r in rows}

    def rule_last_fire_map_by_host(self) -> dict[tuple[str, str], int]:
        """Phase 4 — ``{(rule_id, host): last_fire_unixtime}``."""
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT rule_id, COALESCE(host,''), MAX(run_at) "
                "FROM rule_runs WHERE fired=1 GROUP BY rule_id, host"
            ).fetchall()
        return {(r[0], r[1] or ""): int(r[2] or 0) for r in rows}

    def rule_run_reasons(self, *, rule_id: str = "",
                          host: str = "") -> list[dict]:
        """Per-(rule_id, host, reason) breakdown of evaluations that did
        NOT fire. Used by the coverage view to answer "why didn't this
        rule flag anything on this host?".

        Both filters are optional; pass empty string for "no filter".
        Sorted by rule_id, host, then descending count so the loudest
        reasons surface first.
        """
        sql = ("SELECT rule_id, COALESCE(host,'') AS host, "
               "COALESCE(reason,'') AS reason, COUNT(*) AS n "
               "FROM rule_runs WHERE fired=0")
        params: list = []
        if rule_id:
            sql += " AND rule_id=?"
            params.append(rule_id)
        if host:
            sql += " AND host=?"
            params.append(host)
        sql += (" GROUP BY rule_id, host, reason "
                "ORDER BY rule_id, host, n DESC")
        with self._cursor() as cur:
            rows = cur.execute(sql, params).fetchall()
        return [
            {"rule_id": r[0], "host": r[1] or "",
             "reason": r[2] or "(none)", "count": int(r[3] or 0)}
            for r in rows
        ]

    # ---- DOM Hunter (DOM XSS) findings ----
    def add_dom_hunter_finding(self, *, page_url: str, frame_url: str, sink: str,
                          source: str, severity: str, canary_seen: bool,
                          value: str, stack: str, dedupe_key: str) -> int:
        """Insert a DOM Hunter finding or bump hit_count if the dedupe_key exists.

        Returns the row id of the inserted-or-updated finding.
        """
        now = int(time.time())
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO dom_hunter_findings(ts,page_url,frame_url,sink,source,"
                "severity,canary_seen,value,stack,dedupe_key,hit_count) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,1) "
                "ON CONFLICT(dedupe_key) DO UPDATE SET "
                "hit_count=hit_count+1, ts=excluded.ts, "
                "canary_seen=MAX(dom_hunter_findings.canary_seen, excluded.canary_seen)",
                (now, page_url, frame_url, sink, source, severity,
                 1 if canary_seen else 0, value, stack, dedupe_key),
            )
            r = cur.execute(
                "SELECT id FROM dom_hunter_findings WHERE dedupe_key=?", (dedupe_key,)
            ).fetchone()
        return int(r[0]) if r else 0

    def list_dom_hunter_findings(self, *, limit: int = 200, offset: int = 0,
                            min_severity: str | None = None,
                            q: str | None = None) -> list[dict]:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sql = ("SELECT id,ts,page_url,frame_url,sink,source,severity,"
               "canary_seen,value,stack,hit_count FROM dom_hunter_findings WHERE 1=1")
        args: list = []
        if q:
            sql += " AND (page_url LIKE ? OR sink LIKE ? OR source LIKE ? OR value LIKE ?)"
            like = f"%{q}%"
            args += [like, like, like, like]
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        out = []
        floor = order.get((min_severity or "info").lower(), 0)
        for r in rows:
            sev = r[6] or "medium"
            if order.get(sev, 2) < floor:
                continue
            out.append({
                "id": r[0], "ts": r[1], "page_url": r[2], "frame_url": r[3],
                "sink": r[4], "source": r[5], "severity": sev,
                "canary_seen": bool(r[7]), "value": r[8], "stack": r[9],
                "hit_count": r[10],
            })
        return out

    def get_dom_hunter_finding(self, fid: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,ts,page_url,frame_url,sink,source,severity,"
                "canary_seen,value,stack,hit_count FROM dom_hunter_findings WHERE id=?",
                (fid,),
            ).fetchone()
        if not r:
            return None
        return {
            "id": r[0], "ts": r[1], "page_url": r[2], "frame_url": r[3],
            "sink": r[4], "source": r[5], "severity": r[6] or "medium",
            "canary_seen": bool(r[7]), "value": r[8], "stack": r[9],
            "hit_count": r[10],
        }

    def dom_hunter_findings_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM dom_hunter_findings"
            ).fetchone()[0])

    def auth_matrix_findings_count(self) -> int:
        """Number of findings recorded by the Auth Matrix (both
        active runs and the passive shadow worker). Used by the
        top-nav badge. The ``source`` column for these rows always
        starts with ``auth_matrix`` (the runner writes
        ``"auth_matrix"`` and the shadow worker writes
        ``"auth_matrix:shadow"``)."""
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM issues WHERE source LIKE 'auth_matrix%'"
            ).fetchone()[0])

    def clear_dom_hunter_findings(self) -> int:
        with self._cursor() as cur:
            n = int(cur.execute(
                "SELECT COUNT(*) FROM dom_hunter_findings"
            ).fetchone()[0])
            cur.execute("DELETE FROM dom_hunter_findings")
        return n

    # ---- DOM Hunter postMessage log ----
    def add_dom_hunter_message(self, *, page_url: str, origin: str, data: str,
                          has_canary: bool, handler_stack: str = "") -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO dom_hunter_messages(ts,page_url,origin,data,"
                "has_canary,handler_stack) VALUES (?,?,?,?,?,?)",
                (int(time.time()), page_url, origin, data,
                 1 if has_canary else 0, handler_stack),
            )
            return int(cur.lastrowid or 0)

    def list_dom_hunter_messages(self, *, limit: int = 200,
                            origin: str | None = None,
                            only_canary: bool = False) -> list[dict]:
        sql = ("SELECT id,ts,page_url,origin,data,has_canary,handler_stack "
               "FROM dom_hunter_messages WHERE 1=1")
        args: list = []
        if origin:
            sql += " AND origin=?"
            args.append(origin)
        if only_canary:
            sql += " AND has_canary=1"
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [
            {"id": r[0], "ts": r[1], "page_url": r[2], "origin": r[3],
             "data": r[4], "has_canary": bool(r[5]), "handler_stack": r[6]}
            for r in rows
        ]

    def dom_hunter_messages_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM dom_hunter_messages"
            ).fetchone()[0])

    # ---- Phase 16 — Plugin Apps ---------------------------------------

    def create_plugin_run(
        self, *, slug: str, settings: dict,
        seed_history_id: int | None = None,
    ) -> int:
        """Insert a fresh ``pending`` plugin-run row. Returns its id.

        ``seed_history_id`` records that the run was launched via the
        Send-to-plugin flow from a History row (or an intercept that
        snapshot itself into history first).
        """
        payload = json.dumps(dict(settings or {}), default=str)
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO plugin_runs(slug,started_at,status,"
                "settings_json,seed_history_id) VALUES (?,?,?,?,?)",
                (str(slug), int(time.time()), "pending", payload,
                 int(seed_history_id) if seed_history_id is not None else None),
            )
            return int(cur.lastrowid or 0)

    def update_plugin_run(
        self, run_id: int, *,
        status: str | None = None,
        finished_at: int | None = None,
        error: str | None = None,
        progress_done: int | None = None,
        progress_total: int | None = None,
        progress_msg: str | None = None,
    ) -> None:
        sets: list[str] = []
        args: list = []
        if status is not None:
            sets.append("status=?")
            args.append(str(status))
        if finished_at is not None:
            sets.append("finished_at=?")
            args.append(int(finished_at))
        if error is not None:
            sets.append("error=?")
            args.append(str(error)[:4096])
        if progress_done is not None:
            sets.append("progress_done=?")
            args.append(int(progress_done))
        if progress_total is not None:
            sets.append("progress_total=?")
            args.append(int(progress_total))
        if progress_msg is not None:
            sets.append("progress_msg=?")
            args.append(str(progress_msg)[:240])
        if not sets:
            return
        args.append(int(run_id))
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE plugin_runs SET {','.join(sets)} WHERE id=?", args)  # noqa: S608  # `sets` entries are hardcoded `col=?` fragments assembled locally; all values pass through `args`

    # Cap a single run's log at this size so a runaway plugin can't
    # bloat the .rlr file unboundedly. Old content is dropped from the
    # front; the live tail is what operators care about.
    _PLUGIN_LOG_CAP_BYTES = 256 * 1024

    def append_plugin_run_log(self, run_id: int, line: str) -> None:
        """Append one log line. Trims the front of the log when it
        grows past :pyattr:`_PLUGIN_LOG_CAP_BYTES`."""
        suffix = (str(line) + "\n")
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT log FROM plugin_runs WHERE id=?", (int(run_id),)
            ).fetchone()
            if not row:
                return
            cur_log = row[0] or ""
            merged = cur_log + suffix
            if len(merged) > self._PLUGIN_LOG_CAP_BYTES:
                merged = merged[-self._PLUGIN_LOG_CAP_BYTES:]
                # Re-anchor at a newline so we don't leave a torn line.
                nl = merged.find("\n")
                if 0 <= nl < len(merged) - 1:
                    merged = merged[nl + 1:]
            cur.execute(
                "UPDATE plugin_runs SET log=? WHERE id=?",
                (merged, int(run_id)),
            )

    def append_plugin_run_result(self, run_id: int, row: dict) -> None:
        """Append a result row to ``results_json``. Defensive — invalid
        JSON in the column (shouldn't happen) is rebuilt as an empty
        list rather than crashing the runner."""
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT results_json FROM plugin_runs WHERE id=?",
                (int(run_id),),
            ).fetchone()
            if not r:
                return
            try:
                results = json.loads(r[0]) if r[0] else []
                if not isinstance(results, list):
                    results = []
            except (TypeError, ValueError):
                results = []
            try:
                row_json = json.loads(json.dumps(dict(row), default=str))
            except (TypeError, ValueError):
                row_json = {"_error": "result row not JSON-serialisable"}
            results.append(row_json)
            cur.execute(
                "UPDATE plugin_runs SET results_json=? WHERE id=?",
                (json.dumps(results), int(run_id)),
            )

    def get_plugin_run(self, run_id: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,slug,started_at,finished_at,status,settings_json,"
                "log,results_json,progress_done,progress_total,"
                "progress_msg,error,seed_history_id FROM plugin_runs WHERE id=?",
                (int(run_id),),
            ).fetchone()
        return _row_to_plugin_run(r) if r else None

    def list_plugin_runs(
        self, *, slug: str | None = None, limit: int = 100,
    ) -> list[dict]:
        sql = ("SELECT id,slug,started_at,finished_at,status,settings_json,"
               "log,results_json,progress_done,progress_total,"
               "progress_msg,error,seed_history_id FROM plugin_runs")
        args: list = []
        if slug:
            sql += " WHERE slug=?"
            args.append(str(slug))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [_row_to_plugin_run(r) for r in rows]

    def latest_plugin_run(self, slug: str) -> dict | None:
        runs = self.list_plugin_runs(slug=slug, limit=1)
        return runs[0] if runs else None

    def delete_plugin_run(self, run_id: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM plugin_runs WHERE id=?", (int(run_id),))

    # ----- Phase 17 — Auth Matrix --------------------------------------
    # ``auth_matrix_sessions`` holds the named identities the operator
    # can replay history under. Payload material is encrypted with the
    # per-project key from :mod:`reqlore.auth_matrix.crypto` before it
    # ever touches the DB; this method takes pre-encrypted bytes.
    # ``auth_matrix_runs`` + ``auth_matrix_cells`` capture the per-run
    # state and per-(history, session) verdict respectively.

    def auth_matrix_create_session(
        self, *, name: str, kind: str, payload_blob: bytes,
        source: str = "", source_hid: int | None = None,
    ) -> int:
        """Insert a session row, returning its id. ``name`` must be
        unique within the project."""
        now = int(time.time())
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO auth_matrix_sessions"
                "(name,kind,payload_blob,source,source_hid,"
                " created_at,last_used_at,active)"
                " VALUES(?,?,?,?,?,?,0,1)",
                (str(name), str(kind), bytes(payload_blob or b""),
                 str(source), source_hid, now),
            )
            return int(cur.lastrowid or 0)

    def auth_matrix_update_session(
        self, sid: int, *, name: str | None = None,
        kind: str | None = None,
        payload_blob: bytes | None = None,
        active: bool | None = None,
        bump_last_used: bool = False,
    ) -> None:
        sets: list[str] = []
        args: list = []
        if name is not None:
            sets.append("name=?")
            args.append(str(name))
        if kind is not None:
            sets.append("kind=?")
            args.append(str(kind))
        if payload_blob is not None:
            sets.append("payload_blob=?")
            args.append(bytes(payload_blob))
        if active is not None:
            sets.append("active=?")
            args.append(1 if active else 0)
        if bump_last_used:
            sets.append("last_used_at=?")
            args.append(int(time.time()))
        if not sets:
            return
        args.append(int(sid))
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE auth_matrix_sessions SET {', '.join(sets)} "  # noqa: S608  # `sets` entries are hardcoded `col=?` fragments assembled locally; all values pass through `args`
                "WHERE id=?",
                args,
            )

    def auth_matrix_get_session(self, sid: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,name,kind,payload_blob,source,source_hid,"
                " created_at,last_used_at,active"
                " FROM auth_matrix_sessions WHERE id=?",
                (int(sid),),
            ).fetchone()
        if not r:
            return None
        return {
            "id": int(r[0]), "name": r[1], "kind": r[2],
            "payload_blob": bytes(r[3] or b""),
            "source": r[4] or "",
            "source_hid": (int(r[5]) if r[5] is not None else None),
            "created_at": int(r[6] or 0),
            "last_used_at": int(r[7] or 0),
            "active": bool(r[8]),
        }

    def auth_matrix_list_sessions(
        self, *, active_only: bool = False,
    ) -> list[dict]:
        sql = (
            "SELECT id,name,kind,payload_blob,source,source_hid,"
            " created_at,last_used_at,active"
            " FROM auth_matrix_sessions"
        )
        if active_only:
            sql += " WHERE active=1"
        sql += " ORDER BY name COLLATE NOCASE"
        with self._cursor() as cur:
            rows = cur.execute(sql).fetchall()
        out: list[dict] = []
        for r in rows:
            out.append({
                "id": int(r[0]), "name": r[1], "kind": r[2],
                "payload_blob": bytes(r[3] or b""),
                "source": r[4] or "",
                "source_hid": (int(r[5]) if r[5] is not None else None),
                "created_at": int(r[6] or 0),
                "last_used_at": int(r[7] or 0),
                "active": bool(r[8]),
            })
        return out

    def auth_matrix_delete_session(self, sid: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM auth_matrix_sessions WHERE id=?", (int(sid),),
            )

    def auth_matrix_create_run(
        self, *, mode: str, label: str = "",
        baseline_session_id: int | None = None,
        compare_session_ids: list[int] | None = None,
        history_ids: list[int] | None = None,
        options: dict | None = None,
    ) -> int:
        now = int(time.time())
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO auth_matrix_runs"
                "(mode,label,started_at,status,baseline_session_id,"
                " compare_session_ids_json,history_ids_json,options_json,"
                " progress_done,progress_total,progress_msg,log,error,"
                " verdict_counts_json)"
                " VALUES(?,?,?,?,?,?,?,?,0,?,'','','', '{}')",
                (
                    str(mode), str(label), now, "pending",
                    baseline_session_id,
                    json.dumps(list(compare_session_ids or []), ensure_ascii=False),
                    json.dumps(list(history_ids or []), ensure_ascii=False),
                    json.dumps(dict(options or {}), ensure_ascii=False),
                    int(
                        len(list(history_ids or []))
                        * max(1, len(list(compare_session_ids or [])))
                    ),
                ),
            )
            return int(cur.lastrowid or 0)

    def auth_matrix_update_run(
        self, run_id: int, *,
        status: str | None = None,
        progress_done: int | None = None,
        progress_total: int | None = None,
        progress_msg: str | None = None,
        finished_at: int | None = None,
        error: str | None = None,
        verdict_counts: dict | None = None,
    ) -> None:
        sets: list[str] = []
        args: list = []
        if status is not None:
            sets.append("status=?")
            args.append(str(status))
        if progress_done is not None:
            sets.append("progress_done=?")
            args.append(int(progress_done))
        if progress_total is not None:
            sets.append("progress_total=?")
            args.append(int(progress_total))
        if progress_msg is not None:
            sets.append("progress_msg=?")
            args.append(str(progress_msg))
        if finished_at is not None:
            sets.append("finished_at=?")
            args.append(int(finished_at))
        if error is not None:
            sets.append("error=?")
            args.append(str(error)[:2000])
        if verdict_counts is not None:
            sets.append("verdict_counts_json=?")
            args.append(json.dumps(dict(verdict_counts), ensure_ascii=False))
        if not sets:
            return
        args.append(int(run_id))
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE auth_matrix_runs SET {', '.join(sets)} WHERE id=?",  # noqa: S608  # `sets` entries are hardcoded `col=?` fragments assembled locally; all values pass through `args`
                args,
            )

    def auth_matrix_append_run_log(self, run_id: int, line: str) -> None:
        if not line:
            return
        with self._cursor() as cur:
            cur.execute(
                "UPDATE auth_matrix_runs "
                "SET log = substr(log || ? || char(10), -100000) "
                "WHERE id=?",
                (str(line)[:2000], int(run_id)),
            )

    def _row_to_auth_matrix_run(self, r: tuple) -> dict:
        try:
            compare = json.loads(r[6]) if r[6] else []
            if not isinstance(compare, list):
                compare = []
        except (TypeError, ValueError):
            compare = []
        try:
            hids = json.loads(r[7]) if r[7] else []
            if not isinstance(hids, list):
                hids = []
        except (TypeError, ValueError):
            hids = []
        try:
            opts = json.loads(r[8]) if r[8] else {}
            if not isinstance(opts, dict):
                opts = {}
        except (TypeError, ValueError):
            opts = {}
        try:
            verdicts = json.loads(r[14]) if r[14] else {}
            if not isinstance(verdicts, dict):
                verdicts = {}
        except (TypeError, ValueError):
            verdicts = {}
        return {
            "id": int(r[0]),
            "mode": r[1],
            "label": r[2] or "",
            "started_at": int(r[3] or 0),
            "finished_at": (int(r[4]) if r[4] is not None else None),
            "status": r[5] or "",
            "baseline_session_id":
                (int(r[15]) if r[15] is not None else None),
            "compare_session_ids": [int(x) for x in compare],
            "history_ids": [int(x) for x in hids],
            "options": opts,
            "progress_done": int(r[9] or 0),
            "progress_total": int(r[10] or 0),
            "progress_msg": r[11] or "",
            "log": r[12] or "",
            "error": r[13] or "",
            "verdict_counts": verdicts,
        }

    def auth_matrix_get_run(self, run_id: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,mode,label,started_at,finished_at,status,"
                " compare_session_ids_json,history_ids_json,options_json,"
                " progress_done,progress_total,progress_msg,log,error,"
                " verdict_counts_json,baseline_session_id"
                " FROM auth_matrix_runs WHERE id=?",
                (int(run_id),),
            ).fetchone()
        return self._row_to_auth_matrix_run(r) if r else None

    def auth_matrix_list_runs(
        self, *, mode: str | None = None, limit: int = 100,
    ) -> list[dict]:
        sql = (
            "SELECT id,mode,label,started_at,finished_at,status,"
            " compare_session_ids_json,history_ids_json,options_json,"
            " progress_done,progress_total,progress_msg,log,error,"
            " verdict_counts_json,baseline_session_id"
            " FROM auth_matrix_runs"
        )
        args: list = []
        if mode:
            sql += " WHERE mode=?"
            args.append(str(mode))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [self._row_to_auth_matrix_run(r) for r in rows]

    def auth_matrix_delete_run(self, run_id: int) -> None:
        with self._cursor() as cur:
            # ON DELETE CASCADE handles cells.
            cur.execute(
                "DELETE FROM auth_matrix_runs WHERE id=?", (int(run_id),),
            )

    def auth_matrix_add_cell(
        self, *, run_id: int, history_id: int, session_id: int,
        status: int, body_len: int, duration_ms: int,
        baseline_status: int | None, baseline_len: int | None,
        similarity_pct: int, verdict: str, error: str = "",
        request_blob: bytes = b"", response_blob: bytes = b"",
        baseline_response_blob: bytes = b"",
        finding_id: int | None = None,
    ) -> int:
        now = int(time.time())
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO auth_matrix_cells"
                "(run_id,history_id,session_id,status,body_len,duration_ms,"
                " baseline_status,baseline_len,similarity_pct,verdict,error,"
                " request_blob,response_blob,baseline_response_blob,"
                " finding_id,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    int(run_id), int(history_id), int(session_id),
                    int(status), int(body_len), int(duration_ms),
                    baseline_status, baseline_len,
                    int(similarity_pct), str(verdict), str(error)[:1000],
                    _compress(bytes(request_blob or b"")),
                    _compress(bytes(response_blob or b"")),
                    _compress(bytes(baseline_response_blob or b"")),
                    finding_id, now,
                ),
            )
            return int(cur.lastrowid or 0)

    def auth_matrix_update_cell_verdict(
        self, cell_id: int, *, verdict: str,
    ) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE auth_matrix_cells SET verdict=? WHERE id=?",
                (str(verdict), int(cell_id)),
            )

    def _row_to_auth_matrix_cell(self, r: tuple) -> dict:
        return {
            "id": int(r[0]),
            "run_id": int(r[1]),
            "history_id": int(r[2]),
            "session_id": int(r[3]),
            "status": int(r[4] or 0),
            "body_len": int(r[5] or 0),
            "duration_ms": int(r[6] or 0),
            "baseline_status":
                (int(r[7]) if r[7] is not None else None),
            "baseline_len":
                (int(r[8]) if r[8] is not None else None),
            "similarity_pct": int(r[9] or 0),
            "verdict": r[10] or "",
            "error": r[11] or "",
            "request_blob": _decompress(bytes(r[12] or b"")),
            "response_blob": _decompress(bytes(r[13] or b"")),
            "baseline_response_blob": _decompress(bytes(r[14] or b"")),
            "finding_id":
                (int(r[15]) if r[15] is not None else None),
            "created_at": int(r[16] or 0),
        }

    def auth_matrix_get_cell(self, cell_id: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,run_id,history_id,session_id,status,body_len,"
                " duration_ms,baseline_status,baseline_len,similarity_pct,"
                " verdict,error,request_blob,response_blob,"
                " baseline_response_blob,finding_id,created_at"
                " FROM auth_matrix_cells WHERE id=?",
                (int(cell_id),),
            ).fetchone()
        return self._row_to_auth_matrix_cell(r) if r else None

    def auth_matrix_list_cells(
        self, run_id: int, *,
        verdict: str | None = None,
        history_id: int | None = None,
        limit: int = 5000,
    ) -> list[dict]:
        sql = (
            "SELECT id,run_id,history_id,session_id,status,body_len,"
            " duration_ms,baseline_status,baseline_len,similarity_pct,"
            " verdict,error,request_blob,response_blob,"
            " baseline_response_blob,finding_id,created_at"
            " FROM auth_matrix_cells WHERE run_id=?"
        )
        args: list = [int(run_id)]
        if verdict:
            sql += " AND verdict=?"
            args.append(str(verdict))
        if history_id is not None:
            sql += " AND history_id=?"
            args.append(int(history_id))
        sql += " ORDER BY history_id, session_id LIMIT ?"
        args.append(int(limit))
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [self._row_to_auth_matrix_cell(r) for r in rows]

    def auth_matrix_cell_counts(self, run_id: int) -> dict[str, int]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT verdict, COUNT(*) FROM auth_matrix_cells "
                "WHERE run_id=? GROUP BY verdict",
                (int(run_id),),
            ).fetchall()
        return {str(v): int(c) for v, c in rows}

    def clear_dom_hunter_messages(self) -> int:
        with self._cursor() as cur:
            n = int(cur.execute(
                "SELECT COUNT(*) FROM dom_hunter_messages"
            ).fetchone()[0])
            cur.execute("DELETE FROM dom_hunter_messages")
        return n

    # ----- Phase 1.1 — live passive scan backlog ---------------------
    # The backlog is the durable, on-disk overflow store for the live
    # scanner. The in-memory queue is just a fast lane; anything that
    # cannot land there in O(1) gets parked here instead of being
    # dropped.
    #
    # We use a lease (claim / ack / nack) protocol rather than a
    # pop-and-delete protocol so the contract survives a worker crash
    # mid-scan:
    #
    #   1. ``backlog_pop_batch`` claims rows by stamping ``claimed_at``
    #      with the current epoch; the row stays in the table but is
    #      invisible to subsequent pops.
    #   2. ``backlog_release`` ACKs a successful scan by removing the
    #      row.
    #   3. ``backlog_requeue`` NACKs a failed scan, increments
    #      ``retries`` and clears the claim so the row is eligible
    #      again, or drops the row if the retry budget is exhausted.
    #   4. ``backlog_yield`` clears the claim without bumping retries
    #      (used when the worker is stopping mid-batch and wants the
    #      next session to pick the row back up cleanly).
    #   5. ``backlog_reset_claims`` clears every outstanding claim;
    #      called once on worker startup to recover any row that was
    #      mid-flight when the previous process exited abnormally.

    def backlog_enqueue(self, hid: int) -> bool:
        """Park a history-row id in the durable backlog. Idempotent.
        Returns ``True`` if the row was newly inserted, ``False`` if
        it was already present."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO live_scan_backlog"
                "(hid,ts,retries,claimed_at) VALUES (?,?,0,0)",
                (int(hid), int(time.time())),
            )
            return cur.rowcount > 0

    def backlog_pop_batch(
        self, limit: int = 32,
    ) -> list[tuple[int, int]]:
        """Claim up to ``limit`` of the oldest idle rows for scanning.

        Returns a list of ``(hid, retries)`` tuples. The rows remain in
        the table with a non-zero ``claimed_at`` until the caller
        either :meth:`backlog_release`-s them (successful scan),
        :meth:`backlog_requeue`-s them (failed scan, bump retries) or
        :meth:`backlog_yield`-s them (worker stopping, no retry bump).
        A worker crash leaves the rows visible to the next process
        once it calls :meth:`backlog_reset_claims` on startup.
        """
        n = max(1, min(int(limit), 1024))
        now = int(time.time())
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT hid, retries FROM live_scan_backlog "
                "WHERE claimed_at=0 ORDER BY ts ASC, hid ASC LIMIT ?",
                (n,),
            ).fetchall()
            if not rows:
                return []
            hids = [int(r[0]) for r in rows]
            placeholders = ",".join("?" for _ in hids)
            cur.execute(
                f"UPDATE live_scan_backlog SET claimed_at=? "  # noqa: S608  # `placeholders` is a comma-joined string of `?` markers; timestamp and hids are parameterised
                f"WHERE hid IN ({placeholders})",
                [now, *hids],
            )
        return [(int(r[0]), int(r[1])) for r in rows]

    def backlog_release(self, hid: int) -> bool:
        """ACK a successful scan by removing the row from the backlog.
        Returns ``True`` if a row was actually deleted."""
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM live_scan_backlog WHERE hid=?", (int(hid),),
            )
            return cur.rowcount > 0

    def backlog_yield(self, hid: int) -> bool:
        """Clear the claim on a row without bumping retries. Used when
        the worker is shutting down mid-batch — the row should be
        eligible for the next worker run with no penalty. Returns
        ``True`` if the row was found."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE live_scan_backlog SET claimed_at=0 WHERE hid=?",
                (int(hid),),
            )
            return cur.rowcount > 0

    def backlog_requeue(self, hid: int, *, max_retries: int = 3) -> bool:
        """NACK a failed scan: bump ``retries`` and clear the claim so
        the row becomes eligible again. Returns ``False`` (and drops
        the row) once ``retries`` would exceed ``max_retries``.
        Returns ``False`` if the row no longer exists in the backlog
        (e.g. concurrent clear).
        """
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT retries FROM live_scan_backlog WHERE hid=?",
                (int(hid),),
            ).fetchone()
            if row is None:
                return False
            retries = int(row[0]) + 1
            if retries > int(max_retries):
                cur.execute(
                    "DELETE FROM live_scan_backlog WHERE hid=?",
                    (int(hid),),
                )
                return False
            cur.execute(
                "UPDATE live_scan_backlog SET retries=?, ts=?, "
                "claimed_at=0 WHERE hid=?",
                (retries, int(time.time()), int(hid)),
            )
            return True

    def backlog_reset_claims(self) -> int:
        """Clear every outstanding claim. Called once on worker
        startup so rows that were mid-flight when the previous
        process died become eligible again. Returns the number of
        rows whose claim was reset."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE live_scan_backlog SET claimed_at=0 "
                "WHERE claimed_at<>0",
            )
            return int(cur.rowcount)

    def backlog_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute(
                "SELECT COUNT(*) FROM live_scan_backlog"
            ).fetchone()[0])

    def backlog_clear(self) -> int:
        """Drop every parked row. Returns the count removed.
        Surface this with a confirmation dialog in the UI — the
        deleted rows will not be re-scanned automatically."""
        with self._cursor() as cur:
            n = int(cur.execute(
                "SELECT COUNT(*) FROM live_scan_backlog"
            ).fetchone()[0])
            cur.execute("DELETE FROM live_scan_backlog")
        return n
