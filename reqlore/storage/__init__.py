"""SQLite-backed project file. Single facade for all reads + writes."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid as _uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 3

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
    edited_blob BLOB
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
"""


def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=6) if data else b""


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data) if data else b""


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
        ]
        for table, col, decl in adds:
            cols = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except sqlite3.OperationalError:
                    pass
        # Indices we want even on freshly-migrated databases.
        for ddl in (
            "CREATE INDEX IF NOT EXISTS idx_issues_source ON issues(source)",
            "CREATE INDEX IF NOT EXISTS idx_issues_uuid ON issues(uuid)",
            "CREATE INDEX IF NOT EXISTS idx_issues_rule ON issues(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_issues_dedupe ON issues(dedupe_key)",
        ):
            try:
                self._conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
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
            self._conn.close()

    # ---- project meta ----
    def meta(self) -> dict:
        with self._cursor() as cur:
            r = cur.execute("SELECT name, created_at, schema_version, settings_json FROM project").fetchone()
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
    ) -> list[HistoryRow]:
        sql = ("SELECT id,ts,host,method,url,status,len_req,len_resp,duration_ms,"
               "engine,flags,tags,req_blob,resp_blob FROM http_history WHERE 1=1")
        args: list = []
        if host:
            sql += " AND host = ?"
            args.append(host)
        if method:
            sql += " AND method = ?"
            args.append(method.upper())
        if q:
            sql += " AND url LIKE ?"
            args.append(f"%{q}%")
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [HistoryRow(*r[:12], _decompress(r[12]), _decompress(r[13])) for r in rows]

    def get_history(self, hid: int) -> HistoryRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,ts,host,method,url,status,len_req,len_resp,duration_ms,"
                "engine,flags,tags,req_blob,resp_blob FROM http_history WHERE id=?",
                (hid,),
            ).fetchone()
        if not r:
            return None
        return HistoryRow(*r[:12], _decompress(r[12]), _decompress(r[13]))

    def history_count(self) -> int:
        with self._cursor() as cur:
            return int(cur.execute("SELECT COUNT(*) FROM http_history").fetchone()[0])

    def count_history_after(
        self, since: int, *,
        host: str | None = None, q: str | None = None,
        method: str | None = None,
    ) -> tuple[int, int]:
        """Return (new_count, max_id) for rows with id > since matching filters.

        max_id is the overall MAX(id) under the same filters (0 if empty), so
        the client can advance its "since" cursor monotonically.
        """
        base = " FROM http_history WHERE 1=1"
        args: list = []
        if host:
            base += " AND host = ?"; args.append(host)
        if method:
            base += " AND method = ?"; args.append(method.upper())
        if q:
            base += " AND url LIKE ?"; args.append(f"%{q}%")
        with self._cursor() as cur:
            max_id = int(cur.execute("SELECT COALESCE(MAX(id), 0)" + base, args).fetchone()[0])
            new_count = int(cur.execute(
                "SELECT COUNT(*)" + base + " AND id > ?", args + [int(since)],
            ).fetchone()[0])
        return new_count, max_id

    def clear_history(self) -> int:
        """Delete all recorded HTTP history. Returns the number of rows removed."""
        with self._cursor() as cur:
            n = int(cur.execute("SELECT COUNT(*) FROM http_history").fetchone()[0])
            cur.execute("DELETE FROM http_history")
        return n

    # ---- intercept queue ----
    def enqueue_intercept(self, kind: str, raw: bytes, reason: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intercept_q(kind,req_blob,hold_reason,created_at) VALUES (?,?,?,?)",
                (kind, _compress(raw), reason, int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def list_intercept(self) -> list[InterceptRow]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at FROM intercept_q ORDER BY id"
            ).fetchall()
        return [InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4]) for r in rows]

    def get_intercept(self, iid: int) -> InterceptRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at FROM intercept_q WHERE id=?",
                (iid,),
            ).fetchone()
        if not r:
            return None
        return InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4])

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
                                flow_id: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intercept_q(kind,req_blob,hold_reason,created_at,flow_id) "
                "VALUES (?,?,?,?,?)",
                (kind, _compress(raw), reason, int(time.time()), flow_id),
            )
            return int(cur.lastrowid or 0)

    def get_intercept_by_flow(self, flow_id: str) -> InterceptRow | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,kind,req_blob,hold_reason,created_at FROM intercept_q "
                "WHERE flow_id=? AND decision IS NULL",
                (flow_id,),
            ).fetchone()
        if not r:
            return None
        return InterceptRow(r[0], r[1], _decompress(r[2]), r[3], r[4])

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
            sql += " AND host=?"; args.append(host)
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
        like = f"%{q}%"
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
            if where in ("any", "req"):
                if ql in _decompress(r[7]).lower():
                    hits.append("request")
            if where in ("any", "resp"):
                if ql in _decompress(r[8]).lower():
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
                f"SELECT id,seq,payloads_json,status,len_resp,duration_ms,grep_hits,history_id,"
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
    )

    @staticmethod
    def _row_to_finding(r) -> dict:
        out = dict(zip(Project._ISSUES_COLS, r))
        try:
            out["references"] = json.loads(out.pop("references_json") or "[]")
        except (ValueError, TypeError):
            out["references"] = []
            out.pop("references_json", None)
        return out

    @staticmethod
    def _compute_dedupe_key(*, rule_id: str, title: str, host: str,
                             url: str, evidence: str) -> str:
        ev_hash = hashlib.sha256(evidence.encode("utf-8", "replace")).hexdigest()[:16]
        key_id = rule_id or f"legacy:{title}"
        return f"{key_id}|{host}|{url}|{ev_hash}"

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
                    dedupe_key: str | None = None) -> int:
        """Insert a finding. If a finding with the same dedupe_key already
        exists, return its id instead of inserting a duplicate."""
        key = dedupe_key or self._compute_dedupe_key(
            rule_id=rule_id, title=title, host=host, url=url, evidence=evidence,
        )
        now = int(time.time())
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id FROM issues WHERE dedupe_key=? LIMIT 1", (key,),
            ).fetchone()
            if r:
                fid = int(r[0])
                if extra_targets:
                    self._add_finding_targets(cur, fid, extra_targets)
                return fid
            # Legacy fallback: pre-v3 rows have NULL dedupe_key.
            r = cur.execute(
                "SELECT id FROM issues WHERE title=? AND COALESCE(host,'')=? "
                "AND COALESCE(url,'')=? AND substr(evidence,1,200)=substr(?,1,200) "
                "AND (dedupe_key IS NULL OR dedupe_key='') LIMIT 1",
                (title, host, url, evidence),
            ).fetchone()
            if r:
                fid = int(r[0])
                cur.execute(
                    "UPDATE issues SET dedupe_key=? WHERE id=?", (key, fid),
                )
                if extra_targets:
                    self._add_finding_targets(cur, fid, extra_targets)
                return fid
            refs_json = json.dumps(list(references or []))
            cur.execute(
                "INSERT INTO issues(severity,cwe,owasp,title,host,url,request_id,"
                "response_id,evidence,payload,status,created_at,uuid,source,"
                "rule_id,rule_version,description,remediation,references_json,"
                "cvss_vector,cvss_score,reproduction_token,updated_at,dedupe_key) "
                "VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (severity, cwe, owasp, title, host, url, request_id, response_id,
                 evidence, payload, now,
                 _uuid.uuid4().hex, source, rule_id, rule_version,
                 description, remediation, refs_json,
                 cvss_vector, cvss_score, reproduction_token, now, key),
            )
            fid = int(cur.lastrowid or 0)
            if extra_targets:
                self._add_finding_targets(cur, fid, extra_targets)
            return fid

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
                       limit: int = 500) -> list[dict]:
        cols = ",".join(self._ISSUES_COLS)
        sql = f"SELECT {cols} FROM issues WHERE 1=1"
        args: list = []
        if severity:
            sql += " AND severity=?"; args.append(severity)
        if status:
            sql += " AND status=?"; args.append(status)
        if host:
            sql += " AND host=?"; args.append(host)
        if source:
            sql += " AND source=?"; args.append(source)
        if rule_id:
            sql += " AND rule_id=?"; args.append(rule_id)
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
                f"SELECT {cols} FROM issues WHERE id=?", (fid,),
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
        out = {s: 0 for s in self.SEVERITIES}
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

    def clear_dom_hunter_messages(self) -> int:
        with self._cursor() as cur:
            n = int(cur.execute(
                "SELECT COUNT(*) FROM dom_hunter_messages"
            ).fetchone()[0])
            cur.execute("DELETE FROM dom_hunter_messages")
        return n
