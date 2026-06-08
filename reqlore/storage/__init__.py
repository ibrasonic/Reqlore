"""SQLite-backed project file. Single facade for all reads + writes."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 2

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
    status TEXT NOT NULL DEFAULT 'idle',  -- idle | running | paused | done | cancelled
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
"""


def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=6) if data else b""


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data) if data else b""


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
        ]
        for table, col, decl in adds:
            cols = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
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
                             grep_hits: str, history_id: int | None) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO intruder_results(attack_id,seq,payloads_json,status,len_resp,"
                "duration_ms,grep_hits,history_id) VALUES (?,?,?,?,?,?,?,?)",
                (attack_id, seq, json.dumps(payloads), status, len_resp, duration_ms,
                 grep_hits, history_id),
            )
            return int(cur.lastrowid or 0)

    def list_intruder_results(self, attack_id: int, *, sort: str = "seq",
                               desc: bool = False) -> list[dict]:
        order_col = {
            "seq": "seq", "status": "status", "len": "len_resp",
            "time": "duration_ms", "grep": "grep_hits",
        }.get(sort, "seq")
        direction = "DESC" if desc else "ASC"
        with self._cursor() as cur:
            rows = cur.execute(
                f"SELECT id,seq,payloads_json,status,len_resp,duration_ms,grep_hits,history_id "
                f"FROM intruder_results WHERE attack_id=? ORDER BY {order_col} {direction}",
                (attack_id,),
            ).fetchall()
        return [
            {"id": r[0], "seq": r[1], "payloads": json.loads(r[2]), "status": r[3],
             "len_resp": r[4], "duration_ms": r[5], "grep_hits": r[6], "history_id": r[7]}
            for r in rows
        ]

    def delete_intruder(self, aid: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM intruder_results WHERE attack_id=?", (aid,))
            cur.execute("DELETE FROM intruder_attacks WHERE id=?", (aid,))

    # ---- findings (scanner output) ----
    SEVERITIES = ("info", "low", "medium", "high", "critical")
    STATUSES = ("open", "triaged", "false_positive", "fixed")

    def add_finding(self, *, severity: str, title: str, cwe: str = "",
                    owasp: str = "", host: str = "", url: str = "",
                    request_id: int | None = None, response_id: int | None = None,
                    evidence: str = "", payload: str = "",
                    dedupe_key: str | None = None) -> int:
        """Insert a finding. If dedupe_key is provided, drop duplicates on the
        same (title, host, url, evidence-prefix) tuple to avoid scanner noise."""
        if dedupe_key:
            with self._cursor() as cur:
                r = cur.execute(
                    "SELECT id FROM issues WHERE title=? AND COALESCE(host,'')=? "
                    "AND COALESCE(url,'')=? AND substr(evidence,1,200)=substr(?,1,200) "
                    "LIMIT 1",
                    (title, host, url, evidence),
                ).fetchone()
                if r:
                    return int(r[0])
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO issues(severity,cwe,owasp,title,host,url,request_id,"
                "response_id,evidence,payload,status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?)",
                (severity, cwe, owasp, title, host, url, request_id, response_id,
                 evidence, payload, int(time.time())),
            )
            return int(cur.lastrowid or 0)

    def list_findings(self, *, severity: str | None = None, status: str | None = None,
                       host: str | None = None, limit: int = 500) -> list[dict]:
        sql = ("SELECT id,severity,cwe,owasp,title,host,url,request_id,response_id,"
               "evidence,payload,status,created_at FROM issues WHERE 1=1")
        args: list = []
        if severity:
            sql += " AND severity=?"; args.append(severity)
        if status:
            sql += " AND status=?"; args.append(status)
        if host:
            sql += " AND host=?"; args.append(host)
        sql += " ORDER BY CASE severity "
        sql += "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        sql += "WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT ?"
        args.append(limit)
        with self._cursor() as cur:
            rows = cur.execute(sql, args).fetchall()
        return [
            {"id": r[0], "severity": r[1], "cwe": r[2], "owasp": r[3], "title": r[4],
             "host": r[5], "url": r[6], "request_id": r[7], "response_id": r[8],
             "evidence": r[9], "payload": r[10], "status": r[11], "created_at": r[12]}
            for r in rows
        ]

    def get_finding(self, fid: int) -> dict | None:
        with self._cursor() as cur:
            r = cur.execute(
                "SELECT id,severity,cwe,owasp,title,host,url,request_id,response_id,"
                "evidence,payload,status,created_at FROM issues WHERE id=?", (fid,),
            ).fetchone()
        if not r:
            return None
        return {"id": r[0], "severity": r[1], "cwe": r[2], "owasp": r[3], "title": r[4],
                "host": r[5], "url": r[6], "request_id": r[7], "response_id": r[8],
                "evidence": r[9], "payload": r[10], "status": r[11], "created_at": r[12]}

    def set_finding_status(self, fid: int, status: str) -> None:
        if status not in self.STATUSES:
            raise ValueError(f"unknown status: {status}")
        with self._cursor() as cur:
            cur.execute("UPDATE issues SET status=? WHERE id=?", (status, fid))

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
