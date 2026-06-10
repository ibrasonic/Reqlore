# Reqlore — Architecture

## Process model

Reqlore runs as **one Python process** with three concurrent surfaces:

```
                  +--------------------+
   browser  <-->  |  Flask UI :8787    |  (server-rendered HTML)
                  |  127.0.0.1 only    |
                  +--------+-----------+
                           |
                  +--------v-----------+        intercept queue
                  |   Core (Python)    |  <-->  in-memory + SQLite
                  +--------+-----------+
                           |
                  +--------v-----------+
   browser  <-->  |  MITM Proxy :8080  |  (mitmproxy lib)
                  +--------------------+
```

The Flask UI thread, the proxy event loop, and a thread pool for the engines all share one SQLite project file via a single `storage.Project` facade with a write lock.

## Engines

Every outgoing request flows through one of four **transport engines**
chosen by the caller, plus a render-only helper. Full details in
[engines.md](engines.md).

| Engine | Purpose | When to use |
|---|---|---|
| `httpx_engine` | Default. HTTP/1.1 + HTTP/2, mTLS, proxies, streaming. 30 s timeout. | 95% of traffic — Repeater, Intruder, scanner, history replay. |
| `raw_engine` | Byte-exact requests over raw socket + ssl. 30 s timeout. | Smuggling, malformed headers, edge cases `httpx` normalises away. |
| `h3_engine` | HTTP/3 over QUIC via `aioquic`. Optional `[h3]` extra. 15 s timeout. | Targets that only speak H3. |
| `curl_cffi_engine` | curl-impersonate JA3/JA4 spoofing. Optional `[impersonate]` extra. 15 s timeout. 8 profiles. | Anti-bot bypass; reaching CDNs that fingerprint TLS handshakes. |
| `curl_render` | **Render only**, never sends. | "Copy as curl" exports. |

HTTP/2 frame work and WebSocket fuzzing are handled by dedicated
workbenches (`reqlore.h2_tool` + `/h2/`, `reqlore.websocket` + `/ws/`)
rather than transport engines — they own their own protocol state and
need UI surface that doesn't fit the `send(req) -> resp` contract.

A common `Request` dataclass and `Response` dataclass are shared across
engines so the UI doesn't care which engine produced a response. The
documented degradation signal is `Response(status=0, error="…")` — the
active scanner relies on this contract.

```python
@dataclass
class Request:
    method: str
    url: str
    http_version: str          # "1.1" | "2" | "3"
    headers: list[tuple[str, str]]   # ordered, case-preserved
    body: bytes
    extras: dict[str, Any]     # engine-specific knobs

@dataclass
class Response:
    status: int                # 0 == transport failure; see `error`
    reason: str
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes
    timings: Timings           # dns/connect/tls/ttfb/total
    engine: str
    raw_request: bytes | None  # exact bytes sent, if available
    error: str | None = None   # set when transport failed or extra missing
```

The dispatcher `_send_factory(engine, opts)` in `reqlore/intruder.py`
resolves an engine string (e.g. `httpx`, `raw`, `h3`,
`curl-cffi:chrome120`) to a `send` callable; the Repeater + Intruder UI
pickers both feed strings through it.

## Proxy

Built on `mitmproxy` library (not the binaries). We use it for:

- TLS Certificate Authority generation + rotation (stored under `~/.reqlore/ca/`, 0600 perms).
- HTTP/1.1 + HTTP/2 transparent and explicit proxy modes.
- WebSocket frame interception.

On top we layer:

- **Rules engine** (`proxy/rules.py`) — host/method/status/content-type filters that decide whether to hold a request for interception.
- **Intercept queue** — held requests go into a SQLite-backed FIFO; the UI shows the queue, the user edits/forwards/drops.
- **Match & Replace** — applied automatically on requests/responses by scope.

The History page exposes a small server-driven live indicator:
`/history/latest.json?since=<row_id>` returns `{new, max_id, since}`
backed by `Project.count_history_after(since, host=…, …)` so the page
can refresh a `role="status"` region without JS routing. Same pattern
on Intruder detail (`/intruder/<id>/results.json?since=<seq>`) for
live results during a running attack.

## Storage

A `.rlr` project file is a SQLite database with these tables:

```sql
project        (id, name, created_at, schema_version, settings_json)
scope          (id, kind, pattern, action)              -- in/out/exclude
endpoints      (id, host, port, scheme)
http_history   (id, ts, host, method, url, status, len_req, len_resp,
                duration_ms, engine, flags, tags, req_blob, resp_blob)
ws_history     (id, ts, conn_id, direction, opcode, payload, masked)
intercept_q    (id, kind, req_blob, hold_reason, created_at)
issues         (id, severity, cwe, owasp, title, host, url, request_id,
                response_id, evidence, payload, status, created_at)
notes          (id, target, target_id, body, created_at, author)
attachments    (id, kind, sha256, mime, size, blob)
saved_payloads (id, name, kind, body)
project_state  (key, value)
```

Large binary blobs (`req_blob`, `resp_blob`, attachments) are LZ4-compressed before insert. Schema migrations live in `storage/migrations/`.

## UI layer

- Flask app factory (`app.py:create_app(project_path)`).
- One Blueprint per module (`web/blueprints/proxy.py`, `repeater.py`, etc).
- Templates extend `base.html`, which provides:
  - Skip-link, header with module nav, main with `id="main"`, footer.
  - Live region (`<div id="sr-live" aria-live="polite" aria-atomic="true">`) for announcements.
  - Theme + verbosity controls (form posts; persisted per project).
- No client-side routing. No build step. `reqlore.js` is small and progressive (sortable tables, copy-to-clipboard helper, keyboard-shortcut handler, audio-cue player) — every action works without it.
- All forms submit POST → 303 redirect (PRG pattern) to avoid double-submit prompts.

## Plugin system

See [PLUGINS.md](PLUGINS.md) for the user-facing contract. In short:

- Plugins are single Python files in `~/.reqlore/plugins/*.py` (per
  user) or a `plugins/` folder next to the `*.rlr` (per project).
- Three entry points: `PLUGIN_INFO` (required dict),
  `scanner_rules() -> [Callable]`, `register(app: Flask) -> None`,
  `copy_as() -> [CopyAsHandler]`.
- `watchdog`-driven hot reload via the optional `[plugins]` extra.
- Per-plugin enable/disable on `/plugins/`. Import errors are caught
  and surfaced; a broken plugin disables itself instead of taking the
  whole app down.

## Intruder pipeline

The Intruder request loop in `reqlore/intruder.py` is split into
three pluggable stages so each is independently testable:

1. **Source** — produces the next payload tuple for the chosen attack
   type (sniper / battering-ram / pitchfork / cluster-bomb). Sources
   are list / file / brute / dates / numbers / common-passwords.
2. **Processors** — a chain of named transforms run per payload
   (`apply_processors(value, processors)`). Two registries: `PROCESSORS`
   for nullary functions (`case_upper`, `b64`, `md5`, …) and
   `ARG_PROCESSORS` for `name:arg` syntax (`prefix:foo`, `suffix:bar`,
   `regex_replace:pat:repl`). A specialised `jwt:<spec>` processor mints
   a fresh signed token per payload.
3. **Sender** — the engine-resolved callable from `_send_factory`.
   Receives the processed payload tuple substituted into the request
   template, returns a `Response`. The runner checks a shared cancel
   event before each call so Pause / Cancel from the UI is responsive.

Results stream back through the project's append-only result store;
the live `?auto=1` indicator polls `/results.json?since=<seq>` for
new rows.

## Concurrency

- UI: Flask development server bound to `127.0.0.1`; one request at a
  time per worker is fine because all heavy work hands off to engine
  threads.
- Proxy: mitmproxy's asyncio loop in its own thread, constructed with
  an explicit `loop=` argument (`DumpMaster(loop=loop)`) to side-step
  the `get_running_loop()` regression in mitmproxy 10+.
- Engines: a `concurrent.futures.ThreadPoolExecutor` per module for
  parallel jobs (Intruder, scanner, discovery).
- Rate limiting: per-request `delay_ms` knob on Intruder and
  Param-Miner; `ActiveScanner` enforces a per-scan throttle through
  its injected sender. Engines themselves do not rate-limit; callers
  are expected to space requests or cap concurrency.

## Configuration

- Defaults baked into `config.py`.
- Per-project overrides in `project_state` table.
- Per-user overrides in `~/.reqlore/config.toml`.
- CLI flags override everything.
- Resolution order: CLI > env > user > project > defaults.

## Reliability matrix

A dedicated test surface —
[`test_reliability_phase{1..4}.py`](../reqlore/tests/unit/) — boots
the app and asserts an architectural invariant on every test run:

1. **Module import sweep** — `pkgutil.walk_packages` over `reqlore.*`,
   each `importlib.import_module(name)` must not raise.
2. **Blueprint reachability** — walks `app.url_map.iter_rules()`,
   GETs every parameterless route, asserts status `∈ {200, 302, 303,
   401}` (plus a small documented skip-set of intentional 404s).
3. **CLI subcommand parse** — introspects `build_parser()._SubParsersAction`,
   runs each subcommand with `--help`, asserts `SystemExit(0)`.
4. **Engine round-trip sanity** — `raw_engine._build_raw` /
   `_parse_response` round-trip; `raw_engine.send` against a dead port
   returns `Response(status=0, error=…)`; `httpx_engine.send` keeps
   its `(req, *, timeout, follow_redirects)` signature locked.

The matrix is the canonical guard against architectural drift —
rename a module without updating its import sites, add a blueprint
without a template, or break an engine signature, and one of these
four groups will fail before any feature test gets a chance.
