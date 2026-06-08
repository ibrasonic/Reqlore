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

Every outgoing request flows through an **Engine** chosen by the caller:

| Engine | Purpose | When to use |
|---|---|---|
| `httpx_engine` | Default. HTTP/1.1 + HTTP/2, mTLS, proxies, streaming. | 95% of traffic — Repeater, Intruder, scanner, history replay. |
| `raw_engine` | Byte-exact requests over raw socket + ssl. | Smuggling, malformed headers, `--path-as-is` equivalents, edge cases httpx normalises. |
| `h2_engine` | Direct HTTP/2 frame control via `h2` lib. | Smuggling, priority abuse, settings flooding tests. |
| `h3_engine` | HTTP/3 over QUIC via `aioquic` / `qh3`. | Targets that only speak H3. |
| `ws_engine` | WebSocket via `websockets`. | WS history + repeater + fuzz. |
| `curl_render` | **Render only**, never sends. | "Copy as curl" exports. |

A common `Request` dataclass and `Response` dataclass are shared across engines so the UI doesn't care which engine produced a response.

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
    status: int
    reason: str
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes
    timings: Timings           # dns/connect/tls/ttfb/total
    engine: str
    raw_request: bytes | None  # exact bytes sent, if available
```

## Proxy

Built on `mitmproxy` library (not the binaries). We use it for:

- TLS Certificate Authority generation + rotation (stored under `~/.reqlore/ca/`, 0600 perms).
- HTTP/1.1 + HTTP/2 transparent and explicit proxy modes.
- WebSocket frame interception.

On top we layer:

- **Rules engine** (`proxy/rules.py`) — host/method/status/content-type filters that decide whether to hold a request for interception.
- **Intercept queue** — held requests go into a SQLite-backed FIFO; the UI shows the queue, the user edits/forwards/drops.
- **Match & Replace** — applied automatically on requests/responses by scope.

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

- Plugins are Python modules in `~/.reqlore/plugins/*.py` *or* installed via pip (entry point `reqlore.plugins`).
- `plugins/api.py` exposes a stable API: `on_request(ctx)`, `on_response(ctx)`, `add_passive_check(fn)`, `add_active_check(fn)`, `add_payload_processor(name, fn)`, `add_menu_item(label, path, handler)`, `add_template(path, content)`.
- `watchdog` hot-reloads plugins on file change in dev mode.
- Per-plugin enable/disable in the Settings UI; signature optional but recommended (Ed25519).

## Concurrency

- UI: Flask + `waitress` WSGI server (Windows-friendly, no eventlet).
- Proxy: mitmproxy's asyncio loop in its own thread.
- Engines: a `concurrent.futures.ThreadPoolExecutor` per module for parallel jobs (Intruder, scanner, discovery).
- Rate limiting: per-request `delay_ms` knob on Intruder and Param-Miner workbenches; `ActiveScanner` enforces a per-scan throttle through its injected sender. Engines themselves do not rate-limit; callers are expected to space requests or cap concurrency.

## Configuration

- Defaults baked into `config.py`.
- Per-project overrides in `project_state` table.
- Per-user overrides in `~/.reqlore/config.toml`.
- CLI flags override everything.
- Resolution order: CLI > env > user > project > defaults.
