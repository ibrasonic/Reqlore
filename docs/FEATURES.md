# Reqlore — Feature Matrix

Legend: ✅ shipped · 🚧 in progress · 📋 planned · — out of scope

Cross-reference: every shipped item links to its module page in
[docs/modules/](modules/) or the corresponding cross-cutting page.
For phase-by-phase delivery, see [ROADMAP.md](ROADMAP.md).

## Core

| Feature | Status | Notes |
|---|---|---|
| Local web UI (Flask, 127.0.0.1) | ✅ | Themes: light / dark / high-contrast / system. See [Settings](modules/settings.md). |
| Project files (`.rlr` SQLite) | ✅ | Thread-safe, WAL, zlib blob compression. |
| HTTP engine: `httpx` (H1/H2, mTLS, proxies) | ✅ | Default. See [engines.md](engines.md). |
| HTTP engine: `raw` (socket + ssl) | ✅ | Byte-exact, no normalisation. |
| HTTP engine: `h3` / QUIC | ✅ | Optional `[h3]` extra (`aioquic`). |
| HTTP engine: `curl-cffi:*` (JA3/JA4 impersonation) | ✅ | Optional `[impersonate]` extra. 8 profiles (chrome120/119/116/110, safari17_0/15_5, firefox109/102). |
| `curl_render` helper (Copy as curl) | ✅ | Export-only; never sends. |
| WebSocket workbench | ✅ | Optional `[websocket]` extra. See [websocket.md](modules/websocket.md). |
| Plugin API + hot reload | ✅ | `watchdog`-driven. See [PLUGINS.md](PLUGINS.md). |
| CLI runner (`reqlore run`, YAML / JSON jobs) | ✅ | Same engines; no UI. Optional `[yaml]` extra for YAML. |
| Portable Firefox launcher (`reqlore browser`) | ✅ | See [browser-launcher.md](browser-launcher.md). |
| HAR 1.2 importer (`reqlore import-har`) | ✅ | stdlib-only parser. |
| Scheduled passive scans | ✅ | Optional `[schedule]` extra (APScheduler), thread fallback otherwise. See [scheduler.md](modules/scheduler.md). |
| Opt-in update check | ✅ | Off by default; manual GET only. |
| Docker image | ✅ | `docker compose up --build`. Loopback-bound. |

## Proxy & interception

| Feature | Status | Notes |
|---|---|---|
| MITM proxy (mitmproxy lib) | ✅ | See [proxy.md](modules/proxy.md). |
| Explicit + transparent modes | ✅ | |
| TLS CA generation + export | ✅ | `~/.reqlore/ca/reqlore-ca.pem` (RSA-2048, 5yr, 0600). |
| Intercept rules (host / method / status / CT) | ✅ | |
| Sync + async hold queue | ✅ | SR-friendly forward / edit / drop. |
| Match & Replace (req/resp, scoped, literal + regex) | ✅ | See [matchreplace.md](modules/matchreplace.md). |
| Match & Replace Quick Presets (reveal hidden fields, strip CSP/XFO/HttpOnly, unlock inputs) | ✅ | One-click rule bundles, host-scoped. See [matchreplace.md](modules/matchreplace.md#quick-presets). |

## History & targeting

| Feature | Status | Notes |
|---|---|---|
| HTTP history (search, filter, export) | ✅ | JSONL export. See [history.md](modules/history.md). |
| Live new-row indicator (`/history/latest.json`) | ✅ | Server-driven poll, no JS routing. |
| Sitemap (host tree, in / out scope) | ✅ | See [sitemap.md](modules/sitemap.md). |
| Extended columns (auth / csrf / cors / csp / cookie / redirect flags) | ✅ | |
| Project-wide search (URL · request · response) | ✅ | |
| WebSocket transcript persistence | ✅ | Stored in `project_state` KV. |

## Repeater

| Feature | Status | Notes |
|---|---|---|
| Send / edit / replay | ✅ | See [repeater.md](modules/repeater.md). |
| Paste curl → load request | ✅ | |
| Paste raw HTTP → load request | ✅ | |
| Tabbed history per request | ✅ | |
| Engine picker (all 4 transports + curl-cffi profiles) | ✅ | |
| Send-to: Intruder / Comparer / PoC / JWT / Decoder | ✅ | See [KEYBINDINGS.md](KEYBINDINGS.md). |

## Intruder

| Feature | Status | Notes |
|---|---|---|
| Sniper / Battering Ram / Pitchfork / Cluster Bomb | ✅ | See [intruder.md](modules/intruder.md). |
| Payload sources (list / file / brute / dates / numbers / common-pw) | ✅ | |
| Payload processors (case / encode / hash / regex / prefix / suffix) | ✅ | `PROCESSORS` + `ARG_PROCESSORS` in `reqlore/intruder.py`. |
| JWT-mint processor (per-payload signed token) | ✅ | `jwt:<spec>` syntax. |
| Grep-match / grep-extract / grep-payloads | ✅ | |
| Sortable / filterable results table (status / length / time) | ✅ | Filters by status class, length range, free-text. |
| Pause / Resume / Cancel from UI | ✅ | `Alt+P / Alt+R / Alt+C`. |
| Auto-refresh while running (server-driven, no JS) | ✅ | `?auto=1` + `/results.json?since=<seq>`. |
| Engine picker (4 transports + curl-cffi profiles) | ✅ | |
| Per-host concurrency limiter | ✅ | |
| Results triage — status-class / length-range / free-text / matched-only / dedupe-by-body-md5 | ✅ | |
| Streaming CSV / JSON export (filter-aware) | ✅ | `/<aid>/export.csv`, `/<aid>/export.json`. |
| Built-in wordlists (common-pw / usernames / LFI / XSS / SQLi / subdomains) + `load_wordlist_file()` | ✅ | 5 MB / 100k-line caps. |
| Headless CLI (`reqlore intruder {run,list,show,export}`) | ✅ | YAML / JSON spec via `intruder_spec.py`; `--dry-run`. |
| Per-position payload-set assignment for Sniper / preamble macro / bounded-inflight scheduler | 🚧 | Phase 5 items 6/7/9 of intruder enhancement plan. |

## Decoder / encoder

| Feature | Status | Notes |
|---|---|---|
| URL / HTML / b64 / hex / gzip / deflate | ✅ | See [decoder.md](modules/decoder.md). |
| Form-body URL encode / decode (preserves `&` and `=`) | ✅ | |
| JWT decode + sign (HS / RS / ES, `alg=none`) | ✅ | See [jwt.md](modules/jwt.md). |
| Unicode escapes / ROT-N | ✅ | |
| MD5 / SHA1 / SHA-2 / HMAC | ✅ | |
| Smart-decode (chained) | ✅ | |

## Comparer

| Feature | Status | Notes |
|---|---|---|
| Word + line diff with line numbers | ✅ | See [comparer.md](modules/comparer.md). |
| Byte / cookie / header summary | ✅ | |
| SR-friendly "in A / in B / changed" summary | ✅ | |

## Scanner

| Feature | Status | Notes |
|---|---|---|
| Passive — security headers, X-Frame-Options, cookies, banner, CORS, errors, dir listing, sensitive paths, mixed content, JWT alg=none, open-redirect, basic-auth-over-HTTP, GraphQL batching hint, +others | ✅ | See [scanner.md](modules/scanner.md). |
| Active — XSS reflected, SQLi error, open-redirect, SSTI, OS-cmd-time, JWT alg=none, prototype-pollution, GraphQL introspection, GraphQL batching, deserialisation reflection, forced-browsing, web-cache deception, HTTP smuggling (opt-in), OAST-SSRF | ✅ | Gap-plan complete. |
| Per-finding CWE + OWASP + reproducer | ✅ | |
| Triage workflow (open → triaged → false_positive → fixed) | ✅ | |
| Filter by severity / status / host | ✅ | |
| Resumable scans | ✅ | Reliability Phase 5 (`test_resumable_scans_b5.py`). |
| Coverage page with "Why not fired" reasons | ✅ | Reliability gap-closure. |
| Session-cookie entropy auto-feed (Sequencer → finding) | ✅ | |

## Specialised modules

| Feature | Status | Notes |
|---|---|---|
| JWT workbench (decode / sign / alg-switch / key-confusion / kid traversal) | ✅ | See [jwt.md](modules/jwt.md). |
| SAML inspector + signature audit | ✅ | See [saml.md](modules/saml.md). |
| GraphQL workbench (introspection, schema explorer, batch) | ✅ | See [graphql.md](modules/graphql.md). |
| Param-miner (header / cookie / param brute via length oracle) | ✅ | 200-word built-in list. See [param-miner.md](modules/param-miner.md). |
| Sequencer (entropy, per-position, Hamming, longest-run) | ✅ | See [sequencer.md](modules/sequencer.md). |
| Sequencer deep statistical battery (transition / FIPS monobit-runs-poker per bit / Bonferroni-corrected pairwise correlation / zlib compression) | ✅ | Pure-Python, no scipy. See [sequencer.md](modules/sequencer.md#limits-deep-analysis-only). |
| CSRF PoC generator (form + fetch flavours) | ✅ | See [poc.md](modules/poc.md). |
| Clickjacking tester | ✅ | |
| OAST (in-process HTTP receiver, per-token routing) | ✅ | See [oast.md](modules/oast.md). |
| HTTP/2 frame tool (parse / build) | ✅ | See [h2.md](modules/h2.md). |
| Request-smuggling helpers (CL.TE / TE.CL / TE.TE) | ✅ | See [smuggling.md](modules/smuggling.md). |
| Content discovery wordlist | — | Use `forced-browsing` active check in Scanner. |

## Session handling

| Feature | Status | Notes |
|---|---|---|
| Macro recorder + replay | ✅ | `{{var}}` substitution, header / regex / JSON-path capture. See [macros.md](modules/macros.md). |
| Active-scan `replay_macro` + `replay_every_n_probes` | ✅ | See [login.md](login.md). |
| Match-and-Replace cookie / header injection | ✅ | Host-scoped. |
| Portable Firefox with locked-in proxy + trusted CA | ✅ | One-shot `reqlore browser`. |

## Auth (UI password gate)

| Feature | Status | Notes |
|---|---|---|
| Argon2id-hashed UI password | ✅ | Set via `reqlore init` or `/auth/set-password`. |
| `--no-password` opt-out | ✅ | Loopback-only assumption. |
| Reverse-proxy-friendly trust headers | ✅ | See [login.md](login.md). |

## Reporting

| Feature | Status | Notes |
|---|---|---|
| Markdown / HTML / DOCX export per finding | ✅ | See [reporter.md](modules/reporter.md). |
| Per-finding severity + CVSS band | ✅ | |
| Bundled request / response pairs | ✅ | |
| Optional `[report]` extra (`python-docx`) | ✅ | Markdown / HTML work without it. |

## Accessibility

| Feature | Status | Notes |
|---|---|---|
| WCAG 2.2 AA conformance | ✅ | See [ACCESSIBILITY.md](ACCESSIBILITY.md). |
| WCAG 2.1 AAA structural matrix | ✅ | `test_wcag_aaa.py` covers every blueprint route. |
| axe-core CI gate via Playwright | ✅ | Optional `[a11y]` extra. |
| Plain-language response summariser | ✅ | |
| Verbosity profiles (Concise / Standard / Verbose) | ✅ | Per-project. |
| Optional audio cues (off by default) | ✅ | In-process WAV generator; no external assets. |
| Keyboard-map self-test page | ✅ | `Alt+0` → [Help](modules/help.md). |
| Tabular "Read as list" alt-view | ✅ | |
| Copy as: curl / httpx / requests / raw / fetch + plugin handlers | ✅ | See [PLUGINS.md](PLUGINS.md). |
| Live regions for all status messages | ✅ | `role="status"` / `role="alert"` per phase. |
| Server-driven auto-refresh (no `setInterval`) | ✅ | `<meta http-equiv="refresh">` + `/results.json?since=N`. |
| Server-side find-in-body (no JS) | ✅ | History detail (one Find box across the merged request + response blob), Repeater response, Intercept detail, Scanner finding detail (one Find box across the merged evidence + payload blob), WebSocket transcript, Macros detail (JSON definition). See [ACCESSIBILITY.md § Find-in-body](ACCESSIBILITY.md#find-in-body-no-js-aaa-clean). |

## Out of scope

| Feature | Why |
|---|---|
| Cloud / SaaS deployment | Reqlore is local-only by design. |
| Native desktop GUI (Qt / GTK) | Web UI in the user's browser already inherits the OS a11y stack. |
| Replacing every Burp BApp | Plugin API ships; community covers the long tail. |
| Cert-pinning bypass | Out of scope (use a jailbroken device). |
| Built-in DNS exfiltration receiver | Use a dedicated interactsh client. |
