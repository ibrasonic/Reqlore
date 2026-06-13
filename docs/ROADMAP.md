# Reqlore — Roadmap

## Current status

**Phase 1 — Foundation:** ✅ complete (2026-06-07). 29/29 unit tests pass. All 6 blueprint routes serve 200.
**Phase 2 — Power-user core:** ✅ complete (2026-06-07). 70/70 unit tests pass. All 16 blueprint routes serve 200; live Intruder run against a local echo server returns 3/3 expected results.
**Phase 3 — Scanner foundation:** ✅ complete (2026-06-07). 115/115 unit tests pass. All 17 blueprint routes serve 200; `reqlore scan` + `reqlore report` CLI both work end-to-end.
**Phase 4 — Active scanner + specialised modules:** ✅ complete (2026-06-07). 148/148 unit tests pass. All 22 blueprint routes serve 200; 8 active checks pluggable with dependency-injection sender; 5 new workbenches (GraphQL, WebSocket, SAML, PoC, Macros) wired into the dashboard.
**Phase 5 — Advanced / power tools:** ✅ complete (2026-06-07). 215/215 unit tests pass. All 26 blueprint routes serve 200; `reqlore run` YAML/JSON job runner verified end-to-end (set → assert → scan → report).
**Phase 6 — Polish & integration:** ✅ complete (2026-06-07). 221/221 unit tests pass. Repeater UI now exposes H/3 + curl-cffi engines, History detail surfaces plugin `copy_as()` handlers, ActiveScanner ships an `oast-ssrf` check that auto-wires the running OAST receiver, an opt-in axe-core a11y smoke suite covers all 26 routes, and `scripts/release.ps1` produces wheel + sdist + SHA256SUMS.txt (verified locally).
**Phase 7 — Importers + miner + scheduler:** ✅ complete (2026-06-07). 240/240 unit tests pass. All 28 blueprint routes serve 200; HAR importer + CLI `reqlore import-har` verified end-to-end; Intruder gained the H/3 + curl-cffi engine picker; new `/param-miner` workbench fuzzes ~200 candidate parameter names with a built-in wordlist; new `/schedule` blueprint persists recurring passive scans (APScheduler optional via `[schedule]` extra, thread fallback otherwise); opt-in update-check exposed in `/settings`, off by default.
**Phase 8 — Portable Firefox launcher:** ✅ complete (2026-06-07). 258/258 unit tests pass. New `reqlore.browser` module + `reqlore browser` and `reqlore prefetch-firefox` CLI subcommands. First launch downloads the official Mozilla portable build (zip on Windows, tar.xz on Linux), SHA-256-verifies against `archive.mozilla.org/.../SHA256SUMS`, caches it under `~/.reqlore/firefox/<ver>/`, writes an enterprise `policies.json` (cert trust + locked proxy + telemetry/update lockdown), creates a dedicated profile, and spawns Firefox pointed at the Reqlore UI. Air-gapped flow: `--firefox-zip <path>` or run `prefetch-firefox` once and copy the cache. Also fixed a mitmproxy regression: `DumpMaster` is now constructed with an explicit `loop=` (Phase 7 had only created the loop, which made `mitmproxy 10+`'s `get_running_loop()` fail at startup).
**Phase 9 — Reliability, gap-closure, AAA polish:** ✅ complete (2026-06-09). **1368/1368 unit tests pass, 239 skipped** (skips gate optional extras: `[h3]`, `[impersonate]`, `[websocket]`, `[schedule]`, `[a11y]`). Three internal plans drove this phase: [RELIABILITY_PLAN.md](internal/RELIABILITY_PLAN.md) (component-health matrix, WCAG-AAA structural matrix, error-path coverage, long-session resilience), [SCANNER_GAP_PLAN.md](internal/SCANNER_GAP_PLAN.md) (16 active-scanner gaps closed — smuggling, sequencer auto-feed, forced-browsing, GraphQL batching, deserialisation, web-cache deception, resumable scans, plus the "Why not fired" coverage page), and [INTRUDER_ENHANCEMENTS.md](internal/INTRUDER_ENHANCEMENTS.md) (Phase 0 AAA template fixes + Phase 1 operator control — pause / resume / cancel / server-driven auto-refresh; Phases 2-4 results-triage and export still in progress).

Each phase ends in a tagged release with passing tests and an a11y audit.

---

## Phase 1 — Foundation ✅

End state: a usable proxy + history + repeater + decoder, with the full a11y
baseline in place so every later phase only needs to add Blueprints and
templates that follow the established patterns.

- [x] Repo skeleton, `pyproject.toml`, Apache 2.0 license
- [x] `reqlore.cli` entry point (`ui`, `proxy`, `init`, `both`)
- [x] `reqlore.config` + per-project SQLite settings
- [x] `reqlore.storage.Project` — schema, blob compression, thread-safe
- [x] `reqlore.engines` — Request/Response dataclasses, Timings
- [x] `reqlore.engines.httpx_engine`
- [x] `reqlore.engines.raw_engine`
- [x] `reqlore.engines.curl_render`
- [x] `reqlore.proxy.ca` — CA gen + cert export (cryptography lib)
- [x] `reqlore.proxy.mitm` — wraps mitmproxy DumpMaster in a thread
- [x] `reqlore.proxy.rules` — match rules
- [x] `reqlore.a11y` — contrast helpers, response summariser, copy-as renderers
- [x] `web/templates/base.html` — skip-link, live region, themes, verbosity
- [x] `web/static/reqlore.css` — accessible defaults, three themes
- [x] `web/static/reqlore.js` — progressive enhancement only
- [x] Blueprint: dashboard
- [x] Blueprint: proxy + intercept queue
- [x] Blueprint: history (list, detail, export jsonl, send-to-repeater)
- [x] Blueprint: repeater (engines, render-as, save-to-history, from-curl, from-history)
- [x] Blueprint: decoder (22 ops including smart-decode and JWT)
- [x] Blueprint: settings (theme, verbosity)
- [x] Blueprint: help (keyboard map, a11y, about)
- [x] Plain-language summariser
- [x] "Copy as ..." helpers (curl / httpx / requests / raw / fetch)
- [x] Unit tests for a11y + storage + engines + web smoke (29 tests)
- [x] README quickstart + 7 docs files

## Phase 2 — Power-user core ✅

- [x] Intruder (4 attack types, payload sources, processors, grep, sort)
- [x] Match & Replace engine (req/resp, header/body, literal+regex, host filter)
- [x] Comparer (line diff + plain-language summary + byte summary)
- [x] JWT workbench (decode, sign HS/RS/ES, alg=none, RS→HS key confusion, kid traversal)
- [x] Sitemap + scope rules (include/exclude, host/url targets)
- [x] HTTP history extended columns (auth/csrf/cors/csp/set-cookie/redirect flags)
- [x] Project-wide search (URL · request · response)
- [x] Audio cues (opt-in; in-process WAV generator; no external assets)
- [x] Synchronous intercept hold (forward / drop / forward-edited)
- [ ] axe-core a11y test via playwright (CI gate; deferred to Phase 3)

## Phase 3 — Scanner foundation ✅

- [x] Finding model (CWE / OWASP / CVSS band) — `reqlore.scanner.findings`
- [x] Passive scanner with 12 built-in rules — `reqlore.scanner.passive`
  - missing security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
  - no clickjacking defence (XFO / CSP frame-ancestors)
  - insecure cookies (Secure / HttpOnly / SameSite)
  - server / X-Powered-By version disclosure
  - dangerous CORS (`*` + credentials, reflected Origin + credentials)
  - verbose error pages (Python / Java / Spring / PHP / SQL traces)
  - directory listing exposure
  - sensitive paths (`/.git/`, `/.env`, `/wp-config.php`, …)
  - mixed content
  - JWT `alg=none` in either direction
  - open-redirect heuristic
  - HTTP Basic Auth over plain HTTP
- [x] Scanner UI: run, filter by severity / status / host, triage workflow (open → triaged → false_positive → fixed)
- [x] Reporter (Markdown / HTML / DOCX) — self-contained, no JS, semantic landmarks
- [x] Plugin API + loader — `reqlore.plugins`
  - drop-in `.py` files in `~/.reqlore/plugins/`
  - entry points: `PLUGIN_INFO`, `scanner_rules()`, optional `register(app)`
  - enable / disable / reload from the UI
  - optional watchdog-based hot reload
- [x] Plugins Settings UI
- [x] CLI: `reqlore scan` and `reqlore report`
- [x] 45 new tests (115 total)
- [x] axe-core a11y CI gate (carried over) — still queued, deferred to Phase 4

## Phase 4 — Active scanner + specialised modules ✅

- [x] Active scanner (`reqlore.scanner.active`) — 8 built-in checks:
  - `xss-reflected` (DOM-safe sentinel marker, query+form injection)
  - `sqli-error` (10 DB error signatures across MySQL/PG/MSSQL/Oracle/SQLite)
  - `open-redirect` (sentinel host in `Location` header)
  - `ssti` (Jinja / EL / ERB / Ruby probes, expects evaluated `49`)
  - `os-cmd-time` (5 s sleep payload above 0.7× baseline)
  - `jwt-alg-none` (re-sign header to `alg=none`, keep payload)
  - `prototype-pollution` (JSON body `__proto__` marker)
  - `graphql-introspection` (only on URLs containing `graphql` / `/gql`)
  - dependency-injection `sender=` kwarg so tests run fully offline
  - per-check try/except wraps a crashing check as info finding
- [x] Scanner UI: active-run tab with check toggles, max-req cap, rate delay, follow-redirects
- [x] GraphQL workbench (`reqlore.graphql` + `/graphql/`) — introspection, schema flatten, query runner
- [x] WebSocket workbench (`reqlore.websocket` + `/ws/`) — sync `websockets` client, transcript persistence via `project_state` KV
- [x] SAML inspector (`reqlore.saml` + `/saml/`) — POST/Redirect bindings (raw-DEFLATE via `-zlib.MAX_WBITS`), unsigned/weak-algo/missing-AudienceRestriction/missing-NotOnOrAfter audits
- [x] CSRF + Clickjacking PoC generator (`reqlore.poc` + `/poc/`) — form / fetch flavours, HTML-escaped lure overlay
- [x] Session-handling macros (`reqlore.macros` + `/macros/`) — `{{var}}` substitution, header/regex/JSON-path capture, persisted in `project_state`
- [x] 33 new tests (9 active scanner + 11 phase4 modules + 13 web smoke)
- [x] CLI unchanged — `reqlore scan` / `reqlore report` still work
- [x] All 148 tests pass; all 22 blueprint routes return 200

## Phase 5 — Advanced / power tools ✅

- [x] Sequencer (`reqlore.sequencer` + `/sequencer/`) — Shannon entropy per char + per token, per-position breakdown, Hamming distance over consecutive tokens, longest-run detection, weak-position flagging
- [x] OAST (`reqlore.oast` + `/oast/`) — local in-process HTTP callback receiver on `127.0.0.1:<random>`, per-token routing, in-memory ring of 5000 interactions, plus `interactsh_poll()` stub for opt-in remote polling
- [x] HTTP/2 frame tool (`reqlore.h2_tool` + `/h2/`) — parse hex → typed frames (DATA/HEADERS/SETTINGS/PING/GOAWAY/RST_STREAM/WINDOW_UPDATE/CONTINUATION/PRIORITY/PUSH_PROMISE), preface detection, frame builders for SETTINGS / PING / GOAWAY / RST_STREAM / WINDOW_UPDATE
- [x] HTTP/3 engine (`reqlore.engines.h3_engine`) — thin synchronous wrapper around `aioquic` (optional `[h3]` extra); availability flag + safe "install with pip install reqlore[h3]" fallback when missing
- [x] Request-smuggling helpers (`reqlore.smuggling` + `/smuggling/`) — CL.TE / TE.CL / TE.TE payload generators with downloadable bytes; timing-based detect helper using a sender callable
- [x] curl_cffi JA3/JA4 engine (`reqlore.engines.curl_cffi_engine`) — optional `[impersonate]` extra; supports `chrome120`/`chrome119`/`safari17_0`/`firefox109` etc.; safe error response when missing
- [x] CLI runner (`reqlore run jobs/job.yaml`) — YAML (optional `[yaml]` extra) or JSON; step types `request`, `scan`, `active`, `report`, `set`, `assert`, `sleep`; `{{var}}` substitution; header/JSON-path capture; `--strict` mode
- [x] Plugin SDK (`reqlore.plugins_sdk`) — `make_info`, `make_passive_rule`, `CopyAsHandler`, `assert_compatible`
- [x] Example plugin pack (`examples/plugins/`) — `extra_headers.py` (passive rule), `hello_blueprint.py` (Flask route), `copy_as_php.py` (CopyAsHandler)
- [x] 67 new tests (215 total)
- [x] All 26 blueprint routes return 200
- [x] `reqlore run` verified end-to-end (set → assert → scan → report → OK 158 ms)

## Phase 6 — Polish & integration ✅

- [x] Wire H/3 (`h3`) and curl-cffi (`curl-cffi:chrome120` / `safari17_0` / `firefox109`) engines into the Repeater UI; backend dispatches via `engine.split(":", 1)`
- [x] Surface `copy_as()` plugin handlers in the History detail page; new `/history/<id>/copy-as/<name>` route renders `text/plain; charset=utf-8`
- [x] OAST + Macros + Active scanner cross-flow: new `OASTSSRFCheck` (`reqlore.scanner.active.OASTSSRFCheck`) injects the running receiver's callback URL into every query/form parameter, polls the OAST log for ~600 ms, and escalates to a `CWE-918` high-severity finding when a hit is observed
  - opt-in: only runs when `ActiveOptions.oast` is set; the scanner blueprint auto-wires `current_app.extensions["reqlore_oast"]` when the receiver is running
  - `ActiveCheck.run` now optionally accepts an `opts=` kwarg; `ActiveScanner.run_on_row` introspects via `inspect.signature` to stay backward-compatible with the 8 legacy checks
- [x] axe-core a11y CI gate — `reqlore/tests/a11y/test_axe_smoke.py` boots the app via `wsgiref` and runs axe on all 26 routes; gated behind the new `[a11y]` extra (`playwright` + `axe-playwright-python`) so the default `pytest reqlore/tests/unit` run is unaffected
- [x] Release artefacts — `scripts/release.ps1` builds wheel + sdist via `python -m build`, writes `dist/SHA256SUMS.txt`; verified locally (199 KB wheel, 146 KB sdist)
- [x] 6 new tests (221 total); all 26 routes still serve 200; `/history/<id>/copy-as/<name>` returns 404 cleanly when no plugin is registered

## Phase 7 — Importers + miner + scheduler ✅

- [x] HAR 1.2 importer (`reqlore.har`) — stdlib-only parser; builds raw request/response bytes per entry; new CLI subcommand `reqlore import-har --project <p> <file.har>`; entries land with `engine="har"` and `flags="imported"`
- [x] Param-miner (`reqlore.param_miner` + `/param-miner/`) — baseline-vs-probe diffing with a curated 200-word built-in list; three locations (`query` / `body` / `header`); detection signals are reflected sentinel, status change, or body-length delta beyond a configurable tolerance; dependency-injection `send=` kwarg so tests stay offline
- [x] Intruder engine picker — extended `_send_factory` to dispatch to `h3` and `curl-cffi:<profile>` engines just like Repeater; `new.html` `<select>` now lists all 6 options
- [x] Scheduled passive scans (`reqlore.scheduler` + `/schedule/`) — persists jobs in `project_state["sched:jobs"]`; uses APScheduler when the new `[schedule]` extra is installed, otherwise a tiny thread-based loop; UI supports start/stop, add (with `interval_s ≥ 30` validation), remove, run-now
- [x] Opt-in update check (`reqlore.update_check`) — disabled by default; a single GET to a manifest URL only fires when the user clicks the new button in `/settings`; manifest format is `{latest_version, released, url}`; never auto-checks
- [x] 19 new tests (240 total); all 28 blueprint routes serve 200; CLI `reqlore import-har` verified end-to-end (1-entry HAR → 1 history row)

## Phase 8 — Portable Firefox launcher ✅

- [x] `reqlore.browser` module + `reqlore browser` / `reqlore prefetch-firefox` CLI subcommands
- [x] First launch fetches the official Mozilla portable build (`.zip` on Windows, `.tar.xz` on Linux) from `archive.mozilla.org/.../<ver>/<plat>/<lang>/`; SHA-256-verified against the official `SHA256SUMS`
- [x] Cache: `~/.local/share/reqlore/firefox/<ver>/` (POSIX) or `%APPDATA%\reqlore\firefox\<ver>\` (Windows)
- [x] Enterprise `policies.json` written into the bundle: installs the Reqlore CA, locks the proxy to `127.0.0.1:<port>`, disables telemetry / update / first-run handshakes
- [x] Dedicated profile under `~/.reqlore/firefox-profile/` seeded with `network.proxy.allow_hijacking_localhost=true`
- [x] Air-gapped flow: `--firefox-zip <path>` or run `prefetch-firefox` once and copy the cache
- [x] Linux runtime-dep auto-install via `ensure_linux_runtime()` (apt/dnf/pacman/zypper/apk); skip with `REQLORE_NO_AUTODEPS=1`
- [x] WSL detection + hand-off — proxy + CA wiring instructions printed for the Windows host
- [x] Mitmproxy regression fix: `DumpMaster` is now constructed with an explicit `loop=` (Phase 7 had only created the loop, which made `mitmproxy 10+`'s `get_running_loop()` fail at startup)
- [x] 18 new tests (258 total); all `test_phase8_browser.py` paths exercise offline fixtures via monkeypatch (no live network)

## Phase 9 — Reliability, gap-closure, AAA polish ✅

Tracked in three internal docs that drove this phase:
[RELIABILITY_PLAN.md](internal/RELIABILITY_PLAN.md),
[SCANNER_GAP_PLAN.md](internal/SCANNER_GAP_PLAN.md),
[INTRUDER_ENHANCEMENTS.md](internal/INTRUDER_ENHANCEMENTS.md).

Reliability matrix (sub-phases 1–4 in `test_reliability_phase{N}.py`):

- [x] **R1 — component health matrix**: module-import sweep across `reqlore.*`, blueprint reachability matrix from `app.url_map.iter_rules()`, CLI subcommand parse matrix from `build_parser()._SubParsersAction`, engine round-trip sanity (raw `_build_raw` / `_parse_response`, `httpx_engine.send` signature lock)
- [x] **R2 — WCAG 2.1 AAA structural matrix** (`test_wcag_aaa.py`): every rendered page audited for single `<h1>`, monotonic heading levels, `<main>` landmark, skip-link target, `<label for>` coverage, no `outline: none`, no `tabindex > 0`
- [x] **R3 — error-path coverage**: 401 / 403 / 404 / 500 / engine `Response(status=0, error=…)` paths exercised; user-visible message asserted; live region announcement asserted
- [x] **R4 — long-session resilience**: project-file growth caps, blob cache eviction, history pagination invariants

Scanner gap-closure (16 items from the 2026-06-09 audit, all `[x]` shipped):

- [x] Coverage page "Why not fired" reasons (`Project.rule_run_reasons()`)
- [x] HTTP smuggling as an active check (`HTTPSmugglingCheck`, opt-in via `ActiveOptions.allow_smuggling_probes`)
- [x] Sequencer auto-feed (session-cookie sampling → finding when entropy is `weak`)
- [x] Forced-browsing active check (small built-in wordlist with body fingerprints)
- [x] GraphQL beyond introspection (batching abuse, field-suggestion leak)
- [x] Deserialisation reflection (Java `rO0…`, .NET `AAEAAAD…`, PHP `O:`, Python pickle magic bytes)
- [x] Web-cache deception (`/x.css` / `/x.js` suffix probe)
- [x] Resumable scans (`test_resumable_scans_b5.py`); cancel mid-row leaves a recoverable checkpoint

Intruder enhancement plan (phases 0–6 shipped, three Phase-5 items deferred):

- [x] **P0** template AAA fixes — sort links toggle `desc`, long payload cells wrap in `<details>`, payload-set 2-4 visibility tied to attack type (server-rendered, no JS), detail page action buttons in a labelled `<nav>` toolbar, `role="status"` for last-known runner state
- [x] **P1** operator control — pause / resume POST routes + buttons + status update, `?auto=1` server-driven refresh (with stop toggle), `/<aid>/results.json?since=<seq>`, cancel event check before each network call
- [x] **P2** results triage — status-class filter, length-range filter, free-text contains, matched-only toggle, dedupe by `body_md5` (server-side, filter form on the detail page)
- [x] **P3** export — `/<aid>/export.csv` (9 cols) and `/<aid>/export.json` streaming endpoints; both honour the visible filter
- [x] **P4** payload richness — `ARG_PROCESSORS` (prefix / suffix / repeat), extra `PROCESSORS` (length / strip / b64dec / sql-quote), built-in `WORDLISTS` (common-passwords / usernames / LFI / XSS / SQLi / subdomains), `load_wordlist_file()` with 5 MB / 100 k-line caps
- [x] **P5** scale — `AttackOptions.retries` + `_send_with_retries` exponential back-off, `stop_on_match` / `stop_on_status` cancel logic, `runner.total_jobs` powers a `<progress>` bar in the detail view
- [x] **P6** headless CLI + tests — `reqlore intruder {run,list,show,export}` subcommands wired via `intruder_spec.py`; YAML / JSON spec files with payload sources resolved relative to the spec dir; `--dry-run` reports planned request count without sending
- [ ] **Deferred** (Phase 5 items 6 / 7 / 9): streaming scheduler with bounded inflight `Semaphore`, per-position payload-set assignment for Sniper, preamble macro that runs a Macro once and exposes captures as `${var}` in the template. The current `ThreadPoolExecutor` design meets today's targets; revisit if attack sizes grow into the hundreds of thousands of requests.

Phase totals: **884 → 1368 passing, 239 skipped**. All routes still serve 200; all CLI subcommands still respond to `--help` with exit code 0.
