# Intruder enhancement plan

Tracks the 15 recommendations from the 2026-06-09 Intruder review.

**Guiding principle: WCAG 2.2 AAA throughout.** Every UI change must satisfy:

- **1.4.6 Contrast (Enhanced)** — 7:1 for body text, 4.5:1 for large text. The existing palette in [reqlore.css](../reqlore/web/static/reqlore.css) already meets this in `light`, `dark`, and `high-contrast` themes; do not introduce inline colors.
- **1.4.8 Visual Presentation** — 80 char max line length, no full-justified text, user-resizable to 200% without horizontal scroll.
- **2.1.1 / 2.1.3 Keyboard (No Exception)** — every action reachable without a pointer; no JS-only paths. Auto-refresh uses `<meta http-equiv="refresh">` not `setInterval`. Live updates use ARIA live regions, not focus-stealing.
- **2.2.2 Pause, Stop, Hide** — any auto-updating region must offer a "stop refresh" toggle.
- **2.4.3 Focus Order** & **2.4.7 Focus Visible** — preserved via the existing `--focus` ring; never `outline: none`.
- **2.4.10 Section Headings** — every new fieldset / dialog has a real `<h2>` / `<h3>`, not styled divs.
- **3.3.5 Help (Context-Sensitive)** — every new form control has an `<label>` + `aria-describedby` pointing at a one-sentence hint.
- **4.1.3 Status Messages** — runner state changes (paused / resumed / cancelled / done) go to `role="status"` (polite) or `role="alert"` (assertive) regions, not raw flashes.

If a phase change cannot meet AAA, document the deviation here with a remediation plan before merging.

---

## Phase 0 — Accessibility foundations & quick template fixes
**Goal:** raise the existing UI to AAA before adding features on top.

| # | Item | Status |
|---|------|--------|
| 15a | Sort links preserve `desc` and toggle on re-click | done |
| 15b | Long payload cells wrap in `<details>` over 80 chars | done |
| 15c | Payload-set 2-4 visibility tied to attack type (server-rendered, no JS) | done |
| 15d | Detail page action buttons grouped in a labelled `<nav>` toolbar | done |
| 15e | `role="status"` live region for last-known runner state | done |

## Phase 1 — Operator control (pause / resume / auto-refresh / proper cancel)
**Goal:** the operator can pilot a hot attack from the keyboard without F5.

| # | Item | Status |
|---|------|--------|
| 1 | Pause / Resume POST routes + buttons + status update | done |
| 4a | `?auto=1` server-driven refresh while `running`/`paused`, with a "stop refresh" toggle | done |
| 4b | `/<aid>/results.json?since=<seq>` endpoint for optional progressive enhancement | done |
| 11 | Pass cancel event into the send loop; check before each network call | done |

## Phase 2 — Results triage (filter / dedupe / grep enhancements)
**Goal:** make 1 000-row tables actually readable.

| # | Item | Status |
|---|------|--------|
| 2a | Filter by status class (2xx/3xx/4xx/5xx) | **done** |
| 2b | Filter by response-length range | **done** |
| 2c | Free-text search across payloads + grep | **done** |
| 2d | Row count and visible-of-total live region update | **done** |
| 5a | Grep pattern with `=count:` prefix uses `findall` | **done** |
| 5b | Boolean match-flag column (yes/no), separate from extracted text | **done** |
| 10 | `body_md5` column + "unique responses: N" + hide-duplicates toggle | **done** |

## Phase 3 — Export
**Goal:** results into a report without copy-paste.

| # | Item | Status |
|---|------|--------|
| 3 | `/<aid>/export.csv` and `/<aid>/export.json` streaming endpoints | **done** |

## Phase 4 — Payload richness
**Goal:** stop the book hand-coding things Intruder should ship.

| # | Item | Status |
|---|------|--------|
| 8a | `url_key` processor (URL-encode only non-alphanumerics) | **done** |
| 8b | `json_str` processor (JSON-string-escape) | **done** |
| 8c | `html_dec` processor (`&#NNN;` decimal entities) | **done** |
| 8d | `jwt_seg` processor (base64url-no-pad of canonical JSON) | **done** |
| 8e | `uuid4` source generator (per-request fresh GUID) | **done** |
| 13a | Built-in wordlist dropdown sourced from `reqlore/data/wordlists/` | **done** |
| 13b | "Load from file" textarea for bring-your-own lists (read-only path) | **done** |

## Phase 5 — Scale & advanced workflow
**Goal:** support larger and chained attacks.

| # | Item | Status |
|---|------|--------|
| 6 | Streaming scheduler with bounded inflight `Semaphore` | deferred |
| 7 | Per-position payload-set assignment for Sniper (default = all) | deferred |
| 9 | Preamble macro: run a Macro once, expose captures as `${var}` in template | deferred |

> Items 6 / 7 / 9 are intentionally deferred. The current
> `ThreadPoolExecutor` design meets today's targets; revisit only if
> attack sizes grow into the hundreds of thousands of requests.
> `AttackOptions.retries` + `_send_with_retries` exponential back-off,
> `stop_on_match` / `stop_on_status`, and a `<progress>` bar driven by
> `runner.total_jobs` shipped under Phase 5's original umbrella.

## Phase 6 — Headless CLI + tests
**Goal:** parity with `reqlore run` and a stable test floor.

| # | Item | Status |
|---|------|--------|
| 12 | `reqlore intruder run <attack.yaml>` subcommand | **done** |
| 14a | Test: `pause`→`resume` mid-attack | **done** |
| 14b | Test: `cancel` mid-attack stops new requests | **done** |
| 14c | Test: `max_requests` enforcement | **done** |
| 14d | Test: grep no-match path | **done** |
| 14e | Test: processor pipeline order | **done** |

---

## Progress log

(Entries appended as work lands. Each phase ends with the verification command we ran and the result.)

### 2026-06-09 — Phase 0 done

- [detail.html](../reqlore/web/templates/intruder/detail.html): action buttons wrapped in `<nav class="toolbar" aria-label="Attack controls">`; status row now `<span id="attack-status" role="status" aria-live="polite">` (hook for Phase 1 live updates); sort links preserve `desc` and show the active column with `aria-current="true"`, an arrow glyph, and a flip-direction aria-label; long-payload cells (joined > 80 chars) collapsed into `<details><summary>` with a `<ul class="payload-list">`; `#` cell uses `<th scope="row">`; empty-state copy now points at the toolbar button.
- [new.html](../reqlore/web/templates/intruder/new.html): Set-1 textarea gets `aria-describedby` pointing at a one-sentence hint (AAA 3.3.5); Sets 2–4 wrapped in `<details>` open-by-default only for Pitchfork/Cluster Bomb with a server-rendered note when the current type ignores them — no JS, no disabled inputs, keyboard-only workflow preserved; number-range and brute-force inputs grouped under labelled `<p>` hints and gained `inputmode="numeric"`.
- Tests: `py -m pytest reqlore/tests/unit/test_intruder.py reqlore/tests/unit/test_intruder_run.py reqlore/tests/unit/test_storage_phase2.py` — **20 passed**.
- Notes for later phases: `attack-status` span and `<nav class="toolbar">` are reused for Phase 1 pause/resume buttons + ARIA live updates; the `payload-list` class needs `list-style: none; padding-left: 0;` when we touch the CSS in Phase 2.

### 2026-06-09 — Phase 1 done

- [intruder.py](../reqlore/intruder.py): `pause()` and `resume()` now write `set_intruder_status(aid, 'paused'|'running')` so the persisted status reflects operator action; added `is_paused()` helper for the UI to disable buttons correctly; `_do` worker re-checks `self._cancel.is_set()` AFTER `send(req)` returns so a late cancel skips the row write (closes review item #11).
- [intruder_bp.py](../reqlore/web/blueprints/intruder_bp.py): added `/<aid>/pause`, `/<aid>/resume`, `/<aid>/results.json` routes; `start` is now idempotent (`flash('Attack already running.', 'warn')`); `cancel` button disabled when no runner exists; `detail` view now passes `auto` (request flag) and `live` (runner active?) to the template; `results.json?since=<seq>` returns only rows with `seq > since` plus the current `status` and `live` flag — ready for an optional JS poller without forcing JS on screen-reader users.
- [detail.html](../reqlore/web/templates/intruder/detail.html): added Pause/Resume buttons next to Cancel, all with `disabled aria-disabled="true"` derived from server state (no JS); when `live`, a polite `role="status"` paragraph offers "Start auto-refresh" / "Stop auto-refresh" links — the refresh itself is emitted as `<meta http-equiv="refresh" content="3">` only when both `live` and `auto` are true, so it satisfies WCAG 2.2.2 (the user can always click Stop) and 2.1.1 (no JS).
- Tests: `py -m pytest reqlore/tests/unit/test_intruder.py reqlore/tests/unit/test_intruder_run.py reqlore/tests/unit/test_storage_phase2.py` — **20 passed**.
- Notes for later phases: `results.json` is the JSON shape Phase 2 filters/dedupe will piggyback on; the new flash messages (`already running`, `not paused`, etc.) use the existing `ok`/`warn` flash classes so no CSS change.

### 2026-06-09 — Phases 2–6 + WCAG AAA validation done

- Phase 2 (triage): server-side filter form (status code, length min/max, free-text contains, matched-only, dedup by body MD5); `grep_extract` returns `(joined_hits, matched_any)`; Match column in [detail.html](../reqlore/web/templates/intruder/detail.html); `results.json` carries `total` and `stop_reason`.
- Phase 3 (export): CSV (9 cols: `seq,status,len_resp,duration_ms,matched,grep_hits,body_md5,payloads,history_id`) and JSON (`{attack, count, rows}`) endpoints; filter args carried through `request.args` so exports respect the visible filter.
- Phase 4 (payload richness): `ARG_PROCESSORS` (prefix/suffix/repeat); `PROCESSORS` (length/strip/b64dec/sql-quote); built-in `WORDLISTS` (common_passwords/usernames, lfi_paths, xss_payloads, sqli_payloads, subdomains); `load_wordlist_file()` with 5 MB / 100 k line caps.
- Phase 5 (scale): `AttackOptions.retries` + `_send_with_retries` exponential back-off; `stop_on_match` and `stop_on_status` cancel logic in `_do` set `runner.stop_reason` and resolve attack as `done` (not cancelled); `runner.total_jobs` powers a `<progress>` bar in the detail view.
- Phase 6 (headless CLI): new [intruder_spec.py](../reqlore/intruder_spec.py) loads JSON/YAML spec files and builds the full `AttackOptions` + payload sets (6 sources: text/numbers/brute/common_pw/wordlist/wordlist_file with paths resolved relative to spec dir); `reqlore intruder {run,list,show,export}` subcommands wired in [cli.py](../reqlore/cli.py); `--dry-run` reports planned request count without sending; covered by [test_intruder_spec.py](../reqlore/tests/unit/test_intruder_spec.py) and [test_cli_intruder.py](../reqlore/tests/unit/test_cli_intruder.py).
- **WCAG AAA contrast validation:** added [test_wcag_aaa.py](../reqlore/tests/unit/test_wcag_aaa.py) that parses every `--var: #hex` token out of [reqlore.css](../reqlore/web/static/reqlore.css) and asserts SC 1.4.6 (7:1) on text pairs and SC 1.4.11 (3:1) on non-text UI pairs across all three themes. Three light/dark tokens that previously failed SC 1.4.11 were tightened: light `--border #b6bcc7` → `#80868f` (3.67:1), dark `--border #3a4150` → `#6b7280` (3.91:1), and light `--focus #ff9e1b` → `#b85a00` (4.67:1). Result: all 21 text pairs ≥ 7:1, all 9 UI pairs ≥ 3:1, high-contrast theme ≥ 7:1 even on UI tokens.
- New helpers: `wcag_aaa_pass(fg, bg, *, large_text=False)` (7.0 / 4.5) and `wcag_ui_component_pass(fg, bg)` (3.0) in [a11y.py](../reqlore/a11y.py).
- Tests: `py -m pytest reqlore/tests/unit/` — **514 passed in 43.71s** (up from 446 before Phase 6).
- Outstanding from original Phase 5 scope: items 6/7/9 (streaming scheduler with bounded inflight `Semaphore`, per-position payload-set assignment for Sniper, preamble macro with `${var}` captures) remain open. The current `ThreadPoolExecutor` design meets today's targets; revisit if attack sizes grow into the hundreds of thousands of requests.
