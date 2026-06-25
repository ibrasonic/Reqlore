# Auth Matrix — `/auth-matrix/`

Auth Matrix is Reqlore's structured access-control tester. It is the
same category of tool as the Burp extensions **Autorize** and
**AuthMatrix** rolled into one: a session-aware replay engine that
takes any request you've already captured, re-sends it under every
saved identity (admin, low-privilege user, anon, …), diffs the
normalised responses, and tells you which session got something it
should not have.

Two modes ship in the same release and share the same scoring
pipeline, so a finding from one mode is reproducible by the other:

- **Active** — operator-driven, one-shot. Pick a slice of history rows,
  pick a baseline session and one or more compare sessions, press
  **Start**. Useful for focused audits and reproduction.
- **Passive shadow** — background, fire-and-forget. Every response the
  proxy records is silently replayed under every *active* saved
  session. Useful for "just browse the app and let it scream" coverage.

Saved sessions are encrypted at rest with ChaCha20-Poly1305 keyed per
project (see [Storage footprint](#storage-footprint) below). They
never leave the project and are never logged in plaintext.

## Where it is

- **URL:** `/auth-matrix/`
- **Nav:** *Auth Matrix* in the top bar (with a badge showing the
  current Auth Matrix findings count). **No accesskey** — all
  `Alt`+`0` to `Alt`+`9` were already taken when the module shipped.
- **Send-to slug:** `auth-matrix` — appears as *"Send to → Auth
  Matrix"* in the History and Proxy intercept row-actions menus.

## Quick start — find your first bypass in five steps

1. Start Reqlore, open a project, start the proxy, point a browser
   at it: `reqlore both --project lab.rlr`.
2. Log in as your privileged user (e.g. admin) and click around the
   pages you care about. Each request lands in History.
3. Open **Auth Matrix → Sessions → New session**. Name it `admin`,
   leave kind on `cookie`, paste the cookie value (or use *Send to
   Auth Matrix* from a History row, then *Save its credentials as a
   new session* — Reqlore auto-detects `bearer` vs `cookie` vs
   `anon`). Save. Repeat for a second identity (`user` or `anon`).
4. Open **Auth Matrix → Shadow worker**, press **Start shadow
   worker**. The worker now replays every recorded response under
   every active session in the background. The toggle persists, so
   it auto-resumes next time you open the project.
5. Browse the app as admin. Come back to **Auth Matrix → Recent
   runs**, open the shadow run, and look for cells flagged
   `bypass-suspect` (red) or `denied-status-only` (amber). Click any
   cell for the side-by-side response diff.

Prefer a one-shot scan instead? Skip step 4 and use
**Auth Matrix → Runs → New active run…** to replay a known list of
history-row ids against your saved sessions.

## The interface

### `/auth-matrix/` — landing page

| Section | What it shows |
|---|---|
| **Quick actions** | Link to Sessions (with `N saved / M active`), *New active run…* button, link to the Shadow worker page with live `running / stopped`, processed count, findings count. |
| **Recent runs** | Table: `#` (link to detail), *Mode* (`active` / `shadow`), *Label*, *Status* (`pending` / `running` / `ok` / `error` / `cancelled` / `timeout`), *Progress* (done / total), *Bypass-suspect* count. |

### `/auth-matrix/sessions/` — session list

| Column | Notes |
|---|---|
| `#` | Session id, scope=row. |
| *Name* | The unique name you gave it (max 80 chars). |
| *Kind* | `cookie` / `bearer` / `header` / `multi` / `anon` (see below). |
| *Source* | `manual`, `history`, or `macro:<name>`. |
| *Active* | yes / no — only **active** sessions are used by shadow mode. |
| *Last used* | Auto-updated whenever a runner replays under this session. |
| *Actions* | *Edit*, *Activate / Deactivate* toggle, *Delete* (confirm). |

### `/auth-matrix/sessions/new` — create a session

| Field | Effect |
|---|---|
| **Name** | Required, unique within the project. |
| **Kind** | `cookie` (whole Cookie header), `bearer` (`Authorization: Bearer …`), `header` (single `Name: Value`), `multi` (one `Name: Value` per line), `anon` (strip all auth headers). When seeded from history, auto-selected via [`capture_session_from_history()`](../../reqlore/auth_matrix/sessions.py). |
| **Payload** | The credential material itself. For `cookie`, the full cookie string; for `bearer`, just the token (a leading `Bearer ` is stripped); for `header` / `multi`, one or more `Name: Value` lines; for `anon`, ignored. Stored ChaCha20-Poly1305-encrypted. |

When the form is opened with `?from_history=<hid>` (via *Send to →
Auth Matrix → Save its credentials as a new session*) it pre-fills
*Kind* and *Payload* from the captured request.

### `/auth-matrix/runs/new` — start an active run

| Field | Effect |
|---|---|
| **History rows** | Comma- or space-separated history ids, required. Pre-filled when seeded from a History row. |
| **Baseline session** | *Optional.* If chosen, baseline responses are obtained by replaying each history row under this session first. If left blank, the response captured originally in History is used as the baseline. |
| **Compare sessions** | Checkboxes, at least one required. Each ticked session contributes one column of the matrix. |
| **Label** | Free text; shows on the runs list. |
| **Similarity floor** | Integer 0–100, default `80`. Lower bound for "bodies are similar enough". Affects `denied-correctly` vs `denied-status-only`. |
| **Privileged floor** | Integer 0–100, default `90`. Lower bound for "bodies are basically the same". Required to fire `bypass-suspect`. |
| **Record findings** | Checked by default — writes a row to the project's *Issues* table for every cell whose verdict is in `("bypass-suspect", "denied-status-only")`. |
| **Verify TLS** | Off by default — turn on for production targets. |
| **Follow redirects** | Off by default — most auth-bypass tests want the raw 302 to remain visible. |

### `/auth-matrix/runs/<id>/` — live matrix view

Header dl shows *Label*, *Status*, *Progress* (with a `<progress>`
bar and a live-updated `aria-live=polite` status line), optional
*Error* banner. *Verdict counts* renders all eight labels with live
counts. Below: the matrix itself — one row per history id, one
column per compare session, each cell rendering `{verdict}
({status})` and coloured by verdict class. Click any cell to open
the detail page. **Stop run** button appears while the run is
`pending` or `running`.

The page polls `/auth-matrix/runs/<id>/poll` every ~1.2 seconds.
Once `is_running` flips to false, it reloads once to pick up the
final layout (cells that arrived after the last DOM render).

### `/auth-matrix/runs/<id>/cell/<cid>/` — cell detail

| Section | Contents |
|---|---|
| **Metadata** | History row link, session (name + kind), status (candidate, baseline in parens), similarity %, body length, duration ms, optional error, optional Finding link. |
| **Replayed request** | `<pre>` of the request sent under this session (after substitution). |
| **Responses** | Two-column side-by-side: *Baseline* `<pre>` and *Candidate* `<pre>`. |

*Dismiss (mark false-positive)* button appears unless the verdict
is already `dismissed`.

### `/auth-matrix/shadow/` — shadow worker status

| Field | Notes |
|---|---|
| **Alive** | yes / no. |
| **Queue depth** | Current backlog. |
| **Enqueued / Processed / Dropped** | Lifetime counters since the worker last started. *Dropped* counts hids the queue could not accept because it was full (max 256). |
| **Findings added** | Issues table rows the worker has appended this session. |
| **Skipped (out of scope)** | Hids skipped because the host was not in the project's *include scope*. |
| **Errors** | Lifetime exception count; last message + timestamp shown alongside. |
| **Shadow run** | Link to the long-running `mode=shadow` run that owns the cells. |
| **Verdict counts** | All 8 labels with their cell counts (or *None yet.*). |
| **Start / Stop button** | POSTs to `/auth-matrix/shadow/toggle` with `action=start` or `action=stop`. The action persists to `project_state["auth_matrix:shadow_enabled"]` so the worker auto-resumes on next app boot. |

### `/auth-matrix/from-history/<hid>` — send-to entry point

Renders the request's method, URL, host, and status, then two
buttons: *Save its credentials as a new session* (→ sessions_new
seeded) and *Start a new active run with this request* (→ runs_new
with the hid pre-filled).

## Routes

| URL | Method | What it does |
|---|---|---|
| `/auth-matrix/` | GET | Landing: quick actions, recent runs, shadow status. |
| `/auth-matrix/sessions/` | GET | Session list with toggle / edit / delete actions. |
| `/auth-matrix/sessions/new` | GET / POST | Create session (optionally seeded from a History row via `?from_history=<hid>`). |
| `/auth-matrix/sessions/<int:sid>/edit` | GET / POST | Edit name, kind, payload. |
| `/auth-matrix/sessions/<int:sid>/toggle` | POST | Flip `active` flag. |
| `/auth-matrix/sessions/<int:sid>/delete` | POST | Remove a session. |
| `/auth-matrix/runs/` | GET | Runs index (last 200). |
| `/auth-matrix/runs/new` | GET / POST | Active-run wizard. |
| `/auth-matrix/runs/<int:rid>/` | GET | Live matrix view with embedded polling. |
| `/auth-matrix/runs/<int:rid>/poll` | GET | JSON poll endpoint: `{status, progress_done, progress_total, progress_msg, error, verdict_counts, is_running}`. |
| `/auth-matrix/runs/<int:rid>/stop` | POST | Cooperative cancel via `threading.Event`. |
| `/auth-matrix/runs/<int:rid>/delete` | POST | Delete run and all its cells (cascade). |
| `/auth-matrix/runs/<int:rid>/cell/<int:cid>/` | GET | Side-by-side cell detail. |
| `/auth-matrix/runs/<int:rid>/cell/<int:cid>/dismiss` | POST | Set cell verdict to `dismissed`. |
| `/auth-matrix/shadow/` | GET | Shadow worker status + Start/Stop. |
| `/auth-matrix/shadow/toggle` | POST | `action=start` / `action=stop`; persists to `project_state`. |
| `/auth-matrix/from-history/<int:hid>` | GET / POST | Send-to entry: save-session or new-run. |

## Session kinds

| Kind | Payload format | What `apply_session_to_request` does |
|---|---|---|
| `cookie` | Whole cookie string, e.g. `session=abc; XSRF=xyz`. | Replaces (or appends) the `Cookie` header. |
| `bearer` | Raw token; leading `Bearer ` is tolerated and stripped. | Sets `Authorization: Bearer <token>`. |
| `header` | One `Name: Value` line. | Sets that single named header. |
| `multi` | Multiple `Name: Value` lines, one per line. | Sets every named header; blanks and `#`-comments are ignored. |
| `anon` | Empty. | Strips every entry in `_AUTH_HEADERS_STRIP`: `Cookie`, `Authorization`, `Proxy-Authorization`, `X-API-Key`, `X-Auth-Token`, `X-Access-Token`, `X-CSRF-Token`, `X-XSRF-Token`. |

For every non-`anon` kind, `apply_session_to_request` also strips
the default-auth headers *unless* the session's substitution
provides them — preventing a leftover `Authorization` from silently
keeping the operator logged in after a `cookie` swap.

`capture_session_from_history` auto-detects kind in this order:
`Bearer ` → `bearer`; other `Authorization:` → `header`;
`Cookie:` → `cookie`; nothing → `anon`.

## Verdict labels

| Label | Severity | When it fires |
|---|---|---|
| `bypass-suspect` | **high** | Baseline status ∈ `{200,201,202,204,206,207,208}` **and** candidate status ∈ same set **and** body similarity ≥ `privileged_floor` (default 90 %). The big one — look at these first. |
| `denied-status-only` | **medium** | Baseline privileged, candidate denied (`401/403/407/451` or a 3xx that looks like a login redirect), **and** body similarity ≥ `similarity_floor` (default 80 %). The status says "no" but the body still resembles the privileged page — soft-deny patterns. |
| `denied-correctly` | info | Baseline privileged, candidate denied, body dissimilar. Good outcome. |
| `different-payload` | info | Same family of status but bodies diverge beyond the floors. Usually fine; sometimes interesting. |
| `identical` | info | Same status, similarity ≥ 95 %. Includes the self-baseline tautology. |
| `no-baseline` | info | Could not read the baseline response (history row missing it). |
| `error` | info | Replay raised (timeout, transport, malformed). Check the cell's *Error* field. |
| `dismissed` | info | Operator marked the cell a false positive. Not produced by runners. |

The exact heuristic lives in [`decide_verdict()`](../../reqlore/auth_matrix/verdict.py)
and the severity mapping in `finding_severity_for_verdict()`.

### The self-baseline guard

Replaying an admin-authenticated request under the admin session is
a tautology — the response will be identical and the heuristic
would call it `bypass-suspect` on every page. To prevent that, both
the runner and the shadow worker check two conditions before
replaying:

1. **`Session.source_hid == history_id`** — the session was
   captured from this exact row.
2. **`session_already_present(session, raw_req)`** — the request
   blob already carries this session's auth markers (per-kind
   substring / equality checks).

If either holds, the cell is written as `identical` without a
network round-trip. This is why a shadow run over an admin browsing
session produces zero false positives against `admin` itself.

## How it integrates

- **Proxy.** The shadow worker is wired into the mitm history addon
  in [reqlore/proxy/mitm.py](../../reqlore/proxy/mitm.py). Every
  recorded response calls `Proxy.auth_matrix_shadow.enqueue(hid)`
  inside a try/except — a broken worker can never stall the proxy
  event loop. The plumbing mirrors the existing live-scanner worker.
- **History.** Each row's actions menu offers *Send to → Auth
  Matrix* via the standard slug dispatcher in
  [reqlore/web/blueprints/history.py](../../reqlore/web/blueprints/history.py).
- **Proxy intercept.** Same *Send to → Auth Matrix* entry is also
  available on the intercept page
  ([reqlore/web/blueprints/proxy_bp.py](../../reqlore/web/blueprints/proxy_bp.py)).
- **Scanner / Issues.** Cells with verdict `bypass-suspect` (high)
  or `denied-status-only` (medium) are written to the main issues
  table with `source` starting `auth_matrix:` and a stable dedupe
  key `auth_matrix[:shadow]:<verdict>:<hid>:<sid>`. They show up in
  the main findings count and in [Reporter](reporter.md) output
  without extra work.
- **Macros.** Sessions captured from a macro carry
  `source = "macro:<name>"` so you can tell where they came from.
- **Scope.** The shadow worker honours the project's *include
  scope* via `project.list_scope()`, refreshed every 5 seconds.
  Out-of-scope hids are silently skipped (counted as *Skipped*).

## Engines

The replay path delegates to Reqlore's standard sender selected by
`RunOptions.engine` (default `httpx`). All six request engines work
in principle, but the active runner is built around the assumption
that the sender is the synchronous `httpx` engine in the
foreground — heavy reliance on per-host rate limiting, retries, or
HTTP/3-specific quirks is not currently exercised.

## Keyboard map

Globals (Reqlore web UI):

- *Auth Matrix nav entry has no accesskey* — all `Alt`+`0` to
  `Alt`+`9` were assigned before Phase 17 shipped. Reach it via the
  top-nav link or `Alt`+`Shift`+`T` then *Tab* until *Auth Matrix*
  is focused. See [KEYBINDINGS.md](../KEYBINDINGS.md).
- *Send to → Auth Matrix* accesskey is `a` inside the row-actions
  menu (registered in [`reqlore/web/send_targets.py`](../../reqlore/web/send_targets.py)).

Within an Auth Matrix page, `Tab` order is skip-link → top nav →
heading → action buttons → form / table. There are no focus traps
and no custom widgets.

## Accessibility notes

- All matrix and list tables are real `<table>` with `<th
  scope="col">` / `<th scope="row">` and a heading immediately
  above; screen readers announce row + column on navigation.
- Verdicts are conveyed with **both** the verdict label text and a
  background colour class (`cell-bypass-suspect`, `cell-denied-…`,
  …) — never colour alone.
- The live run page exposes a single `role="progressbar"` element
  plus a polite `aria-live` status line that announces the run's
  progress message; counters update via id-targeted DOM swaps so
  the live region only fires on the message line, not on every
  count change.
- Session-payload textareas use `autocomplete="off"` and never echo
  the plaintext into any flash or log line — the payload is
  encrypted before being written to disk and decrypted only at
  use time.
- Every confirm-required action (delete session, delete run, stop
  run) uses a `<button type=submit>` with visible text inside a
  `<form method=post>`; no JavaScript confirm dialogs to trap focus.
- Status colours on the runs index pass AAA contrast on both light
  and dark themes; the same is true for the eight verdict cell
  classes.

## Recipes

### 1. Find your first bypass in a known-admin session

1. Browse a few admin pages through the Reqlore proxy.
2. Open the History row for `GET /admin/users`. Click *Send to →
   Auth Matrix → Save its credentials as a new session*. Call it
   `admin`. Save.
3. From the same row, click *Send to → Auth Matrix → Start a new
   active run with this request*. In the wizard, leave **Baseline
   session** blank (the captured admin response is the baseline),
   tick `anon` as the compare session (create it first if needed —
   kind `anon`, payload empty), press **Start run**.
4. The run finishes in seconds. A cell flagged `denied-correctly`
   means the app rejected anon properly. `bypass-suspect` means
   anon got the admin page — that's your finding.

### 2. Passive shadow over a browsing session

1. Capture two sessions: `admin` and `user`. Mark both *active*.
2. **Auth Matrix → Shadow worker → Start shadow worker**.
3. Browse the target as admin for 10–30 minutes — every page, every
   admin-only API endpoint, every form submission.
4. Return to **Recent runs** → the shadow run. Filter for
   `bypass-suspect` and `denied-status-only`. Click any flagged
   cell, review the side-by-side diff, dismiss false positives.
5. Stop the shadow worker when you're done; the toggle is
   remembered so re-opening the project resumes where you left off.

### 3. Compare three identities against a fixed slice

1. Sessions: `admin`, `viewer`, `anon` (all active).
2. **Runs → New active run…**
3. **History rows:** paste a comma-separated list of hids covering
   your admin journey (or a single range like `127, 128, 129, 130`).
4. **Baseline session:** `admin`. **Compare sessions:** tick
   `viewer` and `anon`.
5. **Privileged floor:** `90`. **Similarity floor:** `80`. **Record
   findings:** on. Start.
6. The matrix renders one row per history id, two columns
   (`viewer`, `anon`). Anything red in the `anon` column on an
   `/admin/...` path is the lead.

### 4. Reproduce a shadow finding via an active run

1. In the shadow run, copy the cell's `history_id` and `session_id`
   from the URL.
2. **Runs → New active run…**, paste the hid into **History rows**,
   set **Baseline session** to whatever the shadow run used (the
   captured response is fine for shadow), tick the same compare
   session, leave the floors at default.
3. Start. The new active run will write a single cell with the same
   verdict and identical similarity score — guaranteeing the
   shadow result is reproducible and not a flake.

### 5. Dismiss a false positive

1. On the cell detail page, eyeball the side-by-side diff.
2. If the "bypass" is a public page that just happens to look the
   same to both sessions, click **Dismiss (mark false-positive)**.
   The cell verdict becomes `dismissed` and it is excluded from
   future stats. A related Issues-table row, if any, is **not**
   automatically deleted — close it from the *Issues* page.

### 6. Tighten or loosen the heuristic

- Pages that legitimately render the same content to many users
  (status pages, marketing copy) generate `bypass-suspect` noise.
  Re-run with `privileged_floor=95` or `97` to require near-
  identical bodies before flagging.
- Apps that return very small responses (`{}` or `OK`) score 100 %
  similarity on every cell. Restrict the run to interesting hids
  (POSTs that change state, GETs that return PII) instead of
  scanning the whole journey.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Shadow worker is on but no cells appear. | All requests skipped by scope. | Open **Shadow worker** and check *Skipped (out of scope)*. If it equals *Enqueued*, broaden the project's *include scope* under **Settings → Scope**, or set it empty. |
| Shadow worker is on, *Processed* > 0, but every cell is `identical`. | All active sessions are self-baselines for the rows being captured (you only have one identity active). | Add a second session and mark it active. The whole point of the matrix is the cross-product. |
| Bypass-suspect everywhere. | Baseline session is in the compare list, or `privileged_floor` is too permissive. | Don't include the baseline in compare. Bump `privileged_floor` to 95+. |
| Run stops at *timeout* after exactly 10 minutes. | Hit the default watchdog (`RunOptions.timeout_s = 600.0`). | Split the run into smaller batches, or set `inter_request_sleep_s=0` if you'd previously bumped it. The cap is enforced; cells written so far are preserved. |
| Cell shows `error` verdict, blank Error field. | The truncated error string is shown in the run's *log* tail at the bottom of the run-detail page. | Open the run, scroll to the log. For more, run the app with `--log-level debug`. |
| TLS handshake fails. | `verify_tls` defaults to **off**, but some engines still trip on hostname mismatches. | On the active run wizard, leave *Verify TLS* off for self-signed targets. If you ticked it by accident, untick and re-run. |
| 302 → /login surfaces as `bypass-suspect` instead of `denied-correctly`. | *Follow redirects* is on, so the runner ends up at the login form (status 200) and similarity to the baseline is incidentally high. | Untick *Follow redirects*. Auth-bypass tests usually want to see the raw 302. |
| Session save fails: *"Session name is required."* | Whitespace-only name. | Use a non-blank name unique within the project. |
| `bypass-suspect` finding in the *Issues* table won't go away after dismissing the cell. | Dismissal only updates the cell verdict; the finding lives in the issues table. | Close the issue from the *Issues* / *Scanner* view. |

## CLI equivalents

None as of Phase 17. The runner, shadow worker, and session
store are all accessed through the web UI. Programmatic access is
possible via the Python API on `Project`:
[`auth_matrix_create_session`](../../reqlore/storage/__init__.py),
[`auth_matrix_list_runs`](../../reqlore/storage/__init__.py),
[`AuthMatrixRunner.start`](../../reqlore/auth_matrix/runner.py),
[`AuthShadowWorker.start`](../../reqlore/auth_matrix/shadow.py).

## Storage footprint

Schema v6 (introduced in Phase 17). Three new tables in the project
`.rlr` file:

- **`auth_matrix_sessions`** — `id`, `name` (UNIQUE), `kind`,
  `payload_blob` (encrypted), `source`, `source_hid`, `created_at`,
  `last_used_at`, `active`.
- **`auth_matrix_runs`** — `id`, `mode` (`active`/`shadow`), `label`,
  `started_at`, `finished_at`, `status`, `baseline_session_id`,
  `compare_session_ids_json`, `history_ids_json`, `options_json`,
  `progress_done`, `progress_total`, `progress_msg`, `log` (capped
  100 KiB), `error` (capped 2 KiB), `verdict_counts_json`.
- **`auth_matrix_cells`** — `id`, `run_id` (FK
  `auth_matrix_runs.id` `ON DELETE CASCADE`), `history_id`,
  `session_id`, `status`, `body_len`, `duration_ms`,
  `baseline_status`, `baseline_len`, `similarity_pct`, `verdict`,
  `error`, `request_blob` (zlib, ≤ 64 KiB pre-compression),
  `response_blob` (zlib), `baseline_response_blob` (zlib),
  `finding_id`, `created_at`.

Two `project_state` keys:

- **`auth_matrix:key_v1`** — base64-encoded random 32-byte key
  used by ChaCha20-Poly1305 AEAD. Generated on first use by
  [`derive_or_load_key()`](../../reqlore/auth_matrix/crypto.py).
  Versioned envelope on disk: byte `0x00` = plaintext frame (used
  when payload is empty or `cryptography` is missing), `0x01` =
  AEAD frame (`0x01 || nonce || ciphertext || tag`).
- **`auth_matrix:shadow_enabled`** — `"1"` while the operator has
  the shadow worker turned on, `"0"` (or missing) otherwise. Used
  by [reqlore/web/__init__.py](../../reqlore/web/__init__.py)'s
  Phase 17 extensions block to auto-resume the worker on project
  open.

This is **defence in depth, not isolation**: anyone with read
access to the `.rlr` file also has access to the key. The point is
to prevent session payloads from sitting in plaintext inside SQLite
blobs that operators might rsync, copy, or attach to bug reports
without thinking about credential exposure.
