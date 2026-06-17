# Intruder — `/intruder/`

The Intruder bulk-attacks a request template by walking through one or more
payload lists. It is Reqlore's templated payload-fuzzer, with the four
classic attack types (sniper / battering ram / pitchfork / cluster bomb),
the same six request engines as Repeater, and an extended payload-processor
pipeline that includes per-payload JWT signing.

## Where it is

- **URL:** `/intruder/`
- **Nav:** *Intruder* in the top bar.
- **Pre-fills from** `?from_history=<hid>` (every "Send to Intruder" link uses this).

## Quick start — your first attack

1. Capture a request you want to attack (browse through the proxy or pick any row from [History](history.md)).
2. From that history row, click **Send to Intruder** (or open the row Actions menu and pick Intruder).
3. The **New Attack** form is now pre-populated with the request template. Mark each insertion point by wrapping it with the marker character — default **§** (U+00A7), changeable in the *Marker* field. Example: `Authorization: Bearer §token§`.
4. Pick an **Attack type** (Sniper for one position, Cluster Bomb for the cartesian product, …), choose a **Payload source**, paste your wordlist, set **Concurrency** (default 4).
5. **Create attack**. You land on the attack detail page; click **Start**. Rows stream in as responses arrive — sort by Length to spot the outliers, filter by status, export to CSV/JSON.

## Routes

| URL                                  | Method | What it does                                                                              |
|--------------------------------------|--------|-------------------------------------------------------------------------------------------|
| `/intruder/`                         | GET    | List every attack with status (idle / running / paused / done / cancelled / errored).      |
| `/intruder/new`                      | GET    | Show the New Attack form. `?from_history=<hid>` pre-fills the template.                    |
| `/intruder/new`                      | POST   | Validate, persist, redirect to the detail page. P/R/G — refreshing never re-submits.        |
| `/intruder/<aid>`                    | GET    | Detail: live status, progress bar, results table, sort/filter, export links.                |
| `/intruder/<aid>/results.json`       | GET    | Polled by the page when `auto=1`. Returns rows newer than `?since=<seq>`.                   |
| `/intruder/<aid>/export.csv`         | GET    | 9-column CSV honouring current filter state.                                                |
| `/intruder/<aid>/export.json`        | GET    | JSON export with metadata, same filters.                                                    |
| `/intruder/<aid>/start`              | POST   | Build a new `AttackRunner` and start it. Idempotent: flashes a warning if already running.  |
| `/intruder/<aid>/pause`              | POST   | Pause an in-flight attack (workers drain, status becomes `paused`).                         |
| `/intruder/<aid>/resume`             | POST   | Resume a paused attack from the next seq.                                                   |
| `/intruder/<aid>/cancel`             | POST   | Cancel; status resolves to `cancelled`; in-flight requests are allowed to finish.            |
| `/intruder/<aid>/delete`             | POST   | Delete the attack and every result row (confirmation dialog in UI).                          |

## Attack types

| Value         | Label                                              | Payload sets used                  |
|---------------|----------------------------------------------------|------------------------------------|
| `sniper`      | Sniper — one position at a time (single payload set) | 1 — one position fuzzed per request |
| `battering`   | Battering Ram — same payload in every position      | 1 — same payload in every marker    |
| `pitchfork`   | Pitchfork — N sets advance in lockstep              | up to 4 (stops at shortest)         |
| `clusterbomb` | Cluster Bomb — every combination (cartesian)        | up to 4 (cartesian product)         |

Sets 2-4 are hidden in a `<details>` element on the form, opened by default
only when you pick Pitchfork or Cluster Bomb. The form itself preserves any
text you typed across the page (so switching attack type doesn't wipe the
textareas in your current browser tab), but **on submit only the sets the
attack type actually consumes are saved** with the attack:

- `sniper` / `battering` keep Set 1 only — anything in Sets 2-4 is
  silently dropped by `_payload_sources_from_form` (`return sets[:1]`).
  It is **not** stored on the attack record and **not** available if you
  later edit / clone the attack.
- `pitchfork` / `clusterbomb` keep every non-empty set, up to four.

If you typed something into Set 2 and then changed your mind about the
attack type, switch to Pitchfork or Cluster Bomb before clicking
**Create attack**, or paste the contents elsewhere first.

## Payload sources

Picked from the **Source** dropdown; the form shows only the inputs for the
chosen source via a small JS toggle, with a `<noscript>` fallback that shows
everything (so you fill in just the matching inputs).

| Source           | Inputs                                     | Limits                                                                                       | Streams? |
|------------------|--------------------------------------------|----------------------------------------------------------------------------------------------|----------|
| `text`           | `payloads_text` (+ `payloads_set2..4`)     | none, bounded by textarea                                                                    | no       |
| `numbers`        | `num_start`, `num_end`, `num_step`         | total payloads capped at **100,000**                                                          | no       |
| `brute`          | `brute_alphabet`, `brute_min`, `brute_max` | hard cap at **50,000** payloads                                                               | no       |
| `common_pw`      | (none)                                     | small built-in list                                                                          | no       |
| `wordlist`       | `wordlist_name`                            | the six bundled lists (`common_passwords`, `common_usernames`, `lfi_paths`, `xss_payloads`, `sqli_payloads`, `subdomains`) | no |
| `wordlist_file`  | upload `.txt` / `.lst` / `.dic`            | **5 MB**, **100,000 lines** max; lines starting with `#` and blank lines are stripped         | no       |
| `wordlist_path`  | absolute server-side path                  | **no limit** — streams from disk on every iteration (rockyou.txt, SecLists, …)                | **yes** — O(1) RAM |

> **Server-path source** is the right choice for big real wordlists. The file
> is re-opened per attack iteration and read lazily, so memory stays flat no
> matter the file size. The path must be absolute and readable by the
> Reqlore process.

## Engines

Same six engines as the [Repeater](repeater.md), pick from the **Engine**
dropdown:

- `httpx` (default) — HTTP/1.1 + H2 over TLS.
- `raw` — byte-exact raw socket. Use for smuggling/CL.TE/path-traversal where
  framing must not be touched.
- `h3` — HTTP/3 over QUIC. Requires the `[h3]` extra (`pip install reqlore[h3]`).
- `curl-cffi:chrome120` / `curl-cffi:safari17_0` / `curl-cffi:firefox109` —
  TLS-fingerprint impersonation. Requires the `[impersonate]` extra.

See [`../engines.md`](../engines.md) for picking criteria.

## Payload processors

Comma-separated, applied **left-to-right**. Each takes the previous output as
its input. Bad input never throws — the value passes through unchanged so the
attack can keep going.

### No-arg processors

`none`, `url`, `url2`, `html`, `b64`, `b64url`, `b64dec`, `hex`, `upper`, `lower`,
`md5`, `sha1`, `sha256`, `reverse`, `length`, `strip`, `sql-quote`.

### Arg processors (`name:arg`)

| Processor | Syntax                                                                                | Example                                | What it does                                    |
|-----------|---------------------------------------------------------------------------------------|----------------------------------------|-------------------------------------------------|
| `prefix:` | `prefix:<string>`                                                                     | `prefix:Bearer ` → `Bearer token123`   | Prepend a literal string.                       |
| `suffix:` | `suffix:<string>`                                                                     | `suffix:.pdf` → `report.pdf`           | Append a literal string.                        |
| `repeat:` | `repeat:<int>` (clamped to [0, 10000])                                                 | `repeat:5` → `xxxxx`                   | Repeat the payload N times.                     |
| `jwt:`    | `jwt:<ALG> [secret=<S>] [claim=<N>\|header=<N>] [base=<TOKEN>]`                        | see *JWT processor* below              | Mint a signed JWT per payload row.              |

### JWT processor in detail

Built for the bread-and-butter token-attack workflows so you can fuzz JWTs
from Intruder without leaving for the JWT workbench every iteration.

- **Algorithms:** `none`, `HS256`, `HS384`, `HS512`. Asymmetric algs
  (`RS*`/`ES*`) are intentionally not supported here — use the
  [JWT workbench](jwt.md) for those (it handles PEM keys properly).
- **Target — exactly one of:**
  - `claim=<name>` — the payload row becomes the string value of that claim
    in the JWT payload (e.g. `claim=sub`, `claim=role`, `claim=user_id`).
  - `header=<name>` — the payload row becomes the string value of that key in
    the JWT header (e.g. `header=kid` for traversal sweeps).
- **`secret=`** — required for HS\*; ignored for `none`. Quote values with
  spaces: `secret="my long secret"` (parsed via `shlex.split`).
- **`base=<token>`** — seeds header + payload from an existing captured JWT
  so the other claims (`exp`, `iat`, `iss`, …) survive. The target claim or
  header key is overwritten; `alg` is always overwritten.
- **Errors fall through.** Unknown alg, missing target, both targets at
  once, bad `base=` token — the row is sent unchanged, which surfaces as
  401/403 in the results table so you can spot and fix the spec.

Worked examples:

```
jwt:none claim=sub                                  # classic alg=none enumeration
jwt:HS256 secret=mysecret claim=sub                  # once you've cracked the HMAC secret
jwt:none header=kid base=<captured-token>            # kid traversal sweep
jwt:HS256 secret="key with spaces" claim=role        # quoted secret
jwt:none claim=sub, prefix:Bearer                    # chains to a ready-to-paste header value
```

## Grep / extract

The **Grep** textarea (one regex per line) runs against the response body.

- Plain pattern → first match (capped at 120 chars).
- `=count:<re>` → count of matches as `N×re`.
- `=all:<re>` → all matches joined by `;` (each capped at 60 chars, total at 240).

Invalid regex is silently skipped. The result table's **Match** column shows
✓/—, and **Grep** shows the joined extract text. Tick **Stop on match** to
cancel the attack on the first hit; tick **Emit findings** (where present) to
promote each hit to a Finding.

## The Options block

| Field             | Default | Notes                                                                                  |
|-------------------|---------|----------------------------------------------------------------------------------------|
| `concurrency`     | 4       | ThreadPoolExecutor workers. No hard upper bound but be polite.                          |
| `delay_ms`        | 0       | Pause between requests in milliseconds.                                                  |
| `max_requests`    | 1000    | Safety cap; attack stops iterating once this many requests have been sent.               |
| `retries`         | 0       | Retries **only** on network/send exceptions. HTTP status codes do not trigger retries.   |
| `stop_on_status`  | (empty) | Comma- or semicolon-separated status codes; first hit cancels the attack.                |
| `stop_on_match`   | off     | Cancel on the first grep match.                                                          |

## The detail page

- **Status line** — `<span role="status" aria-live="polite">` so screen
  readers announce running / paused / done / errored as it changes.
- **Progress bar** — `<progress value=N max=total>` with `aria-label`.
- **Toolbar** — Start / Pause / Resume / Cancel / Delete buttons. Disabled
  state is server-rendered (`disabled aria-disabled="true"`), so you never
  see a button you cannot use; the only "destructive" one (Delete) is in a
  confirm dialog.
- **Auto-refresh** — `?auto=1` adds a 3-second meta refresh and a "Stop
  auto-refresh" link; `?auto=0` shows "Start auto-refresh" plus a manual
  Refresh link. Works without JS.
- **Filter bar** — Status class (`2xx`/`3xx`/`4xx`/`5xx`), length min/max,
  Match yes/no, free-text search across payload + grep, Dedup by body MD5.
- **Results table columns** — `#`, **Payloads** (collapsed into `<details>`
  when long), **Status**, **Length**, **Time (ms)**, **Match**, **Grep**,
  **History** (link to the snapshot row). Every column is sortable; the
  active column is `aria-current="true"`.
- **Export** — CSV / JSON links respect the current filter state.
- **Errored attacks** — silent worker crashes are surfaced: the final status
  flips to `errored` and `stop_reason` shows the first exception (e.g.
  `LocalProtocolError: Illegal header value` on a malformed template).

## How it integrates

**Producers** (anywhere with a "Send to Intruder" link):

- [Proxy](proxy.md) held-request detail page (accesskey **i**).
- [History](history.md) row Actions menu and detail page.

**Consumers:** each result row links back to its snapshot in
[History](history.md). Findings emitted from grep matches land in
[Scanner](scanner.md) → Findings.

## Accessibility notes

- All form controls have explicit `<label for>` and grouped under
  `<fieldset><legend>` blocks (Basics, Request template, Payload source,
  Options). Number inputs use `inputmode="numeric"` for mobile.
- Source switcher is `<select data-source-select>`; the JS listener toggles
  `hidden` on `<div data-source-group>` blocks. The `<noscript>` block
  reveals every group (CSS rule `[data-source-group][hidden] { display: revert !important; }`)
  so keyboard-only / JS-disabled users can fill any source by ignoring the
  groups they do not want.
- Status updates live in `role="status"` (polite). The progress bar uses a
  native `<progress>` with `aria-label` and `aria-valuetext`.
- Sort links carry `aria-current="true"` on the active column with an
  `aria-label` describing the order *and* the toggle action.
- Long payload cells collapse into `<details><summary>` with a `<ul>` inside
  so a screen reader can drill in only when wanted.

## Recipes

### Spray usernames against a login form

- Template marks the `username` POST field with `§…§`.
- Source: `wordlist_path` → `/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt`.
- Attack type: Sniper.
- Grep: `Invalid|incorrect|unknown` (look for the negative tell).
- Sort results by Length. A row with a different length than the rest is
  often the right username.

### Use the cracked HMAC secret to spray every privileged role

```
Template:    Authorization: Bearer §x§
Source:      text  →  admin, root, super, dba, billing-admin, ...
Processors:  jwt:HS256 secret=mysecret claim=role
Grep:        "role":"(admin|super)"   (you can also rely on status 200 vs 403)
```

### Kid-header path traversal sweep

```
Template:    Authorization: Bearer §x§
Source:      wordlist_path -> /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
Processors:  jwt:none header=kid base=<captured-token>
Stop on:     200
```

The `base=` keeps `exp` and `iat` from the captured token so the server does
not reject for expiry; you only fuzz the `kid` header value.

### Brute a 6-digit OTP with rate-limit dodge

```
Source:        numbers  start=0  end=999999  step=1
Concurrency:   1
delay_ms:      250
max_requests:  1000000     (raise the safety cap)
Grep:          welcome|dashboard
Stop on match: yes
```

## Troubleshooting

| Symptom                                                                    | Cause                                                                                         | Fix                                                                                                                          |
|----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| Attack flips to **errored** immediately, 0 results                          | Stale `Content-Length` or `Transfer-Encoding` from the captured template                       | Reqlore drops both headers automatically before each send (locked down by `test_intruder_run_*` tests). If you still see this, edit the template and remove them by hand. |
| `jwt:` processor produces 401s for every row                                | Wrong alg, wrong secret, or target server expects RS\* (asymmetric)                              | Use the [JWT workbench](jwt.md) to confirm the server's expected alg + key first, then bring the right `secret=` here.       |
| `wordlist_path` form rejects the file                                       | Path is not absolute, or Reqlore process cannot read it                                        | Provide a full path (`/usr/share/...` on Linux, `C:\path\...` on Windows) and check file perms.                              |
| Numbers source caps out at 100,000                                          | Hard cap in `payloads_numbers()`                                                                | Split into multiple attacks or use a streaming wordlist.                                                                       |
| Brute source caps at 50,000                                                 | Hard cap in `_capped()`                                                                          | Tighten the alphabet, drop `brute_max` by 1, or move to a wordlist.                                                            |
| Detail page does not refresh on its own                                     | `?auto=0`                                                                                        | Click **Start auto-refresh (every 3 s)** at the top of the detail page.                                                       |

## CLI equivalents

```
reqlore intruder run    <spec.{json,yaml}> --project <p>   # run a saved spec headlessly
reqlore intruder list   --project <p>                      # list attacks
reqlore intruder show   <aid> --project <p>                # show metadata + results count
reqlore intruder export <aid> --project <p> --format csv   # export by aid
```

Saved specs are plain JSON/YAML mirroring the New Attack form; `--dry-run`
prints the resolved request set without sending.

## Storage footprint

Persisted in the `.rlr` SQLite project file:

- **`intruder_attacks`** — one row per attack: `id`, `name`, `attack_type`,
  `template_blob` (zlib), `positions_json`, `payloads_json` (inline lists or
  `{"kind":"path","path":"..."}` for streaming sources), `options_json`,
  `url`, `engine`, `status`, `created_at`.
- **`intruder_results`** — one row per request: `attack_id`, `seq`,
  `payloads_json`, `status`, `len_resp`, `duration_ms`, `grep_hits`,
  `history_id`, `body_md5`, `matched`.
- Deleting an attack drops both tables' rows for that `aid`.

Each result also writes a row into the History table (with the snapshot's
`hid`), so you can pivot from an Intruder hit straight into a Repeater
session.
