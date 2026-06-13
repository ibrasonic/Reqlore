# History — `/history/`

Every request that flows through the proxy lands in History — paginated, full-text
searchable, filterable, exportable. It is also the launchpad for almost
everything: every row has a "Send to …" menu that dispatches into Repeater,
Intruder, Comparer, JWT workbench, Decoder, or PoC builder.

## Where it is

- **URL:** `/history/`
- **Nav:** *History* in the top bar.
- **Live auto-refresh** (off by default) polls a tiny JSON endpoint and shows
  a "N new requests — Refresh" indicator without reloading the page.

## Quick start

1. Get traffic flowing through the proxy (see [Proxy](proxy.md) for CA setup and `reqlore browser`).
2. Open `/history/`. Newest rows are at the top.
3. Filter with the **Search URL** / **Host** / **Method** form, or scroll.
4. Tick **Auto-refresh when new requests arrive** if you want the page to nudge you when new traffic lands.
5. Click any row's `#` to open the detail; from there, **Send to** Repeater / Intruder / JWT / Decoder / Comparer / PoC.

## Routes

| URL                              | Method | What it does                                                                            |
|----------------------------------|--------|-----------------------------------------------------------------------------------------|
| `/history/`                      | GET    | Paginated table + filter + auto-refresh root.                                            |
| `/history/<hid>`                 | GET    | Detail page (raw request bytes, raw response bytes, response summary, Send-to menu).     |
| `/history/<hid>/copy-as/<name>`  | GET    | Plugin-registered `copy_as()` handler. Returns `text/plain`.                              |
| `/history/<hid>/to-repeater`     | POST   | Convenience POST that 302s to the Repeater (used by the row Actions menu).               |
| `/history/<hid>/send/<slug>`     | POST   | Dispatch to a Send-to target (intruder, comparer, poc, jwt, decoder).                     |
| `/history/latest.json`           | GET    | Poll endpoint. Returns `{"new", "max_id", "since"}` honouring the current filter set.    |
| `/history/export.jsonl`          | GET    | Stream NDJSON (`application/x-ndjson`), capped at 10 000 rows.                            |
| `/history/clear`                 | POST   | Delete every row (POST + confirm dialog).                                                 |

## Index page

### Columns

In display order:

1. `#` — row ID, links to detail.
2. `Method` — `GET`, `POST`, …
3. `Status` — HTTP status code.
4. `Host`.
5. `URL` — long URLs word-break gracefully.
6. `Bytes` — response body length.
7. `ms` — request time.
8. `Engine` — what produced the row: `proxy`, `repeater/<engine>`, `intercept-snapshot`, `intruder`, etc.
9. `Flags` — comma-separated heuristic tags (`auth`, `csrf`, `cors`, `set-cookie`, `csp`, `redirect`) computed from headers.
10. `Actions` — the row-level menu button (see below).

Caption (visually hidden for screen readers): "HTTP history, newest first."

### Filter form

`<form method="get" role="search" aria-label="Filter history">`:

| Input    | Type   | Default | Behaviour                                                |
|----------|--------|---------|----------------------------------------------------------|
| `q`      | search | empty   | Substring match against URL (`LIKE %q%`).                 |
| `host`   | search | empty   | Exact host match.                                         |
| `method` | select | any     | `GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS`.     |

Buttons: **Apply** (submit), **Reset** (link to `/history/`), **Export
JSONL** (link to `/history/export.jsonl`), **Clear all history** (POST,
disabled when total is 0, JS confirm dialog).

## Row Actions menu (WAI-ARIA APG menu button)

Introduced in commit `d93039d`. Each row's Actions cell holds a `<button>`
that, when enhanced by JS, opens an ARIA menu of:

- **View** — `/history/<hid>`.
- **Send to Repeater** — `/repeater?from_history=<hid>`.
- **Send to Intruder** — `/intruder/new?from_history=<hid>`.
- **Compare A** / **Compare B** — two-step pick that builds a comparer URL.

### Keyboard behaviour (when JS is on)

- **Button** — `Space` / `Enter` / `↓` opens the menu at item 0; `↑` opens at the last item.
- **Open menu** — `↓` / `↑` roving focus; `Home` / `End` jump to edges; **Esc** closes and returns focus to the button.
- **Tab** — strict focus trap; cycles inside the menu, never escapes.
- **Type-ahead** — printable characters search item text (case-insensitive, 500 ms window, wrapping).
- Click-outside closes (no focus return, per APG).

### No-JS fallback

If JavaScript is off the button stays `hidden` and the `<ul>` renders as a
flat link list — every action is reachable as an ordinary anchor.

## Send-to targets

From `send_targets.py`:

| Slug       | Label                | Accesskey | Available when…                                              |
|------------|----------------------|-----------|--------------------------------------------------------------|
| `repeater` | Repeater             | **r**     | Always.                                                       |
| `intruder` | Intruder             | **i**     | Always.                                                       |
| `comparer` | Comparer (side A)    | **m**     | Always.                                                       |
| `poc`      | PoC builder          | **b**     | Always.                                                       |
| `jwt`      | JWT workbench        | **j**     | Request has `Authorization: Bearer <jwt-shaped>` header.     |
| `decoder`  | Decoder              | **o**     | Request has a non-empty body.                                |

The detail page also offers **Send to Comparer (side B)** (so you can pair
two rows) and **Create manual finding from this request** which jumps to
[Scanner → Manual](scanner.md#manual-finding-scannermanual) with
`?request_id=<hid>` pre-filled.

If any plugin registered `copy_as()` handlers, they show up as
**Copy as: …** links pointing at `/history/<hid>/copy-as/<name>`.

## Live auto-refresh

The page wraps the toggle in:

```html
<div class="hist-live" data-history-live
     data-latest-url="/history/latest.json?q=...&host=...&method=..."
     data-since="<max_id>">
  <label class="hist-live-toggle">
    <input type="checkbox" id="hist-live-cb"> Auto-refresh when new requests arrive
  </label>
  <span id="hist-live-status" role="status" aria-live="polite"></span>
  <noscript>(JavaScript disabled — press F5 to see new requests.)</noscript>
</div>
```

| Behaviour                       | Spec                                                                                        |
|---------------------------------|---------------------------------------------------------------------------------------------|
| Polling interval                | 2500 ms                                                                                      |
| Reload delay after detection    | 600 ms                                                                                       |
| Pause on hidden tab             | Yes — polls resume on `visibilitychange`.                                                    |
| Focus-busy guard                | Skips reload while focus is in an INPUT/TEXTAREA/SELECT or while any row Actions menu is open. Indicator stays so you can refresh manually. |
| `localStorage` key              | `reqloreHistoryAutoRefresh` (`"on"` / `"off"`).                                              |
| Default                         | **OFF** — required by WCAG 2.2 SC 3.2.5 *Change on Request* at the AAA level.                |
| Filter scoping                  | The `since` cursor advances monotonically and the polled URL carries the current filter set, so the "N new" count always reflects what you actually see. |
| Network failures                | Silent. Retry on the next tick.                                                              |

The status span builds: `<span>{N} new {request|requests} — <a href=...>Refresh</a></span>`,
with `.has-new` adding accent colour.

## Detail page

- **Heading** — `<h1>Request #<id></h1>`.
- **Summary line** — `<strong>METHOD</strong> URL → <strong>STATUS</strong> in <ms> ms (engine)`.
- **Response summary** — `summarise_response()` one-liner: "200 OK text/html 5.2 kB".
- **Send-to menu** — `<section aria-labelledby="hs-h">` plus a `<p id="hs-help">` explaining the accesskey modifier per browser.
- **Plugin copy-as links** (when any).
- **Request (`<len_req>` bytes)** — `<pre><code>` with the raw bytes,
  decoded UTF-8 with latin-1 fallback.
- **Response (`<len_resp>` bytes)** — same shape with its own pane.
- **Find in this exchange** — below both panes sits a single
  server-side find form. On submit the page re-renders with each
  hit wrapped in `<mark id="body-mN">`, a `role="status"` count, and
  a list of "Match N of M in exchange (line L)" anchor links. URL
  params: `?find=<text>&re=1` (regex opt-in; matching is always
  case-insensitive). When both request and response bodies are
  present they are merged with visible `--- Request ---` /
  `--- Response ---` section markers so screen-reader users can
  tell which region each highlighted match lives in. See
  [ACCESSIBILITY.md §
  Find-in-body](../ACCESSIBILITY.md#find-in-body-no-js-aaa-clean).
- **Back to history** link at the foot.

## Storage

Table **`http_history`**:

```
id (PK)  ts  host  method  url  status
len_req  len_resp  duration_ms  engine
flags  tags
req_blob (zlib level 6)  resp_blob (zlib level 6)
```

Indexes on `ts`, `host`, `status`, `method`. Blobs are decompressed
transparently on read.

Helpers used by this page:

- `add_history(...)` — every write goes through here; `ts = int(time.time())`
  at write time; `len_req` / `len_resp` recorded before compression.
- `list_history(host=, method=, q=, limit=200, offset=0)` — returns
  `HistoryRow` objects ordered `id DESC`.
- `count_history_after(since, host=, method=, q=) -> (new_count, max_id)` —
  drives `/history/latest.json`. Invalid `since` is coerced to 0.

## Accessibility notes

- Filter form is a search landmark.
- Row Actions button uses the full APG menu pattern: `aria-haspopup="menu"`,
  `aria-expanded`, `aria-controls`, `aria-label="Actions for request #<id>"`.
  Menu items get `role="menuitem"` and `tabindex="-1"` (roving focus).
- Live region (`role="status" aria-live="polite"`) on the auto-refresh
  status span. It only announces when the count changes; idle silence.
- AAA SC 3.2.5 — auto-refresh defaults OFF, locked down by
  `test_history_live_toggle_defaults_off_for_aaa`.
- Reduced motion: CSS `@media (prefers-reduced-motion: reduce)` disables
  the indicator's flash animation.
- Tables: `<th scope="col">` headers; caption (visually hidden) gives the
  read order (newest first).

## How it integrates

**Producers** (everything that writes a history row):

- [Proxy](proxy.md) — every captured request/response.
- [Proxy](proxy.md) Send-to actions — snapshot a held flow as a row with
  `engine="intercept-snapshot"` and `tags="intercept:<iid>"`.
- [Repeater](repeater.md) — every send is recorded as `engine="repeater/<engine>"`.
- [Intruder](intruder.md) — each result also writes a row so you can pivot
  back into the Repeater from any hit.

**Consumers** (everything that reads from a row):

- [Repeater](repeater.md), [Intruder](intruder.md), [Comparer](comparer.md),
  [JWT workbench](jwt.md), [Decoder](decoder.md), [PoC builder](poc.md) —
  all hydrate from `?from_history=<hid>` (or equivalent param).
- [Scanner](scanner.md) — passive checks run automatically over each new row.
- [Sitemap](sitemap.md) — builds its tree from this table.
- [Search](search.md) — FTS5 index over headers + bodies of every row.

## Recipes

### Tail traffic while you browse

Tick the **Auto-refresh** checkbox. Click anywhere outside form fields, then
keep browsing — the indicator builds "N new requests" silently, polite live
region announces it, and Refresh pulls the new page when you want it.

### Find every request that set a cookie

Filter URL by your target, then ctrl-F the **Flags** column for `set-cookie`.

### Export and grep offline

```
curl 'http://127.0.0.1:8787/history/export.jsonl?host=target.com' \
  | jq -r 'select(.method == "POST") | .url'
```

### Compare two responses

From the row Actions menu, **Compare A** on the first row, **Compare B** on
the second. The header chip on subsequent visits remembers your A pick.

## Troubleshooting

| Symptom                                           | Cause                                                  | Fix                                                                            |
|---------------------------------------------------|--------------------------------------------------------|--------------------------------------------------------------------------------|
| No new rows appear                                | Browser not actually using the proxy or CA not trusted | See [Proxy](proxy.md) — confirm the proxy is running and the CA is in place.    |
| Auto-refresh never indicates new requests          | The `since` cursor is at MAX(id) already               | Refresh once manually; the cursor resets to the new MAX(id).                    |
| Auto-refresh fires but the reload never happens    | Focus is inside a form field or a row menu is open      | Click elsewhere — the focus-busy guard releases on `blur`.                       |
| **Send to JWT** is missing                         | Request has no `Authorization: Bearer <jwt>` header     | Use the JWT workbench's "Paste a token" entry instead.                          |
| **Send to Decoder** is missing                     | Request body is empty                                  | Decoder is for body editing; for URL params use the in-place query builder.    |
| `/history/export.jsonl` cuts off                   | 10 000-row cap                                          | Filter first (`?host=…`), or export in batches by date range.                    |

## CLI equivalents

```
reqlore import-har --project <p> session.har    # bulk-load a browser HAR into history
```

Active scanning over history is handled by `reqlore scan`; see [Scanner](scanner.md).

## Test contract

`reqlore/tests/unit/test_history_live.py` locks:

- `count_history_after` empty / cursor / filter behaviour.
- `/history/latest.json` shape, filter passthrough, bad-`since` tolerated.
- Index page renders the live root with `data-history-live`, `data-latest-url`, `hist-live-cb`, `hist-live-status`.
- `data-since` reflects the current max id.
- Filter params round-trip into `data-latest-url`.
- **AAA toggle defaults off** (`test_history_live_toggle_defaults_off_for_aaa`).
