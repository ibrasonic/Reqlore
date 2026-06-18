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
3. Filter by clicking a column-header **▾** marker — pick **Method**, **Status**, **Host**, **URL**, **Bytes**, **ms**, or **Engine** — and tick / type values inside the menu, then submit (Enter or **Apply filters**). Active filters show a filled **●** marker on the column and an accent-coloured left-border on the cell.
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

### Filter menus (per column)

The old top-of-page form was replaced with **per-column disclosure menus**
attached directly to each filterable `<th>`. Each header is rendered as:

```html
<th scope="col" class="hist-th hist-th--filter">
  <details class="hist-col-filter" data-hist-col-filter id="hist-filter-method">
    <summary class="hist-col-filter-toggle"
             aria-label="Method filter; active: GET, POST">
      <span class="hist-col-name">Method</span>
      <span class="hist-col-filter-marker" aria-hidden="true">●</span>
    </summary>
    <div class="hist-col-filter-panel" role="group" aria-label="Method filter">
      …form controls…
    </div>
  </details>
</th>
```

The whole table is wrapped in **one** `<form id="hist-filters" method="get"
role="search">` so submitting from any column commits every column's
draft state in a single navigation. Per-column controls:

| Column   | Control                                                                   | Query string                                            |
|----------|---------------------------------------------------------------------------|---------------------------------------------------------|
| Method   | Multi-select checkboxes — `GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS` | `?method=GET,POST` (CSV) or repeated `?method=GET&method=POST` |
| Status   | Multi-select bucket checkboxes (`1xx / 2xx / 3xx / 4xx / 5xx`); exact codes via URL bar (e.g. `?status=401,403`) | `?status=2xx,4xx` |
| Host     | Text input + radio (`exact` / `contains`)                                  | `?host=example.com&host_mode=contains`                  |
| URL      | Text input + checkbox **Treat as regular expression**                      | `?q=/admin&q_re=1`                                      |
| Bytes    | Min / Max numeric pair (response body length)                              | `?len_min=1000&len_max=200000`                          |
| ms       | Min / Max numeric pair (request duration)                                  | `?dur_min=100&dur_max=5000`                             |
| Engine   | Multi-select checkboxes populated from the values currently in the table  | `?engine=httpx,raw`                                     |

Active filters are signalled three ways (so colour is never the sole
signal — SC 1.4.1 *Use of Colour*):

1. The summary's `aria-label` is rewritten to include the active values.
2. The marker glyph flips from `▾` to `●`.
3. The cell gets an accent-coloured left-border.

A **Clear all filters** link appears in the toolbar above the table when
any filter is active. **Export JSONL** and **Clear all history** stay
in that toolbar.

#### Apply, Cancel, focus trap (popup behaviour, JS on)

Every open menu renders a footer row with two buttons plus a keyboard hint:

- **Apply** — `<button type="submit" class="hist-filter-apply">`. It is
  inside the wrapping `<form id="hist-filters">`, so clicking it
  commits every column's draft state in a single GET navigation —
  identical to pressing Enter inside any field. This is the
  discoverable affordance for sighted mouse users; keyboard users
  additionally get Enter.
- **Cancel** — `<button type="button" data-hist-filter-close>`. Closes
  the menu and restores focus to its `<summary>` without submitting.
  Mirrors what **Esc** does from the keyboard.
- A `<p class="hist-filter-hint">` tells the user verbatim which keys
  apply and which cancel.

While a menu is open the JS layer **traps Tab / Shift+Tab inside the
panel** — focus cycles through the panel's form controls + Apply +
Cancel, then wraps. Screen-reader users therefore cannot accidentally
tab past the open menu into the next column header or table row and
lose their place. The only ways out are:

- **Esc** or **Cancel** (closes, restores focus to the column summary), or
- **Enter** or **Apply** (commits — page reloads to the filtered table).

This is a deliberate departure from a plain disclosure: the open menu
behaves more like a popup. We picked it because the user-research
report specifically asked for "cannot go out of [the menu] if it is
open" for screen-reader certainty. The trap is implemented in JS only;
with JS off the menus revert to native `<details>` behaviour and Tab
walks normally — see *No-JS fallback* below.

#### Whitelist / validation

The blueprint never forwards a hand-edited query-string value straight
into the SQL `WHERE`. Methods are clamped to a fixed whitelist; status
tokens must match `^[1-5]xx$|^[1-9]\d{2}$`; numeric ranges are coerced
through `int()` and silently dropped on `ValueError`; `host_mode` falls
back to `exact` for any value other than `contains`. Defence in depth —
the storage layer already binds with `?` placeholders.

#### Why per-column instead of one big form?

* The filter UI lives next to the data it filters, so it is discoverable
  even on a 27-column table. (`Bytes` and `ms` ranges, in particular,
  were invisible in the old form.)
* Native `<details>` works without JavaScript: keyboard activation,
  toggle, focus order all come from the browser. The JS layer only adds
  *nice-to-haves* — close-on-Escape, close-others-on-open, focus the
  first input on open. With JS off the menus still open / close and the
  fallback **Apply filters** button submits the form.
* Each menu is a `<details>` whose `<summary>` is the **single**
  visible interactive element in that header cell — exactly one
  control per `<th>`, which keeps the table semantics intact for
  screen readers (no nested-button traps).

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
     data-latest-url="/history/latest.json?method=GET,POST&status=2xx&…"
     data-since="<max_id>">
  <label class="hist-live-toggle">
    <input type="checkbox" id="hist-live-cb"> Auto-refresh when new requests arrive
  </label>
  <span id="hist-live-status" role="status" aria-live="polite" aria-atomic="true"></span>
  <a id="hist-live-refresh" class="hist-live-refresh" href="" hidden>Refresh now</a>
  <noscript>(JavaScript disabled — press F5 to see new requests.)</noscript>
</div>
```

Crucially, the **Refresh now** link is a *sibling* of the
`role="status"` element, **not a child**. Only the count text lives
inside the live region, so screen readers announce the count change
without re-reading the link's label every poll. The JS only repaints
when the count *actually changes* (`lastAnnouncedCount` guard) — an
unchanged 5 → 5 triggers no announcement.

| Behaviour                       | Spec                                                                                        |
|---------------------------------|---------------------------------------------------------------------------------------------|
| Polling interval                | 2500 ms                                                                                      |
| Reload delay after detection    | 600 ms                                                                                       |
| Pause on hidden tab             | Yes — polls resume on `visibilitychange`.                                                    |
| Focus-busy guard                | Skips reload while focus is in an INPUT/TEXTAREA/SELECT or while any row Actions menu is open. Indicator stays so you can refresh manually. |
| `localStorage` key              | `reqloreHistoryAutoRefresh` (`"on"` / `"off"`).                                              |
| Default                         | **OFF** — required by WCAG 2.2 SC 3.2.5 *Change on Request* at the AAA level.                |
| Repeat-announce guard           | Live region only repaints when `newCount` differs from the last announced count — required by SC 2.2.4 *Interruptions* (AAA). |
| Filter scoping                  | The `since` cursor advances monotonically and the polled URL carries the current filter set, so the "N new" count always reflects what you actually see. |
| Network failures                | Silent. Retry on the next tick.                                                              |

When new requests are detected the status span is filled with a plain
sentence — `5 new requests.` — and the sibling **Refresh now** link is
unhidden with `href` set to the current URL.

## Detail page

- **Heading** — `<h1>Request #<id></h1>`.
- **Summary line** — `<strong>METHOD</strong> URL → <strong>STATUS</strong> in <ms> ms (engine)`.
- **Response summary** — `summarise_response()` one-liner: "200 OK text/html 5.2 kB".
- **Send-to menu** — `<section aria-labelledby="hs-h">` plus a `<p id="hs-help">` explaining the accesskey modifier per browser.
- **Plugin copy-as links** (when any).
- **Request (`<len_req>` bytes)** — `<pre><code>` with the raw bytes,
  decoded UTF-8 with latin-1 fallback. When a Find query is active,
  matches in the request body are wrapped in `<mark id="req-mN">`
  in this same pane (no duplicated combined block).
- **Response (`<len_resp>` bytes)** — same shape with its own pane;
  matches are wrapped in `<mark id="resp-mN">` in place.
- **Find in this exchange** — a single server-side find form sits
  ABOVE the two panes. On submit the page re-renders with each
  hit wrapped in place inside its native pane (request or response),
  a `role="status"` count, and a list of "Match N of M in request|
  response (line L)" anchor links that jump into the original
  panes. URL params: `?body_find=<text>&body_re=1` (regex opt-in;
  matching is always case-insensitive). See
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
- `list_history(*, limit=200, offset=0, host=None, host_mode='exact', q=None, q_regex=False, method=None, methods=None, statuses=None, engines=None, len_min=None, len_max=None, dur_min=None, dur_max=None)` — returns
  `HistoryRow` objects ordered `id DESC`. Multi-select arguments accept `list[str]`; an empty list / `None` means "no constraint". `statuses` accepts both buckets (`2xx`) and exact codes (`401`); they OR together. `q` + `q_regex=True` post-filters in Python with `re.search` (invalid pattern silently falls back to LIKE-only).
- `count_history_after(since, *, …same filters…) -> (new_count, max_id)` —
  drives `/history/latest.json`. Invalid `since` is coerced to 0.

## Accessibility notes

- The whole filter UI is a single search landmark (`<form role="search" aria-label="History filters">`) wrapping the table.
- Each filterable `<th>` contains a `<details>` whose `<summary>` is the column-header **button** (a real disclosure trigger that screen readers announce as "Method filter, button, collapsed"). Active filters are added to that `aria-label` so AT users hear "Method filter; active: GET, POST" — meeting SC 1.4.1 *Use of Colour*. The visible `●` glyph and the cell's accent border are redundant, not the sole signal.
- Multi-select groups are wrapped in `<fieldset><legend>Match any of</legend>` so the group name is announced once with each option.
- All interactive controls meet **44 × 44 px** target size (SC 2.5.5 *Target Size*, AAA): summary toggles, `<input>`s, the *Apply filters* fallback, and the toolbar links use `min-height: 44px`.
- **Focus management** for the menus: opening a column menu auto-focuses its first input on the next paint; **Escape** closes the open menu and returns focus to its `<summary>` (SC 2.4.3 *Focus Order*); opening one menu closes any other open menu (no focus ever leaves the user's expectation).
- Row Actions button uses the full APG menu pattern: `aria-haspopup="menu"`,
  `aria-expanded`, `aria-controls`, `aria-label="Actions for request #<id>"`.
  Menu items get `role="menuitem"` and `tabindex="-1"` (roving focus).
- Live region (`role="status" aria-live="polite" aria-atomic="true"`) on the auto-refresh status span. The **Refresh now** link is a sibling, not a child, so the link's label never enters the live region. The region only fires when the count *changes* — required by SC 2.2.4 *Interruptions* (AAA).
- AAA SC 3.2.5 *Change on Request* — auto-refresh defaults OFF; `?q_re=1`,
  multi-checkbox toggling and any other filter change require an explicit
  Apply / Enter to commit (no auto-submit on change).
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
