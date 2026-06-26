# Proxy — `/proxy/`

The Proxy is the intercepting MITM that sits between your browser and the
target. It always binds to `127.0.0.1:8080`, ships its own CA, supports
interactive request holds (forward / drop / forward-edited), and is the
producer of almost every row you see in [History](history.md).

## Where it is

- **URL:** `/proxy/`
- **Nav:** *Proxy* in the top bar.
- **Listener:** always `127.0.0.1:8080` (loopback only — `--port` only
  changes the port number, never the bind host).

## Quick start — trust the CA, point a browser, intercept

1. Start Reqlore with the proxy enabled: `reqlore both --project my.rlr` (or `reqlore proxy --project my.rlr` for proxy-only).
2. Open `/proxy/`, click **Start** (if not auto-started), then **Download CA**.
3. Import `reqlore-ca.pem` into your browser's *Authorities* store (Firefox: Settings → Privacy & Security → Certificates → Import).
4. Set your browser's HTTP/HTTPS proxy to `127.0.0.1:8080`. (Or skip steps 2-3 and just run `reqlore browser` — see [`../browser-launcher.md`](../browser-launcher.md).)
5. Browse the target. Rows stream into [History](history.md) live. Toggle **Intercept ON** to hold requests for manual editing.

## Routes

| URL                                            | Method | What it does                                                                            |
|------------------------------------------------|--------|-----------------------------------------------------------------------------------------|
| `/proxy/`                                      | GET    | Queue dashboard: pending intercepts, intercept toggle, filter config, bulk actions.      |
| `/proxy/intercept/count`                       | GET    | Poll endpoint, returns `{"count": N}` of pending holds.                                  |
| `/proxy/start`                                 | POST   | Start the listener in a background thread.                                               |
| `/proxy/stop`                                  | POST   | Stop the listener.                                                                       |
| `/proxy/intercept/toggle`                      | POST   | Global intercept on/off; persists to `project_state["intercept_on"]`.                    |
| `/proxy/intercept/config`                      | POST   | Update filter; persisted as JSON. UI exposes the method checkboxes and the scope toggle; the route still accepts `host_regex` / `path_regex` / `exclude_host_regex` / `exclude_path_regex` for round-trip compatibility (state restore, external callers).            |
| `/proxy/intercept/next`                        | GET    | Redirect to the oldest still-pending intercept, or back to the queue if none are held.    |
| `/proxy/intercept/<iid>`                       | GET    | Detail page: raw bytes editor, Forward/Drop/Forward-edited bar, Send-to menu.            |
| `/proxy/intercept/<iid>/forward`               | POST   | Forward as-is.                                                                            |
| `/proxy/intercept/<iid>/drop`                  | POST   | Drop (mitmproxy flow killed).                                                             |
| `/proxy/intercept/<iid>/forward_edited`        | POST   | Apply edits from the textarea then forward.                                                |
| `/proxy/intercept/<iid>/send/<slug>`           | POST   | Send the held request into a tool (snapshots to history; flow remains held).               |
| `/proxy/intercept/forward_all`                 | POST   | Forward every pending hold.                                                                |
| `/proxy/intercept/drop_all`                    | POST   | Drop every pending hold.                                                                   |
| `/proxy/intercept/send_all/repeater`           | POST   | Snapshot all held flows to history, then redirect to Repeater with the latest hid.         |
| `/proxy/ca`                                    | GET    | Download `reqlore-ca.pem` (`application/x-pem-file`). Returns 404 until first run.         |

P/R/G is honoured throughout — refreshing a POST'd page never re-submits.

## Listener

- **Bind**: always `127.0.0.1` (settings.proxy_host, hardcoded). `--port`
  changes the port (default 8080).
- **Mode**: explicit forward proxy (not transparent). Use a system or
  browser proxy config, not iptables.
- **Started from**: `ProxyController.start()` spawns a daemon thread named
  `reqlore-proxy` running mitmproxy's `DumpMaster` with a custom
  `_HistoryAddon` for request/response hooks.
- **Self-bypass**: requests targeting `127.0.0.1:<ui-port>`
  (or `localhost` / `::1`) are **never** held — your UI tab cannot get
  stuck waiting on itself even if intercept is on.
- **Port pre-check**: the CLI verifies the port is free before starting; on
  conflict you get a clean error, not a stack trace.

## CA management

- **Files** (`~/.reqlore/ca/`):
  - `reqlore-ca.pem` — public cert (CN: *Reqlore Local Root CA*, RSA 2048,
    SHA-256, 5-year validity).
  - `reqlore-ca.key` — private key, `0600` on Unix; Windows ACL-protected.
- **Generation**: `ensure_ca(ca_dir)` auto-creates both on the first proxy
  start.
- **Download**: `GET /proxy/ca` serves the PEM as an attachment. Returns
  404 if the CA hasn't been generated yet (i.e. proxy has never started).
- **Trusting the CA**:
  - **Firefox** — Preferences → Privacy & Security → Certificates → View
    Certificates → Authorities tab → Import → choose the PEM → tick "Trust
    this CA to identify websites".
  - **Chrome / Edge** — Settings → Privacy and security → Security →
    Manage certificates → Authorities → Import.
  - **Windows store** — right-click the PEM → Install → Current User →
    Trusted Root Certification Authorities.
  - **macOS Keychain** — drag the PEM into Keychain Access → set "Always
    Trust".
- **Shortcut**: `reqlore browser` does all of this for a dedicated
  Firefox profile in one command (see [`../browser-launcher.md`](../browser-launcher.md)).

## Held-request queue

Schema (`intercept_q` table):

```
id  kind ('request' | 'response')  req_blob (zlib)
hold_reason  created_at  flow_id
decision (NULL | 'forward' | 'drop' | 'forward_edited')
edited_blob (zlib, only if decision='forward_edited')
```

- Queue view at `/proxy/`. Columns: `#`, `Method`, `Host`, `URL`,
  `Kind`, `Reason`, `Actions`. Sorted newest at the bottom. The
  Method / Host / URL cells are derived per-row by parsing the held
  raw request via `_parse_raw_request()` in `proxy_bp`.
  - **Per-column filter popovers** (Method, Host, URL, Kind) sit in
    the `<th>` headers and use the shared
    [`_macros/hist_filter.html`](../../reqlore/web/templates/_macros/hist_filter.html)
    macros — same `<details><summary>` triangle markers, modal-dialog
    upgrade, focus trap and arrow-key roving as the History table.
    The wrapper `<form method="get" class="hist-filter-form"
    role="search">` collects every popover into one Apply submit;
    filtering is server-side and the empty state renders
    `No items match the current filter.`
  - The queue wrapper carries the shared `data-live-refresh` widget
    (same JS path as History) so new arrivals are announced via a
    `role="status" aria-live="polite"` region instead of an
    unannounced page reload. The auto-refresh checkbox defaults OFF
    (WCAG 2.2 SC 3.2.5 AAA) and the poll URL carries the current
    filter querystring so a `kind=response` view isn't surprised by
    request-side holds. See *Live auto-refresh* below for the full
    contract.
  - **Row Actions cell** uses the same WAI-ARIA APG menu-button
    widget as [History](history.md#row-actions-menu-wai-aria-apg-menu-button) — see *Row Actions menu*
    below for the form-item extension that makes Forward / Drop /
    Send-to work as menuitems while remaining CSRF-protected POSTs.
- **No auto-eviction.** Rows stay until you Forward / Drop or the
  sync-hold timeout fires (600 s).
- **Async vs sync hold**:
  - **Async** — flow forwarded immediately, queue keeps a copy you can
    inspect or replay.
  - **Sync** — flow blocks in the mitmproxy event loop until you decide;
    100 ms poll, 600 s ceiling. Used when the filter rule is marked
    `sync`.
- **Graceful Ctrl+C** — `_ProxyController.stop()` joins the proxy
  thread, and `_run()` cancels every pending asyncio task, gathers
  them with `return_exceptions=True`, runs
  `loop.shutdown_asyncgens()`, then closes the loop. This suppresses
  the `Task was destroyed but it is pending!` warning that previously
  appeared on Windows ProactorEventLoop when the user pressed Ctrl+C
  with requests held in the queue.

## Row Actions menu

The `Actions` cell on each queue row reuses the
[History row Actions menu](history.md#row-actions-menu-wai-aria-apg-menu-button)
widget (`data-row-actions`) — same APG menu-button pattern, same
focus trap, type-ahead and no-JS fallback. The Proxy queue is the
first caller where the menuitems are **CSRF-protected POSTs**
(Forward as-is / Drop / Send to …), not plain `<a href>` links, so
each `<li>` wraps a `<form method="post" class="row-actions-form">`
and its `<button type="submit">` carries `role="menuitem"`. The
widget treats `li > a` and `li > form > button[type="submit"]`
interchangeably:

- **JS on** → the `<form>` `<button>` is a menuitem; activating it
  submits the form normally (no `event.preventDefault`), so the CSRF
  hidden input still rides the POST.
- **JS off** → the toggle stays `hidden`, the `<ul>` renders as a
  flat list, and each form submits via its own button click.

Keyboard contract, roving focus, Esc-closes and click-outside are
identical to the History page; see the linked section for the full
behaviour table.

## Live auto-refresh

The held-queue page uses the **same `[data-live-refresh]` widget** as
History — same JS initializer, same opt-in checkbox, same dedup,
same `userIsBusy()` guard. The Proxy template just hands it a
different config:

```html
<div class="hist-live" data-live-refresh
     data-latest-url="/proxy/intercept/count?<current-filter-qs>"
     data-since="<max_iid_currently_shown>"
     data-count-field="new"
     data-storage-key="reqloreProxyAutoRefresh"
     data-checkbox-id="proxy-live-cb"
     data-status-id="proxy-live-status"
     data-refresh-id="proxy-live-refresh"
     data-focus-target="#q-h"
     data-noun-singular="intercept"
     data-noun-plural="intercepts">
  …
</div>
```

Contract:

- **Default OFF (WCAG 2.2 SC 3.2.5 AAA Change on Request).** The
  checkbox is never `checked` on server render; only `localStorage`
  (`reqloreProxyAutoRefresh = "on"`) flips it back on after the user
  opts in once. Toggle preference is page-scoped — flipping it on for
  Proxy does NOT also opt History in.
- **`/proxy/intercept/count` is filter-aware.** It accepts the same
  `method` / `kind` / `host` / `host_mode` / `q` / `q_re` querystring
  as the index view and returns `{count, new, max_id, since}` where
  `new` only counts *pending* intercepts with `id > since`. Decided
  (forwarded / dropped) items are skipped. The `count` field is the
  total matching the filter now, retained for backward compatibility.
- **`since` cursor.** The page template seeds `data-since` with the
  highest id currently on screen so the first poll never re-announces
  what the user already sees. The JS advances the cursor as new arrivals
  are announced via the `role="status" aria-live="polite"` region.
- **Quiet for screen readers.** Live region only updates when the
  count *actually changes* (`lastAnnouncedCount` guard), the "Refresh
  now" link is a sibling of the live region (so its label never enters
  the announcement), polling pauses while the tab is hidden, and the
  600 ms reload is skipped while focus is in a form control, a row
  Actions menu is open, or a column-filter `<details>` popover is open.
- **No more `data-intercept-watch` meta-poll.** The legacy
  `data-intercept-watch / data-intercept-on / data-intercept-count`
  attrs are gone; tests assert they don't come back (see
  `test_proxy_live.py::test_proxy_index_no_legacy_intercept_watch_attrs`).

## Action bar

On `/proxy/intercept/<iid>`:

| Button             | Accesskey | What it does                                                                               |
|--------------------|-----------|--------------------------------------------------------------------------------------------|
| **Forward edited** | **e**     | Submit the edited textarea (`name="raw"`, UTF-8 errors=replace). Stored as `edited_blob`.   |
| **Forward as-is**  | **a**     | Release the original bytes unchanged.                                                       |
| **Drop**           | **p**     | Kill the mitmproxy flow (silent close or 502 depending on stage). Styled `.danger` (red).    |

The accesskey letter is wrapped in `<u>…</u>` inside the label so it's
visually discoverable. Browser modifier varies — Alt (Chrome/Edge),
Alt+Shift (Firefox), Ctrl+Alt (macOS).

### Auto-advance after a decision

Forward / Forward-edited / Drop all redirect to the next still-pending
intercept (oldest first) instead of bouncing back to the queue page.
When the queue is empty they land on `/proxy/` so the "no intercepts
held" state is visible. This trims a triage decision from two round
trips (decide → queue → row click → detail) down to one (decide → next
detail). The bookmarkable `/proxy/intercept/next` shortcut does the
same thing on demand. Pinned by
[`test_intercept_auto_advance.py`](../../reqlore/tests/unit/test_intercept_auto_advance.py).

## Find in held request

Below the edit form sits a SEPARATE `<form method="get">` find widget
(`?body_find=<text>&body_re=1`) so submitting it cannot accidentally
forward or drop the held flow. On submit the page renders a read-only
`<pre>` with each hit wrapped in `<mark id="body-mN">`, a
`role="status"` count, and a list of "Match N of M in held request
(line L)" anchors. The editable textarea above stays untouched —
edits are not lost. Browser Ctrl+F cannot search inside a
`<textarea>`, so this is the only AAA-clean way to point a
screen-reader user at a substring in the held bytes. See
[ACCESSIBILITY.md § Find-in-body](../ACCESSIBILITY.md#find-in-body-no-js-aaa-clean).

## Send-to menu

Same six targets as the History detail page:

| Slug       | Label                | Accesskey | Available when…                                              |
|------------|----------------------|-----------|--------------------------------------------------------------|
| `repeater` | Repeater             | **r**     | Always.                                                       |
| `intruder` | Intruder             | **i**     | Always.                                                       |
| `comparer` | Comparer (side A)    | **m**     | Always.                                                       |
| `poc`      | PoC builder          | **b**     | Always.                                                       |
| `jwt`      | JWT workbench        | **j**     | Request has `Authorization: Bearer <jwt-shaped>`.            |
| `decoder`  | Decoder              | **o**     | Request body is non-empty.                                   |

Each Send-to:

1. Snapshots the held request to [History](history.md) with `engine="intercept-snapshot"` and `tags="intercept:<iid>"`.
2. Redirects to the target with `?from_history=<new_hid>` (or `?token=…` / `?text=…` for JWT and Decoder).
3. **Leaves the flow held.** You can still Forward / Drop / Forward-edited later.

## Send all queued to Repeater

`POST /proxy/intercept/send_all/repeater`:

- Iterates every pending intercept (`decision IS NULL`).
- Snapshots each to History with the `intercept-snapshot` engine tag.
- Redirects to `/repeater/?from_history=<latest_hid>`.
- Flashes: *"Sent N held item(s) to Repeater (latest history #M). Flows are still held."*
- Empty queue: flashes *"No pending intercepts to send"* without snapshotting.

## Intercept rules

The single rule built from `InterceptConfig` (persisted as JSON in
`project_state["intercept_config"]`):

| Field                 | Default                                                         | UI?  | Notes                                                                          |
|-----------------------|-----------------------------------------------------------------|------|--------------------------------------------------------------------------------|
| `methods`             | `["POST", "PUT", "PATCH", "DELETE"]`                            | yes  | Checkboxes for GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS.             |
| `restrict_to_scope`   | `False` (unchecked)                                             | yes  | Opt-in: when on, the proxy consults the project's [Sitemap](sitemap.md) scope rules before holding. Out-of-scope hosts pass through even if every other field matches. Useful when you want intercept to follow the same boundary as the rest of the project. |
| `host_regex`          | empty (any host)                                                | no   | Python `re`. Backend-only; ad-hoc host narrowing belongs in the per-column **Host** filter on the queue table.       |
| `path_regex`          | empty (any path)                                                | no   | Python `re`. Backend-only; ad-hoc path narrowing belongs in the per-column **URL** filter on the queue table.        |
| `exclude_host_regex`  | `DEFAULT_NOISE_HOST_REGEX` (Mozilla telemetry etc.)             | no   | Always-on default; the constant lives in `reqlore/proxy/rules.py`.             |
| `exclude_path_regex`  | `DEFAULT_NOISE_PATH_REGEX` (`\.(?:css|js|png|svg|woff2|...)$`)   | no   | Static-asset blanket exclude; always-on default in the same module.             |

The four regex fields stay in `InterceptConfig` (and on the
`POST /proxy/intercept/config` route) so persisted state from earlier
Reqlore versions round-trips intact and external callers can still
drive them programmatically. They're no longer surfaced in the panel
because real triage was happening in the per-column queue filters; the
upstream rule stays minimal (methods + optional scope gate + the noise
excludes) and the queue table handles ad-hoc host / URL slicing.

Matching order on a request:

1. Rule enabled? (always, when the toggle is on)
2. Host excluded → skip.
3. Path excluded → skip.
4. Host required but does not match → skip.
5. Method not in list → skip.
6. Path required but does not match → skip.
7. `restrict_to_scope` is on **and** host is out-of-scope per Sitemap → skip.
8. Otherwise → hold.

Note: the scope check is the last gate. An empty Sitemap (no include /
exclude rules) treats every host as in scope, so toggling
`restrict_to_scope` on a fresh project changes nothing until you add at
least one scope rule.

Responses can also be held — set `status_in` or `content_type_regex` on a
rule and the response addon will match.

## Match & Replace

Owns its own panel (see [Match & Replace](matchreplace.md)) but is **applied
here on the wire** by the same `_HistoryAddon`:

- On **request**: `apply_request(mr_rules, host, headers, body)` rewrites
  in-place before the flow is forwarded.
- On **response**: `apply_response(...)` rewrites before the body reaches
  the browser.
- Rules are filtered by `host_regex` (per rule) and by `where`
  (`req_header` / `req_body` / `resp_header` / `resp_body`).
- Live: changes saved in the Match & Replace panel apply on the next request,
  no proxy restart.

## Accessibility notes

- **Action bar** uses `accesskey` HTML attributes — browser handles them
  **before** the screen reader's browse-mode layer, so they work in NVDA
  without single-letter-quick-nav collisions.
- Header carries `role="banner"`, footer `role="contentinfo"`, breadcrumb
  `<nav aria-label="Breadcrumb">` with the current page marked
  `aria-current="page"`.
- Intercept summary on the detail page is a `<dl class="meta"
  aria-label="Intercept summary">`.
- Status messages (proxy running / stopped, intercept ON / OFF, queue
  count) live in `role="status"` (polite) live regions.
- Queue table: visually-hidden caption, `<th scope="col">` headers,
  `<th scope="row">` on the intercept id.
- Visual underlines: `_underline_first()` wraps the accesskey character in
  `<u>…</u>` for sighted operators.

## How it integrates

**Consumers** (everything that consumes a Proxy snapshot):

- [History](history.md) — every flow becomes a row.
- [Repeater](repeater.md), [Intruder](intruder.md), [Comparer](comparer.md),
  [JWT workbench](jwt.md), [Decoder](decoder.md), [PoC builder](poc.md) —
  one accesskey away from the detail page.
- [Match & Replace](matchreplace.md) — runs in the same addon.
- [Scanner](scanner.md) — passive checks fire automatically on each new
  flow.

## Recipes

### Hold every state-changing request, forward GETs

Default config already does this — only POST/PUT/PATCH/DELETE are listed
in `methods`. Toggle **Intercept ON** and start browsing. GETs flow
through; mutations queue for review.

### Quiet a noisy app

`exclude_host_regex` is no longer exposed as a text input in the panel
(the built-in `DEFAULT_NOISE_HOST_REGEX` already covers Mozilla
telemetry and the common offenders). To extend it for a one-off noisy
app, either:

- **One-shot, from the command line / a script**, POST a fuller regex
  to `/proxy/intercept/config` (the field is still accepted and
  persisted):

  ```
  curl -X POST -d '_csrf=...&exclude_host_regex=(^|\.)mozilla\.(com|net|org)$|(^|\.)telemetry\.example\.com$' \
       http://127.0.0.1:8787/proxy/intercept/config
  ```

- **Project-wide / persistent**, broaden `DEFAULT_NOISE_HOST_REGEX` in
  [`reqlore/proxy/rules.py`](../../reqlore/proxy/rules.py) so every new
  project picks it up.

For ad-hoc *inspection-time* narrowing (the common case), prefer the
per-column **Host** filter on the held-queue table instead \u2014 the rule
stays generous, you slice the view.

### Mass-replay everything you held

After a session, click **Send all queued to Repeater**. You land on Repeater
with the most recent flow loaded, and each earlier flow is now a snapshot
row in History — open them with `?from_history=<hid>` (the row Actions
menu in History does this for you).

### Edit one parameter and forward

On `/proxy/intercept/<iid>`, edit the value in the raw-bytes textarea.
**Alt+E** (Chrome/Edge) → Forward edited. Stored as `edited_blob`; the
original `req_blob` is still in the queue if you need to compare.

## Troubleshooting

| Symptom                                                  | Cause                                                                | Fix                                                                                              |
|----------------------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Browser warns "untrusted certificate" on every HTTPS site| CA not yet trusted in this profile                                    | Download `/proxy/ca`, import into the browser's *Authorities* store, restart the browser tab.    |
| Proxy refuses to start                                    | Port 8080 already in use                                              | Pass `--port <n>` (and `--proxy-port` if running `both`); pre-check error tells you which port.   |
| `/proxy/ca` returns 404                                   | Proxy has never started — CA file not generated yet                    | Click **Start** on `/proxy/` once (it creates the CA), then retry the download.                  |
| The UI tab freezes when intercept is ON                   | Should be impossible — self-bypass excludes `127.0.0.1:<ui-port>`      | Confirm `--ui-port` matches the UI port you opened; the proxy must know about it.                |
| Held request cannot be **Drop**-ped                       | Decision was already taken (race with auto-forward)                    | Refresh the queue — the row should have flipped to `decision IS NOT NULL` and disappeared.       |
| Send-to **JWT** missing                                   | No `Authorization: Bearer <jwt>` in the request                        | Use the JWT workbench's manual paste-token form instead.                                          |
| Send-to **Decoder** missing                               | Request body is empty                                                  | Decoder operates on bodies; for URL params use the in-place query builder elsewhere.              |
| Static assets still appear in the queue                   | `exclude_path_regex` no longer covers a new extension                  | Edit the constant in `reqlore/proxy/rules.py` (`DEFAULT_NOISE_PATH_REGEX`) or, programmatically, `POST /proxy/intercept/config` with a wider `exclude_path_regex`. |
| Intercept holds nothing for in-scope hosts even though the rule matches | `restrict_to_scope` is checked and the host isn't in your Sitemap include scope | Either add the host to your Sitemap scope (**Settings → Scope**) or untick **Only hold requests for hosts that are in scope** on the intercept filter. An empty Sitemap means *every* host is in scope. |

## CLI

```
reqlore proxy --project <p> [--port 8080] [--ui-port 8787] [-v]
reqlore both  --project <p> [--host 127.0.0.1] [--ui-port 8787] [--proxy-port 8080]
                            [--unsafe-bind] [--no-password] [-v]
```

`--unsafe-bind` is the only way to bind a non-loopback address. The proxy
side is always loopback regardless; `--unsafe-bind` only affects the UI.
See [`../login.md`](../login.md) for password requirements when
`--unsafe-bind` is set.

## Storage footprint

- **`intercept_q`** — queue of held flows (see schema above).
- **`project_state["intercept_on"]`** — `"0"` or `"1"`; survives restarts.
- **`project_state["intercept_config"]`** — JSON of `InterceptConfig`
  (including the `restrict_to_scope` flag); survives restarts.
- **`http_history`** — every proxied flow, plus every Send-to snapshot.
- **`match_replace`** — rules applied here on the wire; managed in the
  Match & Replace panel.
- **`~/.reqlore/ca/`** — CA cert + key (outside the project file).
