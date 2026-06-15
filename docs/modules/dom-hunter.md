# DOM Hunter — `/dom-hunter/`

DOM Hunter is Reqlore's DOM-XSS source/sink tracer. It is the same
category of tool as Burp Suite's DOM Invader: a browser-side agent
that wraps every dangerous JavaScript sink, watches them for a
per-project canary string, logs every `postMessage`, and streams the
findings back to Reqlore over a token-authenticated bridge.

The big difference is delivery: DOM Hunter ships as a native browser
add-on that the Reqlore-managed Firefox **force-installs and
auto-configures** on first launch — there is no XPI upload, no
about:debugging dance, no copy-pasting tokens.

## Where it is

- **URL:** `/dom-hunter/`
- **Nav:** *DOM Hunter* in the top bar (with a badge showing the
  current finding count).
- **DevTools panel:** inside the managed Firefox, press `F12` →
  *DOM Hunter* tab.
- **Sidebar:** `Ctrl`+`Shift`+`D`.
- **Toolbar popup:** click the puzzle-piece, choose *DOM Hunter*.
- **Bridge endpoints (token-auth, no session):** `/dom-hunter/__bridge/config`,
  `/dom-hunter/__bridge/report`, `/dom-hunter/__bridge/findings.json`.

## Quick start — zero-config tracing in one command

1. Create or open a project and start the UI:
   `reqlore serve --project my.rlr`
2. In a second terminal, launch the managed browser **with the same
   project** so the extension auto-installs and is pre-configured:
   `reqlore browser --project my.rlr --url http://127.0.0.1:8787/`
3. In Reqlore go to *DOM Hunter → Settings*, set the **Scope** (one
   host per line, `*.example.com` allowed), tick any **auto-inject
   targets** you want (URL fragment, query, `window.name`,
   `document.referrer`), then turn the tracer **On**.
4. In Firefox press `F12` on a target page and switch to the
   **DOM Hunter** panel. Browse the app — findings stream in live as
   the canary touches a hooked sink.
5. Click any row's *Open in Reqlore* to jump to the full detail page
   at `/dom-hunter/finding/<id>` (page URL, frame URL, source, sink,
   severity, the offending value, and the deduplicated stack).

## The interface

### `/dom-hunter/` — findings index

| Control | What it does |
|---|---|
| **Search** | Free-text match against `page_url`, `sink`, `source`, and `value`. |
| **Min severity** | Filter to *info / low / medium / high / critical* and above. |
| **Findings table** | Time, sink, source, severity, canary-seen flag, hit count (dedupe), open button. Up to 200 rows. |
| **Tracer status** | *Enabled / Disabled* with the current canary and bridge token (truncated). |
| **Clear findings** | `POST /dom-hunter/clear-findings` — wipes the `dom_hunter_findings` table for this project (idempotent, prints how many rows were deleted). |
| **Scope summary** | Read-only echo of `dom_hunter_scope` so you don't have to open Settings. |

### `/dom-hunter/finding/<id>` — finding detail

Full per-finding page rendering, in order:

- page URL and frame URL (separate when the sink fired inside an iframe)
- source label + plain-language explanation
- sink label + plain-language explanation (read from `SINK_INDEX`)
- severity badge
- `canary_seen` ("the canary was in the value that reached the sink")
- value (truncated at 4 KiB on the server)
- stack (truncated at 8 KiB), with the deduped top frame highlighted

### `/dom-hunter/messages` — `postMessage` log

| Control | What it does |
|---|---|
| **Origin filter** | Pull-down of every origin the agent has seen so far. |
| **Only canary** | Tick to hide messages that don't contain the canary. |
| **Messages table** | Time, origin, *has-canary* flag, data (first 4 KiB). |
| **Clear messages** | `POST /dom-hunter/clear-messages`. |

### `/dom-hunter/settings`

| Field | Effect |
|---|---|
| **Tracer enabled** | Persists to `project_state["dom_hunter_enabled"]`. Off by default. The next page load in the browser picks it up. |
| **Scope** | One host per line, `*.example.com` supported. Empty = every host. |
| **Auto-inject targets** | Check any of `location.hash`, `location.search`, `window.name`, `document.referrer` — the agent rewrites those sources on each in-scope page load so source→sink flows surface without you crafting payloads. |
| **Rotate canary** | Generates a fresh `rqdomh<12-hex>` value. Existing findings keep their old canary; new findings use the new one. |
| **Rotate token** | Generates a fresh URL-safe 32-byte bridge token. After rotation, run `reqlore browser --project my.rlr` again so the new token is written into Firefox's enterprise policy and picked up by the extension via `storage.managed`. |

### DevTools panel (`F12 → DOM Hunter`)

Same data as the web UI, filtered to the inspected tab. Live updates
arrive via `runtime.sendMessage({ type: "dom_hunter.eventAdded" })`
broadcast from the background script. Has a per-tab on/off radio that
disables hooks for the current tab and reloads.

## Routes

| URL | Method | What it does |
|---|---|---|
| `/dom-hunter/` | GET | Findings index + tracer status. |
| `/dom-hunter/finding/<int:fid>` | GET | Finding detail page. |
| `/dom-hunter/messages` | GET | `postMessage` log with origin / canary filters. |
| `/dom-hunter/settings` | GET / POST | Enable, scope, auto-inject, rotate canary, rotate token. |
| `/dom-hunter/clear-findings` | POST | Wipe `dom_hunter_findings`. |
| `/dom-hunter/clear-messages` | POST | Wipe `dom_hunter_messages`. |
| `/dom-hunter/__bridge/config` | GET | Token-authed config feed for the extension (`enabled`, `canary`, `scope`, `auto_inject`, `sinks`, `ui_url`). |
| `/dom-hunter/__bridge/report` | POST | Token-authed sink: `{kind:"finding", ...}` or `{kind:"message", ...}`. Findings dedupe on `sha256(sink|source|page_url|stack-top|canary_seen)`. |
| `/dom-hunter/__bridge/findings.json` | GET | Token-authed read mirror for the sidebar/popup. |

The three `__bridge/*` paths are exempted from the global CSRF
before-request in [reqlore/web/__init__.py](../../reqlore/web/__init__.py)
because the extension has no Reqlore session cookie; they enforce
their own auth via `X-DOMHunter-Token` (constant-time compared
against the per-project secret).

## How it integrates

- **Proxy / History.** DOM Hunter is *not* in the Send-to graph — it
  is observation-only and the browser is the producer. The traffic
  the agent generates while you browse still appears in
  [History](history.md) like any other request through the proxy.
- **Reporter.** Findings are pulled by [Reporter](reporter.md) the
  same way scanner findings are, so your project's PDF/HTML report
  includes them under a *DOM XSS* section without extra work.
- **Search.** Free-text search across `value`, `sink`, `source`,
  `page_url` is available on the index. Use the
  [Search](search.md) module for cross-table queries that include
  DOM Hunter rows.
- **Scope.** The DOM Hunter scope is independent of the global
  Reqlore scope. Set it explicitly in *Settings* — empty means
  *every host*, which is rarely what you want.

## Engines

Not applicable. DOM Hunter only consumes traffic the browser
generates. The six request engines (httpx, raw, curl-cffi, curl
renderer, h3, hpack) are *not* involved.

## Keyboard map

Globals (Reqlore web UI):

- `Alt`+`7` — open DOM Hunter findings (`accesskey="7"` on the nav
  link, after the badge-bearing label).
- `1`–`6` / `8`–`9` / `0` — the other module nav accesskeys
  (Dashboard, Proxy, History, Repeater, Intruder, Scanner, Decoder,
  JWT, Settings, Help). See [KEYBINDINGS.md](../KEYBINDINGS.md).

Browser extension (rebindable at `about:addons` → gear → *Manage
Extension Shortcuts*):

- `F12` then `→` until you reach **DOM Hunter** — DevTools panel.
- `Ctrl`+`Shift`+`D` — open the sidebar.
- `Ctrl`+`Alt`+`S` — toggle hooks on the current tab and reload it.
- `Ctrl`+`Alt`+`F` — open `/dom-hunter/` in a new tab.

Within any DOM Hunter page, `Tab` order is skip-link → top nav →
heading → filter form → action buttons → table rows. There are no
focus traps and no custom widgets.

## Accessibility notes

- All findings/messages tables are real `<table>` with `<caption>`
  and `<th scope="col">`; screen readers announce row + column on
  navigation.
- Severity is conveyed by **both** a text label and a background
  colour — never colour alone.
- Every sink and source has a plain-language explanation stored
  server-side in `SINKS` / `SOURCES` (see
  [reqlore/dom_hunter/__init__.py](../../reqlore/dom_hunter/__init__.py)).
  The detail page renders these next to the technical id so a
  non-JavaScript reader still understands the finding.
- The DevTools panel and sidebar both expose a single
  `role="status" aria-live="polite"` region (`#live`) for
  announcements like *"New finding: innerHTML from location.hash
  (high)."* No competing live regions.
- The Options page locks down its inputs (`readonly` + visible
  status text) when `storage.managed` provides values — this happens
  automatically under `reqlore browser --project`.
- Focus rings are 3 px and respected on every focusable control;
  contrast ≥ 7:1 (AAA) on all DOM Hunter views.

## Recipes

### 1. Surface a hash-based DOM XSS quickly

1. `reqlore browser --project lab.rlr --url http://127.0.0.1:8787/`
2. *DOM Hunter → Settings*: scope = `*.target.tld`, tick
   *auto-inject `location.hash`*, **On**.
3. Visit any page on the target. The agent rewrites the fragment to
   include the canary on each navigation; `innerHTML` /
   `document.write` / `eval` invocations that ingest the hash fire
   immediately and show up in the DevTools panel.

### 2. Pick out only canary-bearing `postMessage` traffic

1. Browse to a page that uses cross-frame messaging.
2. Open `/dom-hunter/messages`, tick **Only canary**.
3. The remaining rows are messages where the sender included a
   string controlled by the URL fragment (one of the auto-inject
   targets) — those are usually the interesting ones for
   client-side trust boundary review.

### 3. Verify a manual payload using the test harness

`extensions/dom-hunter/tests/test_target.html` deliberately wires
four source→sink flows (`hash → innerHTML`, `hash → eval`,
`postMessage → innerHTML`, `window.name → document.write`). Open it
in the managed Firefox at:

```
file:///D:/TechBooks/reqlore/extensions/dom-hunter/tests/test_target.html#<paste-canary-here>
```

You should see four rows appear in `/dom-hunter/` within a second.
If none appear, the tracer is not enabled or the page is out of
scope — fix in *Settings*.

### 4. Drive the bridge directly (no browser)

Grab the bridge token from *DOM Hunter → Settings* (it is shown in
full on that page), then:

```sh
curl -s http://127.0.0.1:8787/dom-hunter/__bridge/config \
     -H "X-DOMHunter-Token: <paste-token>" | jq .
```

Useful in CI to assert the canary changes after `rotate_canary` or
to mirror findings into another tool.

### 5. Reset everything for a fresh engagement

1. *DOM Hunter → Settings* → **Rotate canary**, **Rotate token**.
2. *DOM Hunter* index → **Clear findings**.
3. *DOM Hunter → Messages* → **Clear messages**.
4. `reqlore browser --project my.rlr` — re-launches Firefox with the
   new policy so the extension picks up the new token without you
   touching `about:addons`.

### 6. Force-disable tracing on a single noisy tab

In the DevTools *DOM Hunter* panel, choose **Off** under *Tracer on
this tab* and submit — the agent stops hooking for that tab only
(`browser.storage.local["dom_hunter.tabOff"][tabId] = true`). Other
tabs continue tracing. Closing the tab forgets the flag
automatically.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No *DOM Hunter* DevTools tab | You launched Firefox **without** `--project`, so the policy did not include the XPI. | `reqlore browser --project <foo.rlr>`. Check `about:policies` for `ExtensionSettings → reqlore-dom-hunter@reqlore.local`. |
| Findings on a page but nothing in Reqlore | Bridge token mismatch — usually because you rotated it but didn't relaunch Firefox. | Rotate again, then `reqlore browser --project <foo.rlr>` to re-emit the policy. |
| Options page is editable when it should be locked | `storage.managed` was not delivered — the `3rdparty → Extensions` policy block is missing. | Open `about:policies` and confirm the block; if absent, relaunch Reqlore with `--project`. |
| Page enforces `Trusted Types` and the agent throws | Expected. DOM Hunter still records the *attempt* in `dom_hunter_findings`; the assignment just doesn't execute. | Use a Trusted Types-aware payload (sink-specific) and re-test. |
| Live updates stop arriving in the DevTools panel | The panel filters by `inspectedWindow.tabId`. Reloading or navigating that tab clears the local view; new rows still appear. | Click **Refresh** in the panel or switch tabs and back. |
| `extension: DOM Hunter auto-installed for project` line missing from `reqlore browser` log | XPI build failed (usually because the source tree is missing). | Re-check `extensions/dom-hunter/manifest.json` exists; logs the actual `FileNotFoundError` immediately above. |

## CLI equivalents

DOM Hunter is browser-driven; there is no headless tracer. The only
operation the CLI exposes is:

- `reqlore browser --project <foo.rlr>` — force-installs the
  extension and seeds bridge URL + token via Firefox enterprise
  policies. The same command relaunches the browser with the
  current values after any rotation.

Settings rotations, clearing, and reading the bridge token are
web-only today; the token is shown in full at
`/dom-hunter/settings`.

## Storage footprint

All data is persisted into the project's SQLite `.rlr` file.

### Tables

```
CREATE TABLE dom_hunter_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    page_url     TEXT NOT NULL DEFAULT '',
    frame_url    TEXT NOT NULL DEFAULT '',
    sink         TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'medium',
    canary_seen  INTEGER NOT NULL DEFAULT 0,
    value        TEXT NOT NULL DEFAULT '',
    stack        TEXT NOT NULL DEFAULT '',
    dedupe_key   TEXT NOT NULL,
    hit_count    INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX idx_dom_hunter_dedupe ON dom_hunter_findings(dedupe_key);
CREATE INDEX        idx_dom_hunter_ts     ON dom_hunter_findings(ts);
CREATE INDEX        idx_dom_hunter_sev    ON dom_hunter_findings(severity);

CREATE TABLE dom_hunter_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    page_url      TEXT NOT NULL DEFAULT '',
    origin        TEXT NOT NULL DEFAULT '',
    data          TEXT NOT NULL DEFAULT '',
    has_canary    INTEGER NOT NULL DEFAULT 0,
    handler_stack TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_dom_hunter_msg_ts ON dom_hunter_messages(ts);
```

Dedupe is server-side: `sha256("{sink}|{source}|{page_url}|{stack-top-frame}|{c|n}")`.
Re-inserts of an existing key bump `hit_count` and set `canary_seen
:= max(old, new)` instead of creating a new row.

### `project_state` keys

| Key | Purpose | Default |
|---|---|---|
| `dom_hunter_enabled` | `"1"` / `"0"` — master tracer switch. | `"0"` |
| `dom_hunter_canary` | `rqdomh<12-hex>` per-project canary. | generated on first read |
| `dom_hunter_token` | URL-safe 32-byte bridge token. | generated on first read |
| `dom_hunter_scope` | Comma-separated host list (`*.example.com` allowed). | empty = all hosts |
| `dom_hunter_auto_inject` | Comma list of source ids: `location.hash`, `location.search`, `window.name`, `document.referrer`. | empty |

### Truncation caps (enforced server-side in
[reqlore/web/blueprints/dom_hunter_bp.py](../../reqlore/web/blueprints/dom_hunter_bp.py))

| Field | Max |
|---|---|
| `page_url`, `frame_url` | 2 KiB |
| `value` | 4 KiB |
| `stack` | 8 KiB |
| `origin` | 256 B |
| `data` (postMessage) | 4 KiB |
| `handler_stack` | 4 KiB |
| `__bridge/findings.json?limit=` | 200 |

## See also

- [Extension README](../../extensions/dom-hunter/README.md) — install
  flow, file layout, manifest details.
- [browser-launcher.md](../browser-launcher.md) — how
  `reqlore browser` provisions the managed Firefox profile,
  including the `ExtensionSettings` and `3rdparty.Extensions`
  policy blocks DOM Hunter depends on.
- [ACCESSIBILITY.md](../ACCESSIBILITY.md) — Reqlore's WCAG 2.2 AAA
  baseline; DOM Hunter complies with every requirement listed there.
- [SECURITY.md](../SECURITY.md) — why the bridge endpoints are CSRF-
  exempt and how the token authenticates them instead.
