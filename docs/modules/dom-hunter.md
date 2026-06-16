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

1. Create or open a project and start the UI + proxy:
   `reqlore both --project my.rlr`
2. In a second terminal, launch the managed browser **with the same
   project** so the extension auto-installs and is pre-configured:
   `reqlore browser --project my.rlr --url http://127.0.0.1:8787/`

   On the first run with `--project`, Reqlore downloads **Firefox
   Developer Edition** into `<cache>/firefox/devedition/<version>/`
   (≈ 80 MiB) instead of Release. This is intentional: the sideloaded
   DOM Hunter XPI is unsigned, and Release/Beta silently drop unsigned
   add-ons regardless of `xpinstall.signatures.required`. Dev Edition,
   Nightly, ESR, and Unbranded honour the pref. Override with
   `--channel release` if you have a signed build of the XPI.
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

#### How the *source* is attributed

When a sink fires with the canary in the value, the agent runs
`detectSource(value)` to figure out which DOM source(s) the canary
came from. It compares the value against the live content of every
readable source — also against `decodeURIComponent(...)` of each
variant, so a page that URL-decodes `location.hash` before piping
it into the sink still attributes back to `location.hash` instead
of getting lost. **Every** source whose content has verified
overlap with the value is reported, in precedence order, joined
with commas (e.g. `location.hash,location.search` when the user
has more than one auto-inject toggle on and the page reads more
than one of them). The precedence list:

1. `location.hash`
2. `postMessage` — last canary-bearing `MessageEvent.data` seen on the page
3. `window.name`
4. `document.referrer`
5. `location.search`
6. `document.cookie`
7. `location.pathname`
8. bounded scan of `localStorage` keys *(only when no live source matched)*
9. bounded scan of `sessionStorage` keys *(only when no live source matched)*
10. `unknown` — canary reached the sink but the agent could not match it
    back to any readable source (e.g. the page derived the value from a
    `fetch` response). The finding is still recorded.

Precedence is **display order**, not a tiebreaker: pure-DOM vectors
(hash, postMessage, window.name) appear before cross-cutting ones
(referrer, search, cookie, storage) so the channel a real attacker
would most naturally use shows first in the list — but every
channel the canary actually travelled through is recorded, so the
user who ticks every auto-inject toggle to test them at once sees
all of them on the finding. A leading `#` or `?` stripped by the
page before use is tolerated. The web UI renders each source as
its own `<code>` chip on the findings index and lists the
plain-language explanation per source on the detail page.

The `/dom-hunter/__bridge/report` endpoint validates each part of
a comma-joined `source` against `SOURCE_INDEX`; unknown parts are
dropped silently, and the field falls back to `"unknown"` if
nothing survives validation.

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
| **Auto-inject targets** | Check any of `location.hash`, `location.search`, `window.name`, `document.referrer` — the agent rewrites those sources on each in-scope page load so source→sink flows surface without you crafting payloads. `document.referrer` is read-only from JavaScript, so Reqlore implements it by splicing `rqdomh=<canary>` into the **`Referer` request header** at the MITM proxy (only when a Referer is already present; never synthesised). |
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
- The numeric module accesskeys are: `Alt`+`1` Dashboard, `Alt`+`2`
  Proxy, `Alt`+`3` History, `Alt`+`4` Repeater, `Alt`+`5` Intruder,
  `Alt`+`6` Scanner, `Alt`+`7` DOM Hunter, `Alt`+`8` JWT, `Alt`+`9`
  Settings, `Alt`+`0` Help. See [KEYBINDINGS.md](../KEYBINDINGS.md).
  Decoder no longer has a numeric shortcut; reach it from the nav.

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

`reqlore/dom_hunter/extension/tests/test_target.html` deliberately wires
four source→sink flows (`hash → innerHTML`, `hash → eval`,
`postMessage → innerHTML`, `window.name → document.write`). Open it
in the managed Firefox at:

```
file:///D:/TechBooks/reqlore/reqlore/dom_hunter/extension/tests/test_target.html#<paste-canary-here>
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

### 7. Prove a DOM Hunter finding with a custom payload

A DOM Hunter finding is **evidence the source feeds the sink**; it is
not yet a runnable PoC. Once a row appears, promote it to a real PoC
in five steps:

1. **Read the finding.** Open `/dom-hunter/finding/<id>` and write
   down four things:
   - **page URL** — where to navigate the victim browser.
   - **source** — which channel to load the payload through (see the
     attribution list above).
   - **sink** — what the page does with the value; this picks the
     payload shape (see the table below).
   - **stack top frame** — the function name + file/line that read the
     source. Useful for breakpoints and for the writeup.
2. **Pick a payload that matches the sink.** Replace the canary with a
   visible side effect (`alert(1)` is fine for a lab; for write-ups
   prefer `document.title='PWN-<finding_id>'` so the proof appears in
   the screenshot caption without needing a dialog).

   | Sink (from the finding) | Minimal payload | Notes |
   |---|---|---|
   | `Element.innerHTML`, `Element.outerHTML`, `Element.insertAdjacentHTML`, `Range.createContextualFragment`, `HTMLIFrameElement.srcdoc` | `<img src=x onerror=alert(1)>` | `<script>` does *not* execute via `innerHTML`; use an event-handler tag. |
   | `document.write`, `document.writeln` | `<script>alert(1)</script>` | Only before the page is closed; if the sink fires after `DOMContentLoaded`, fall back to the `<img onerror>` form. |
   | `eval`, `Function`, `setTimeout(string)`, `setInterval(string)` | `alert(1)` | Bare JS; no HTML wrapping. |
   | `Element.setAttribute(on*)` | `alert(1)` | The value of an `on*` attribute is JS source. |
   | `HTMLScriptElement.src`, `HTMLIFrameElement.src`, `location.href` | `javascript:alert(1)` | Modern Firefox blocks `javascript:` in `iframe.src`; host an attacker JS file and use that URL instead for those. |
   | `Worker`, `importScripts` | URL of a one-line attacker JS file (`self.postMessage('pwn')` or similar) | Same-origin or worker-allowed origin. |
   | `DOMParser.parseFromString` | `<img src=x onerror=alert(1)>` | Only runs once the parsed node is **inserted** into the live document; check the stack for the inserter and pair with `innerHTML`. |
3. **Inject through the same source channel** the finding used. The
   delivery method depends on the source:

   | Source | How to deliver the payload |
   |---|---|
   | `location.hash` | Edit the address bar: `https://target/page#<payload>` and press Enter. |
   | `location.search` | Edit the query string: `?q=<payload>` (URL-encode `<`, `>`, `"`, space). |
   | `location.pathname` | Navigate to a path the client router consumes verbatim, e.g. `/app/<payload>`. |
   | `document.referrer` | Open an attacker page on a separate origin whose body is a single `<a href="https://target/page?...">go</a>`; click it. The Referer header carries the attacker URL — encode the payload into a query param the attacker URL exposes. |
   | `window.name` | From an attacker page: `var w = window.open('https://target/page', 'name'); w.name = '<payload>';` then refresh the opened tab. |
   | `postMessage` | From an attacker iframe or opener: `target.contentWindow.postMessage('<payload>', '*')`. Use the **origin** the page's message handler accepts (often `*` in vulnerable code). |
   | `document.cookie` / `localStorage` / `sessionStorage` | Use DevTools → *Storage* on the same origin to write the value, then reload. These usually indicate a *stored* DOM XSS that needs prior taint. |
4. **Watch DOM Hunter** confirm the second hit. Your payload string
   does not contain `rqdomh…`, so `canary_seen` will be **no** on the
   new row — that is correct: the canary proved reachability, this row
   proves *execution* through the same sink. The `value` column will
   show your payload verbatim. If no new row appears, the page sanitised
   your payload but not the canary; switch to an alternative payload
   for the same sink from the table above.
5. **Capture proof.** Screenshot the page (`alert(1)` dialog, modified
   `document.title`, or the `<img>` 404 in DevTools Network) **and** the
   matching DOM Hunter row. Both are useful in a report: the alert
   proves execution to a non-technical reader; the DOM Hunter row
   proves the source→sink path to a technical reviewer.

Troubleshooting:

- *Payload appears in the DOM but does not execute.* Check the page's
  CSP in DevTools → Network → response headers. A `script-src` without
  `'unsafe-inline'` blocks event-handler payloads; a Trusted Types
  policy blocks `innerHTML` assignment entirely. Try a sink with no
  Trusted Types contract (`eval` if available, or `location.href` with
  `javascript:`).
- *Sink is `unknown` source.* Use the stack top frame from the finding
  to set a breakpoint, reload with the canary in every plausible
  source, and step until the canary value is read — that is your true
  source. Common cases: data came from `fetch` (server reflects your
  input), `IndexedDB`, or a deeply-cloned `postMessage` the agent
  missed because of structured-clone proxies.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No *DOM Hunter* DevTools tab | You launched Firefox **without** `--project`, so the policy did not include the XPI. | `reqlore browser --project <foo.rlr>`. Check `about:policies` for `ExtensionSettings → dom-hunter@ibrasonic.github.io`. |
| `about:policies` shows `ExtensionSettings` with **other** extensions but **not** `dom-hunter@…` (only `3rdparty` for our id is present) | A higher-precedence enterprise policy (typically `HKLM\SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings`, set by corporate IT or anti-malware software) replaced our `distribution/policies.json` entry wholesale. | Reqlore also **sideloads** the XPI into `<profile>/extensions/dom-hunter@ibrasonic.github.io.xpi` with `xpinstall.signatures.required=false`. The sideload only works on **Firefox Developer Edition, Nightly, ESR, or Unbranded** — Release/Beta enforce signing. `reqlore browser --project` now defaults to `--channel devedition` and auto-downloads Dev Edition for you, so this should Just Work. If you forced `--channel release` or pointed at a Release build via `--use-system`, switch back to Dev Edition. |
| Findings on a page but nothing in Reqlore | Bridge token mismatch — usually because you rotated it but didn't relaunch Firefox. | Rotate again, then `reqlore browser --project <foo.rlr>` to re-emit the policy. |
| Options page is editable when it should be locked | `storage.managed` was not delivered — the `3rdparty → Extensions` policy block is missing. | Open `about:policies` and confirm the block; if absent, relaunch Reqlore with `--project`. |
| Page enforces `Trusted Types` and the agent throws | Expected. DOM Hunter still records the *attempt* in `dom_hunter_findings`; the assignment just doesn't execute. | Use a Trusted Types-aware payload (sink-specific) and re-test. |
| Live updates stop arriving in the DevTools panel | The panel filters by `inspectedWindow.tabId`. Reloading or navigating that tab clears the local view; new rows still appear. | Click **Refresh** in the panel or switch tabs and back. |
| `extension: DOM Hunter auto-installed for project` line missing from `reqlore browser` log | XPI build failed (usually because the source tree is missing). | Re-check `reqlore/dom_hunter/extension/manifest.json` exists; logs the actual `FileNotFoundError` immediately above. |

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

- [Extension README](../../reqlore/dom_hunter/extension/README.md) — install
  flow, file layout, manifest details.
- [browser-launcher.md](../browser-launcher.md) — how
  `reqlore browser` provisions the managed Firefox profile,
  including the `ExtensionSettings` and `3rdparty.Extensions`
  policy blocks DOM Hunter depends on.
- [ACCESSIBILITY.md](../ACCESSIBILITY.md) — Reqlore's WCAG 2.2 AAA
  baseline; DOM Hunter complies with every requirement listed there.
- [SECURITY.md](../SECURITY.md) — why the bridge endpoints are CSRF-
  exempt and how the token authenticates them instead.
