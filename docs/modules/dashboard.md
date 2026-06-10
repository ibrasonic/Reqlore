# Dashboard — `/`

The landing page. Three cards:

1. **Project** — name, schema version, history / intercept / findings
   counts, proxy endpoint and running state.
2. **Quick links** — 26 buttons, one per module.
3. **Firefox launcher** — a copy-paste shell command to spin up a
   Reqlore-aware Firefox.

Pure view — no forms, no algorithms, no writes.

## Where it is

- **URL:** `/`
- **Nav:** *Dashboard* in the top bar.

## What's on the page

### Project card (`<dl>`)

| Term                | Value                                                        |
|---------------------|--------------------------------------------------------------|
| Name                | `project.meta().name`                                        |
| Schema version      | `project.meta().schema_version`                              |
| Recorded requests   | `project.history_count()`                                    |
| Held intercepts     | `project.intercept_count()`                                  |
| Scanner findings    | `project.findings_count()`                                   |
| Proxy               | `settings.proxy_host:settings.proxy_port` + `running` / `stopped` |

All values are refreshed per request via the context processor in
`reqlore/web/__init__.py` (L93-108). No caching, no JavaScript.

### Quick links card

A `<ul>` of 26 links — one per module. Use it as a top-level menu or
let muscle memory take over and use the Alt-N keyboard shortcuts
documented in [Keybindings](../KEYBINDINGS.md).

### Firefox launcher card

A `<pre>`-wrapped command:

```bash
reqlore browser --proxy-port <PORT> --url http://<HOST>:<PORT>/
```

Plus a note: first run downloads ~80 MiB of Firefox into the cache.
See [Browser launcher](../browser-launcher.md) for the full story.

## Routes

| URL  | Method | What it does          |
|------|--------|-----------------------|
| `/`  | GET    | Render the dashboard. |

## Accessibility notes

- Each card wrapped in `<section aria-labelledby="…-h">` paired with
  `<h2 id="…-h">`.
- `<h1>Dashboard</h1>` is the page heading.
- Project card uses `<dl>` / `<dt>` / `<dd>` (correct semantic for
  key/value).
- Quick links use plain `<ul>` of `<a>` — native list semantics.
- Nav header carries the live counts as `<span class="badge"
  aria-label="recorded requests">…</span>`.

## How it integrates

**Producer:** none. **Consumer:** none. Read-only view of the project.

## Recipes

### Verify the project file you're attached to

Scroll to the Project card. Name + schema version are both shown.

### Confirm the proxy is up

Project card → Proxy line → `running` or `stopped`.

### Jump to a tool by keyboard

Press `Alt+1` through `Alt+0` per [Keybindings](../KEYBINDINGS.md). The
Dashboard's quick-link card lists every module URL if you want to
right-click → open in new tab.

### Spawn a fresh Firefox

Copy the Firefox launcher command. Paste into a terminal. Browser
opens with the Reqlore CA pre-installed (first run downloads ~80 MiB).

### Sanity-check counts after a long run

After running [Intruder](intruder.md) / [Scanner](scanner.md), revisit
the Dashboard. Recorded requests / findings counts should match what
you expected.

## Storage footprint

**None.** Dashboard is purely a view of existing data.

## CLI

No CLI surface for the page itself, but the modules it links to are
mostly addressable via `reqlore <subcommand>` — see
[USAGE.md](../USAGE.md) for the catalogue.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Counts look stale                                        | No live updates — refresh per request only                              | Refresh the page (Ctrl+R).                                                                       |
| Proxy says "stopped" but you just started it              | Proxy state is read on page render                                      | Refresh; if still stopped, see [Proxy troubleshooting](proxy.md#troubleshooting).                |
| Quick link 404s                                          | Should never happen in a default install — every blueprint is registered | Check that the module's optional extra is installed if it's a soft dep.                          |
| Firefox launcher command fails                            | `reqlore browser` requires the `[browser]` extra                        | `pip install reqlore[browser]`; see [Browser launcher](../browser-launcher.md).                  |

## Test contract

- `reqlore/tests/unit/test_web_smoke.py::test_dashboard_loads` — GET `/` returns 200, "Dashboard" text, skip link, aria-live region.
- `reqlore/tests/unit/test_web_smoke_phase3.py::test_dashboard_shows_findings_count` — findings count appears after `add_finding()`.
- `…::test_nav_lists_scanner_reporter_plugins` — nav contains module links.
- `reqlore/tests/unit/test_web_smoke_phase4.py::test_dashboard_links_all_modules` — all phase-4 modules in `<a href="…">`.
- `reqlore/tests/unit/test_web_smoke_phase5.py::test_dashboard_links_phase5_modules` — phase-5 modules present.
