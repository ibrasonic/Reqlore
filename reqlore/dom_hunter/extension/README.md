# Reqlore DOM Hunter

Accessibility-first DOM-XSS source/sink tracer for the Reqlore-managed
Firefox browser. Functionally equivalent to Burp Suite's DOM Invader,
but driven entirely by native HTML controls, server-side findings, and
a DevTools panel built to meet WCAG 2.2 AAA where practical.

## Where you see it in the browser

| Surface | Open it with | What you see |
| --- | --- | --- |
| DevTools panel | `F12` -> **DOM Hunter** tab | Findings + postMessages for the current tab, live |
| Sidebar | `Ctrl`+`Shift`+`D` | Same findings, persistent next to the page |
| Toolbar popup | Click the DOM Hunter icon | Per-tab on/off, quick links |
| Options page | `about:addons` -> DOM Hunter -> Preferences | Reqlore base URL + bridge token (read-only when managed) |
| Reqlore web UI | Top nav: **DOM Hunter** | Full history, filtering, message log, settings |

Every surface uses semantic HTML, AAA-grade contrast, 44 CSS px touch
targets, 3 px focus rings, and a single live region for announcements --
no custom widgets, no focus traps, no ARIA roles fighting the platform.

## What it does

- Injects a small JavaScript agent at `document_start` into every in-scope page.
- Wraps dangerous sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `eval`, `Function`, `setTimeout`/`setInterval` with string args,
  `document.write`/`writeln`, `setAttribute(on*)`, `script.src`,
  `iframe.src`, anchor `href`).
- Watches every wrapped sink for the project's canary string.
- Logs every `postMessage` event with origin, data, and handler stack.
- Optionally injects the canary into `location.hash`, `location.search`,
  or `window.name` so source-to-sink flows surface immediately.
- POSTs findings and messages to Reqlore at
  `/dom-hunter/__bridge/report` with the per-project bridge token.

The agent never modifies the inspected page's accessible tree (no
overlays, no focus moves, no ARIA writes). It only wraps JavaScript
prototypes.

## Install

### Automatic (recommended)

Launch the Reqlore-managed browser with a project:

```sh
reqlore browser --project path/to/your.rlr
```

This downloads the Reqlore-managed Firefox build (first run only),
writes an enterprise policy that:

- Trusts the Reqlore CA, points the proxy at Reqlore.
- Force-installs DOM Hunter via `ExtensionSettings`
  (`installation_mode: "force_installed"` is exempt from Mozilla's
  signing requirement).
- Pre-fills the extension's bridge URL + bearer token via
  `3rdparty.Extensions` (read by the extension as
  `browser.storage.managed`).

You see the **DOM Hunter** tab in DevTools the moment Firefox
finishes starting. No options-page round-trip.

### Manual (for other browsers / profiles)

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on...**
3. Pick `reqlore/dom_hunter/extension/manifest.json`.
4. Open `about:addons` -> DOM Hunter -> Preferences and paste:
   - **Reqlore base URL** -- usually `http://127.0.0.1:8080`.
   - **Bridge token** -- shown in Reqlore at *DOM Hunter -> Settings*.

## Keyboard shortcuts (defaults)

| Shortcut | Action |
| --- | --- |
| `F12` | Open DevTools, then click the *DOM Hunter* tab |
| `Ctrl`+`Shift`+`D` | Open the DOM Hunter sidebar |
| `Ctrl`+`Alt`+`S` | Toggle tracing on the current tab and reload it |
| `Ctrl`+`Alt`+`F` | Open the Reqlore DOM Hunter findings page |

Rebind any of them at `about:addons` -> gear icon ->
*Manage Extension Shortcuts*.

## File layout

```
reqlore/dom_hunter/extension/
  manifest.json
  background/service_worker.js   bridge to Reqlore + shortcuts + per-tab state
  content/
    isolated.js                  ISOLATED world: fetches config, injects agent
    agent.js                     MAIN world: the actual sink + source hooks
  devtools/
    devtools.html / devtools.js  registers the DevTools panel
    panel.html / panel.js        the DevTools UI (findings + messages, live)
  ui/
    popup.html / popup.js        toolbar popup: per-tab on/off + links
    sidebar.html / sidebar.js    findings mirror (same data as the panel)
    options.html / options.js    Reqlore URL + bridge token configuration
    styles.css                   accessible stylesheet shared by all UI
  _locales/en/messages.json
  icons/icon.svg
```

## Limitations

- Pages enforcing `Trusted Types` will throw on the canary-bearing
  `innerHTML` assignments. DOM Hunter still captures the *attempt*
  as a finding; it just won't observe execution.
- Strict `Content-Security-Policy` on the target page does not block
  the agent (extensions bypass CSP for their own content scripts), but
  a CSP that forbids `eval` still applies to page code.
- The agent does not yet hook dedicated workers, service workers, or
  prototype-pollution sources. Those are planned for a later version.

## License

Apache-2.0. Same as Reqlore.
