# Reqlore — Accessibility Specification

Reqlore targets **WCAG 2.2 Level AA** as a minimum and intentionally exceeds it where the pentesting workflow demands it (long sessions, dense data, time-sensitive prompts).

## Conformance commitments

- Every UI screen passes an automated audit using `axe-core` invoked via Playwright (CI gate).
- Every release is manually exercised end-to-end with **NVDA 2024+ on Firefox**, **Orca on Firefox**, and **VoiceOver on Safari** before tagging.
- The keyboard map is the ground truth: any action reachable by mouse is reachable by keyboard with a documented shortcut and a menu item.

## Patterns

### Page skeleton (`base.html`)

```html
<!doctype html>
<html lang="en">
  <head>... CSP, viewport, no-script fallback ...</head>
  <body>
    <a class="skip" href="#main">Skip to main content</a>
    <header role="banner">
      <h1>Reqlore</h1>
      <nav aria-label="Modules">...</nav>
    </header>
    <main id="main" tabindex="-1">{% block main %}{% endblock %}</main>
    <footer role="contentinfo">...</footer>
    <div id="sr-live" aria-live="polite" aria-atomic="true" class="visually-hidden"></div>
  </body>
</html>
```

- One `<h1>` per page (the module name). No skipped heading levels.
- `<main id="main" tabindex="-1">` so the skip-link moves focus, not just scroll.
- Live region is `polite`, **never** `assertive` (assertive interrupts SR speech).

### Forms

- Every `<input>`, `<select>`, `<textarea>` has a `<label for>` (no placeholder-as-label).
- Required fields: `required aria-required="true"` + visible `*` plus the word "(required)" in the label.
- Errors: list inside a `<div role="alert">` at the top of the form, each item links to the offending field; that field gets `aria-invalid="true"` and `aria-describedby` pointing to the inline error text.
- Buttons: `<button type="submit">` with descriptive text. Never `<a class="button">` for actions.

### Tables

- `<table>` with `<caption>` describing what it shows and how many rows.
- `<th scope="col">` and (when needed) `<th scope="row">`.
- Sortable columns: header contains a `<button>` (not a click handler on `<th>`); the button has `aria-sort="ascending|descending|none"` and the table caption announces "Sorted by ..." via the live region after a sort.
- "Read as list" toggle: re-renders the same data as `<dl>` per row inside `<section>` with row headings (some SRs handle this better than tables).

### Per-column filter menus (History)

The `/history/` table is the most data-dense surface in Reqlore — seven
filterable columns plus row actions plus a poll-driven live region.
The filter UI is rebuilt as **per-column disclosure menus** rather than
a single top-of-page form, with these AAA-aligned commitments:

- **Single interactive control per `<th>`.** Each filterable header
  contains exactly one `<details><summary>` button. The summary
  carries an `aria-label` like *"Method filter; active: GET, POST"*
  so screen readers always announce both the column and the current
  state — colour and the `●` glyph are redundant signals (SC 1.4.1
  *Use of Colour*).
- **Native `<details>` first; JS only enhances.** Native disclosure
  works without JavaScript: keyboard activation, toggle, and focus
  order all come from the browser. The JS layer adds *only*
  Escape-to-close (with focus restoration to the summary),
  click-outside-to-close, "open one closes the others", and
  auto-focus the first input on open. With JS off, the menus still
  open / close and a fallback **Apply filters** button submits.
- **No auto-submit on change.** Toggling a checkbox / typing into a
  text input never changes the URL implicitly; commit is explicit
  (Enter, the fallback Apply button) — required by SC 3.2.5
  *Change on Request*.
- **Single wrapping `<form>`.** The `<table>` lives inside one
  `<form method="get" role="search" aria-label="History filters">`,
  so pressing Enter from any column commits *every* column's draft
  state in a single navigation — no silent loss of intent.
- **44 × 44 px target sizes** on every summary toggle, input,
  toolbar link, and the fallback Apply button (SC 2.5.5 AAA).
- **Multi-select groups** are wrapped in `<fieldset><legend>Match any
  of</legend>` so the group name is announced once with each option.
- **Defence-in-depth validation.** The blueprint clamps `method` to
  a fixed whitelist, validates `status` tokens against
  `^[1-5]xx$|^[1-9]\d{2}$`, coerces numeric ranges through `int()`,
  and rejects unknown `host_mode` values — even though the storage
  layer already binds with `?` placeholders.
- **Visible Apply / Cancel buttons + keyboard hint.** Every open
  menu renders an in-panel **Apply** submit button (commits all
  columns) and a **Cancel** button (closes, restores focus), plus a
  screen-reader-only `<p class="visually-hidden">` reading *"Press
  Enter or Apply to update the table. Escape cancels and closes
  this menu. Arrow up and arrow down move between options."* The
  hint is `visually-hidden` because the same contract is already
  visible to sighted users via the labelled buttons — repeating it
  on screen would be noise. The commit mechanism is therefore
  never hidden behind invisible keystrokes — sighted, mouse,
  keyboard, and screen-reader users all see / hear the same contract
  (SC 3.2.4 *Consistent Identification*, SC 3.3.2 *Labels or
  Instructions*).
- **Tab focus trap inside the open menu.** While a menu is open the
  JS layer cycles Tab / Shift+Tab within the panel's controls + Apply
  + Cancel. Screen-reader users cannot accidentally walk past the
  menu into the next column header or table row and lose their
  place. The only ways out are Esc / Cancel (closes without
  committing) or Enter / Apply (commits and reloads). With JS off
  the menus remain plain `<details>` and Tab walks normally — the
  trap is a JS-only enhancement on top of working baseline.
- **Screen-reader virtual cursor trap (modal dialog upgrade).** On
  open the panel becomes `role="dialog" aria-modal="true"
  aria-labelledby="<summary id>" tabindex="-1"` and the summary
  gets `aria-haspopup="dialog" aria-expanded="true"`. NVDA, JAWS and
  VoiceOver honour `aria-modal` by switching into focus / forms
  mode when entering the dialog, so the virtual cursor stays inside
  — the same "you cannot read past me" semantics the row Actions
  menu gets from its `role="menu"` upgrade. We use `dialog` rather
  than `menu` because the panel contains form controls (checkboxes,
  text inputs, radios, numeric ranges), and `menu` / `menuitem`
  would be the wrong semantics for those. On close the panel
  reverts to `role="group"` and `aria-expanded` flips back.
- **Arrow-key roving inside the panel.** ArrowDown / ArrowUp / Home
  / End move focus between the panel's focusable items (checkboxes,
  buttons, links) with wrap. Controls whose own arrow keys carry
  meaning are explicitly excluded so they keep their native
  behaviour: text and number inputs (caret / increment), `<select>`
  / `<textarea>` (caret / value), and radio groups (native group
  navigation). ArrowLeft / ArrowRight are never intercepted. The
  modal-dialog upgrade above ensures the SR virtual cursor cannot
  drift past the panel, so arrow-key roving works consistently in
  both focus and browse modes.
- **Filter UI persists across reload.** The `<table>` and its
  filter `<thead>` always render — even when the active filters
  match zero rows. An empty result set shows a "No requests match
  the current filters. Clear all filters to see every request."
  message inside the otherwise-empty `<tbody>`, with a link back to
  `/history/`. Without this, a too-strict filter would hide the
  very controls the user needs to recover, leaving them no
  keyboard-only escape (SC 3.3.3 *Error Suggestion*, SC 3.3.4
  *Error Prevention*). URL parameters round-trip into every input's
  `value` / `checked` attribute, so manual reload, the auto-refresh
  poller, and the "Refresh now" link all preserve filters until the
  user explicitly clears them.
- **SR position preserved across commits.** The wrapping form opts
  into the global focus-restore baton via
  `data-focus-after-submit="#hist-table"` (see "Focus restoration
  after navigation" below), so applying a filter, pressing Enter
  inside a numeric range, or letting auto-refresh fire all return
  the SR virtual cursor to the data table rather than the page
  masthead.

Verified by [`test_history_filters.py`](../reqlore/tests/unit/test_history_filters.py).

### Tabs / panels

- We avoid ARIA tabs widget except where it genuinely helps. Default: separate pages or a `<details>` per panel.
- When ARIA tabs are used: full APG pattern (`role="tablist"`, `role="tab"`, `role="tabpanel"`, arrow-key navigation, `aria-selected`).

### Dialogs

- Avoided whenever possible — full-page navigation is more reliable for SR users.
- When required (intercept prompt): `role="dialog" aria-modal="true" aria-labelledby="..." aria-describedby="..."`, focus trapped within, `Esc` closes, focus restored to trigger.

### Live updates

- Intercept queue page polls server via fetch every 2 s; **only the count and "new since you opened this page" message update** in the live region — never a full table re-render.
- Long-running operations (Intruder, scanner) provide a `<progress>` with `aria-valuetext` containing a human sentence ("Processed 142 of 500 payloads, 3 hits so far").

### Colour & contrast

- Body text ≥ 4.5:1; large text ≥ 3:1; UI components and focus indicator ≥ 3:1.
- Information is never carried by colour alone — every status uses an icon, a word, or both.
- Three themes shipped: **Light**, **Dark**, **High-contrast** (WHCM-compatible, no background images, all borders 2px solid).

### Focus

- Visible focus ring on every interactive element: 3px outline, `outline-offset: 2px`, contrast ≥ 3:1.
- Focus is never trapped (except modal dialogs).
- Focus order matches reading order (no `tabindex > 0`).

### Focus restoration after navigation

Most Reqlore screens are server-rendered: filtering, paginating,
sorting, and committing edits all submit a `GET` form that triggers
a full page reload. Browsers default to parking focus on `<body>`
after any navigation, which means screen-reader users hear the page
title, the skip-link, the masthead, and the module nav re-spoken
**every** time they apply a filter — a 10–20 second tax on what
should be an instant action. Reqlore's global focus-restore baton
collapses that to zero.

How it works:

- Any `<form>` may opt in by declaring
  `data-focus-after-submit="<css-selector>"`. On submit the global
  handler in [`reqlore.js`](../reqlore/web/static/reqlore.js)
  serialises `{path, sel, ts: Date.now()}` into `sessionStorage`
  under the key `reqloreFocusAfterNav`.
- After the new page loads, an IIFE reads-and-clears the entry. If
  the path matches and the timestamp is fresh (≤ 30 s), it locates
  the target via `querySelector`, adds `tabindex="-1"` if the
  element isn't natively focusable, and calls
  `target.focus({preventScroll: true})` inside `requestAnimationFrame`.
- The 30 s freshness window prevents stale entries from hijacking
  focus on unrelated subsequent navigations (back button, bookmark,
  copy-pasted URL).
- Programmatic reloads (auto-refresh, "Refresh now" links) call
  `window.Reqlore.stashFocusTarget(selector)` directly to opt into
  the same flow.

This is **opt-in per form, not global** — pages that genuinely want
focus at `<main>` (e.g. submitting a "create new" form that lands
on a fresh detail screen) simply omit `data-focus-after-submit` and
inherit the original `<main>`-focus behaviour. The History filter
form opts in for `#hist-table` so applying any filter, hitting Enter
in a numeric range, or letting auto-refresh fire all return the SR
virtual cursor to the table — preserving the user's place across
the entire data-exploration loop.

Verified by `test_filter_form_opts_into_focus_restoration` and the
auto-refresh / Refresh-now wiring tests in
[`test_history_filters.py`](../reqlore/tests/unit/test_history_filters.py).

### Motion & timing

- `prefers-reduced-motion: reduce` disables all animations.
- No time limit on any user action. If a session would expire (long Intruder run), we present an "Extend" button before timeout.
- Audio cues: off by default; per-event volume; respects OS "Do Not Disturb".

### Reading-order alternatives

- Every dense table view has a "Read as list" toggle (announced via live region when activated).
- Verbosity profile (per-project): Concise / Standard / Verbose. Controls how much explanatory text appears alongside data.

### Keyboard

- Global JS shortcuts use **modifier + letter** (never single letter —
  single letters collide with screen-reader browse-mode quick-nav).
- Per-page action buttons (e.g. the Proxy intercept-detail "Forward edited"
  / "Forward as-is" / "Drop" bar and the "Send to..." list) use HTML
  [`accesskey`](https://developer.mozilla.org/docs/Web/HTML/Global_attributes/accesskey)
  attributes instead of JS shortcuts. The browser handles `accesskey`
  **before** the screen reader's browse-mode layer, so the shortcut works
  in NVDA without disabling browse mode. The activation modifier varies by
  browser (Alt on Chrome/Edge, Alt+Shift on Firefox, Ctrl+Alt on macOS) —
  this is documented per page and surfaced in the `<u>` underline shown on
  the access-key letter.
- Press `?` anywhere to open a full keyboard map page.
- Map is editable in Settings.

## Testing

| Check | Tool | When |
|---|---|---|
| axe-core ruleset | playwright + `axe-core` | every CI run |
| Tab-order spot check | manual | every PR |
| NVDA full run | manual | every release |
| Orca full run | manual | every release |
| VoiceOver full run | manual | every release |
| Contrast | automated via `reqlore.a11y.contrast` | every theme change |
| Reduced motion | manual | every animation change |

## What we will refuse to ship

- Inline `style="..."` (breaks user stylesheets).
- Custom focus styles that rely on `outline: none` without a replacement.
- Drag-and-drop without a keyboard equivalent.
- Mouse-only context menus.
- Auto-focusing arbitrary fields on page load (only after user explicit action).
- Pop-ups, toasts, or notifications without a corresponding entry in a persistent log page.

---

## Appendix — WCAG 2.1 AAA-strict patterns we apply

Reqlore's baseline target is WCAG 2.2 AA, but the pentesting workflow
(long sessions, dense data, time-sensitive prompts, screen-reader-heavy
users) pulls us toward AAA on most criteria. The reliability plan
(Phase 9) added an automated structural matrix —
[`test_wcag_aaa.py`](../reqlore/tests/unit/test_wcag_aaa.py) — that
runs against every blueprint route on every test run and asserts the
patterns below.

### 1.4.6 Contrast (Enhanced)

- Body text ≥ **7:1** (not just AA's 4.5:1) in all three themes.
- Large text ≥ **4.5:1** (not just AA's 3:1).
- Verified by `reqlore.a11y.contrast` against every palette swap.

### 1.4.8 Visual Presentation

- Max line length **80 characters** for body prose.
- No full-justified text (avoids river-of-whitespace).
- Pages remain usable when zoomed to 200% with no horizontal scroll.

### 2.1.1 / 2.1.3 Keyboard (No Exception)

- Every action reachable without a pointer.
- **No JS-only code paths.** Auto-refresh uses
  `<meta http-equiv="refresh">`, not `setInterval`.
- Live updates use ARIA live regions, never focus-stealing.

### 2.2.2 Pause, Stop, Hide

- Any auto-updating region offers a "stop refresh" toggle. Example:
  the Intruder detail page's `?auto=1` server-driven refresh has a
  visible **Stop auto-refresh** link rendered on every refresh.

### 2.2.3 No Timing

- No time limit on any user action.
- Long-running operations (Intruder, scanner) show a `<progress>`
  with `aria-valuetext` containing a human sentence ("Processed 142
  of 500 payloads, 3 hits so far").
- If a session would expire, we present an "Extend" button before
  timeout.

### 2.2.4 Interruptions

- Interruptions (audio cues, status updates) are user-suppressible
  in [Settings](modules/settings.md).
- **History live region** (`/history/` "*N new requests*" indicator)
  only updates when the count *changes*. The poll runs every 2.5 s but
  the live region is repainted exclusively when `newCount` differs
  from the previously announced value (`lastAnnouncedCount` guard);
  identical-count polls are silent. The user-actionable **Refresh now**
  link is rendered as a *sibling* of the `role="status"` element, not
  inside it, so the link's label never enters the live region. See
  [history.md § Live auto-refresh](modules/history.md#live-auto-refresh).
- **Proxy held-queue live region** (`/proxy/` "*N new intercept(s)*"
  indicator) uses the **same `[data-live-refresh]` widget** as History
  \u2014 same dedup, same sibling-link structure, same opt-in checkbox
  default OFF. The `/proxy/intercept/count` endpoint mirrors the page's
  active column filters and accepts a `since` cursor so a `kind=response`
  view never re-announces unrelated request-side holds. Replaces the
  earlier `data-intercept-watch` poller that reloaded the page on every
  count change with no opt-in and no live-region announcement. See
  [proxy.md \u00a7 Live auto-refresh](modules/proxy.md#live-auto-refresh).

### 2.3.3 Animation from Interactions

- `prefers-reduced-motion: reduce` is honoured by all built-in
  animations.

### 2.4.8 Location

- Every page renders a breadcrumb trail in `<nav aria-label="Breadcrumb">`.

### 2.4.9 Link Purpose (Link Only)

- Every `<a>` has a label that makes sense out of context — no bare
  "click here" / "read more". Verified by the structural matrix.

### 2.4.10 Section Headings

- Every fieldset, dialog, or content group has a real `<h2>` / `<h3>`,
  not a styled `<div>`.
- Heading levels are monotonic (no skipping h2 → h4).
- Verified by `test_wcag_aaa.py::test_heading_hierarchy_is_monotonic`.

### 3.1.3 Unusual Words

- Pentesting jargon (SSRF, JWT, CSRF, smuggling, etc.) is defined on
  first use; each module page repeats the definition in its
  *Background* section.

### 3.1.5 Reading Level

- The plain-language response summariser targets a lower secondary
  education reading level for status descriptions.

### 3.2.5 Change on Request

- No automatic context changes. Forms submit POST → 303 redirect (PRG
  pattern); the user always presses a button.
- **History per-column filter menus** never auto-submit on change.
  Toggling a checkbox / typing into a text input mutates the form's
  draft state in the page; the URL only changes when the user presses
  Enter, clicks **Apply filters**, or activates one of the column
  controls that submits via `<input type="submit">`. The whole table
  is wrapped in a single `<form id="hist-filters" role="search">` so
  pressing Enter inside any column's menu commits *every* column's
  draft state in one navigation. The auto-refresh toggle on the same
  page is OFF by default for the same SC.

### 3.3.5 Help (Context-Sensitive)

- Every new form control has a `<label>` plus `aria-describedby`
  pointing at a one-sentence hint.

### 4.1.3 Status Messages

- Runner state changes (paused / resumed / cancelled / done) go to
  `role="status"` (polite) or `role="alert"` (assertive) regions, not
  raw flash messages.

### Find-in-body (no-JS, AAA-clean)

Long request / response / evidence / payload / transcript bodies on
**History detail** (request and response merged with visible section
markers — one Find box covers both), **Repeater** (response side),
**Intercept detail**, **Scanner finding detail** (evidence and payload
merged with visible section markers — one Find box covers both),
**WebSocket transcript** and **Macros detail** (JSON definition)
carry a server-side find widget powered by
[`reqlore.a11y.find_in_text`](../reqlore/a11y.py) and the shared
[`templates/_find.html`](../reqlore/web/templates/_find.html) macros.
Browser Ctrl+F cannot search inside an editable `<textarea>`, and a
JS incremental-find would violate 2.2.2 + 3.2.5, so the only
AAA-clean answer is a GET form that re-renders the page with each
hit wrapped in `<mark id="prefix-mN">`, a `role="status"` sentence
("3 matches for \"admin\" in request body."), and a `<nav>` of
"Match N of M in {section} (line L)" anchor links. The textarea
above the marked-up `<pre>` on Intercept-detail stays untouched, so
the edit form remains usable.

The pattern hits 2.1.1 (no JS required), 2.4.9 AAA (link purpose
out of context — each match link reads as a full sentence), 2.4.10
AAA (real `<h3>`/`<h4>` headings on the form, the jump list, and
the marked-up body), 3.2.5 AAA (page only changes when the user
submits) and 4.1.3 (status region announces the count). See
[`test_a11y_find.py`](../reqlore/tests/unit/test_a11y_find.py),
[`test_history_find_smoke.py`](../reqlore/tests/unit/test_history_find_smoke.py),
[`test_repeater_find_smoke.py`](../reqlore/tests/unit/test_repeater_find_smoke.py),
[`test_intercept_find_smoke.py`](../reqlore/tests/unit/test_intercept_find_smoke.py),
[`test_scanner_find_smoke.py`](../reqlore/tests/unit/test_scanner_find_smoke.py),
[`test_ws_find_smoke.py`](../reqlore/tests/unit/test_ws_find_smoke.py)
and
[`test_macros_find_smoke.py`](../reqlore/tests/unit/test_macros_find_smoke.py).

### Structural matrix — what the test enforces

[`test_wcag_aaa.py`](../reqlore/tests/unit/test_wcag_aaa.py) walks
every blueprint route via `app.url_map.iter_rules()` and asserts each
of these for the rendered HTML:

- Exactly one `<h1>`.
- Monotonic heading levels (no skipped h2 → h4 jumps).
- `<main id="main">` landmark present, and the skip-link points to it.
- `<label for="…">` covers every input / select / textarea (or
  `aria-label` / `aria-labelledby` when a visible label would be
  redundant — checkbox toggles in dense tables).
- No `style="outline: none"` anywhere.
- No `tabindex` value greater than 0.
- Any `<button>` has visible text or an `aria-label`.
- Any `<a>` has visible text or an `aria-label`.
- `lang="en"` set on `<html>`.

Plus per-page assertions for the modules that ship dense interactive
state (Intruder detail page, Scanner coverage page, History list).

### Exemptions

The structural matrix has a documented skip-set for two intentional
404s — `auth.login` when no password is configured (the route 404s by
design so password-less installs don't render a login form) and
`comparer.export_diff` with no token / history arguments (the route
404s when called without a target).

If you add a new exemption, document it here and in the test's
`_SKIP` constant.

