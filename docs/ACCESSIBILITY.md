# Weblore — Accessibility Specification

Weblore targets **WCAG 2.2 Level AA** as a minimum and intentionally exceeds it where the pentesting workflow demands it (long sessions, dense data, time-sensitive prompts).

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
      <h1>Weblore</h1>
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

### Motion & timing

- `prefers-reduced-motion: reduce` disables all animations.
- No time limit on any user action. If a session would expire (long Intruder run), we present an "Extend" button before timeout.
- Audio cues: off by default; per-event volume; respects OS "Do Not Disturb".

### Reading-order alternatives

- Every dense table view has a "Read as list" toggle (announced via live region when activated).
- Verbosity profile (per-project): Concise / Standard / Verbose. Controls how much explanatory text appears alongside data.

### Keyboard

- Global shortcuts use modifier + letter (never single letter — collides with SR shortcuts).
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
| Contrast | automated via `weblore.a11y.contrast` | every theme change |
| Reduced motion | manual | every animation change |

## What we will refuse to ship

- Inline `style="..."` (breaks user stylesheets).
- Custom focus styles that rely on `outline: none` without a replacement.
- Drag-and-drop without a keyboard equivalent.
- Mouse-only context menus.
- Auto-focusing arbitrary fields on page load (only after user explicit action).
- Pop-ups, toasts, or notifications without a corresponding entry in a persistent log page.
