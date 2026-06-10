# Help — `/help/`

A single-page keyboard map (27 shortcuts), WCAG 2.2 AA accessibility
claim, and an *About* blurb. Alt+0 opens it from anywhere.

## Where it is

- **URL:** `/help/`
- **Nav:** *Help* (Alt+0).
- Static — no forms, no JS, no state.

## Sections

### Keyboard map

Two-column table (`Shortcut`, `Action`) covering:

- **Global nav** — `Alt+1` … `Alt+0` (ten tools).
- **Tab navigation** within modules.
- `?` to (re-)open the keyboard map.
- Context-specific shortcuts: Intercept detail, History detail,
  Intruder list/detail, New-attack form.

Full enumeration lives in [Keybindings](../KEYBINDINGS.md); the Help
page is a quick-reference embedded in the app for moments when you
can't tab-switch out.

### Accessibility notes

WCAG 2.2 Level AA claim. Bullets:

- Semantic HTML throughout (`<table>`, `<th scope="col">`,
  `<label for="…">`).
- Keyboard-only operation; visible 3 px focus indicator on every
  control.
- No color-only signalling.
- Live regions (`role="status"` flashes, `aria-live="polite"`
  screen-reader region).

### About

Brief project description — engines (httpx for normal traffic, raw for
byte-exact, mitmproxy for TLS interception), the GitHub URL, and a
note about how the project is licensed.

## Routes

| URL      | Method | What it does                |
|----------|--------|-----------------------------|
| `/help/` | GET    | Render the static page.     |

## Form fields

None — read-only page.

## Behaviour

`KEYMAP` is a 27-tuple list of `(shortcut, action)` strings declared in
`reqlore/web/blueprints/help_bp.py`. The template iterates the list
into table rows. There is no introspection of actual key handlers —
**the map is a hand-maintained source of truth**.

## Accessibility notes

- `<table>` with `<caption class="visually-hidden">`, `<th scope="col">` / `<th scope="row">`.
- Each section wrapped in `<section aria-labelledby="…-h">` paired with
  `<h2 id="…-h">` (`kb-h`, `a11y-h`, `about-h`).
- Shortcuts wrapped in `<kbd>` for native semantic + visual
  consistency.

## How it integrates

**Producers / consumers:** none. The page itself is a Send-to target
of sorts — Alt+0 from any page.

The `KEYMAP` list mirrors the `accesskey` attributes scattered across
other blueprints; **they must be kept in sync manually**.

## Recipes

### Find a shortcut

Open `/help/`, Ctrl+F in the browser. Or memorise the global
Alt+digit pattern.

### Add a new shortcut

1. Edit `KEYMAP` in `reqlore/web/blueprints/help_bp.py` — add
   `("Alt+X", "New feature")`.
2. In the blueprint that implements it, add `accesskey="x"` to the
   relevant button or link.
3. If it's a Send-to target, also update `reqlore/web/send_targets.py`
   so the order matches.
4. Add a test in `reqlore/tests/unit/test_intruder_accesskeys.py` (or
   similar) to lock the order in.

### Reference the keymap programmatically

```python
from reqlore.web.blueprints.help_bp import KEYMAP
print([k for k, _ in KEYMAP])
```

### Link to Help from a template

```html
<a href="{{ url_for('help.index') }}">View all keyboard shortcuts</a>
```

### Context-aware reading

`Alt+R` means **Repeater** globally but **Resume** in Intruder detail.
Same letter, different action depending on focus context — the table
notes the context for each row.

## Storage footprint

**None.** Static content; no `project_state` keys.

## CLI

No CLI surface.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Shortcut documented but doesn't work                     | `KEYMAP` and `accesskey` are out of sync                                | Confirm via DevTools that the target element has the expected `accesskey`; update the template or the map. |
| `Alt+R` does the wrong thing                             | Context-specific — Repeater vs Intruder Resume                          | Read the current page's row in the map; the action depends on context.                            |
| `?` doesn't open the keymap                              | No modal JavaScript is shipped (yet)                                    | Navigate to `/help/` manually (Alt+0).                                                            |
| Browser modifier differs                                  | Windows/Chrome `Alt+key`; Firefox `Alt+Shift+key`; macOS `Ctrl+Option+key` | Documented at the top of `/help/`; follow your browser's convention.                              |

## Test contract

- `reqlore/tests/unit/test_intruder_accesskeys.py::test_help_page_renders_intruder_shortcuts` — Alt+N (new attack) is listed on the Help page.

Help is also covered by the broader route-200 smoke tests.
