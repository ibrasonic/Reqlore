# Keyboard shortcuts

The canonical map is in `reqlore/web/blueprints/help_bp.py` (`KEYMAP`)
and is also rendered on the in-app [Help](modules/help.md) page (Alt+0).
The list below is verbatim plus the per-module audit.

## How browsers map `Alt+key`

| Browser                          | Modifier            | Example      |
|----------------------------------|---------------------|--------------|
| Chrome / Edge / Brave (Windows)  | `Alt`               | `Alt+R`      |
| Firefox (Windows / Linux)        | `Alt+Shift`         | `Alt+Shift+R`|
| Safari (macOS)                   | `Ctrl+Alt`          | `Ctrl+Alt+R` |
| Any browser (macOS)              | `Ctrl+Alt`          | `Ctrl+Alt+R` |

Where this doc says `Alt+R`, substitute your browser's modifier.

## Global navigation (always available)

| Shortcut | Action                       |
|----------|------------------------------|
| `Alt+1`  | [Dashboard](modules/dashboard.md) |
| `Alt+2`  | [Proxy](modules/proxy.md)         |
| `Alt+3`  | [History](modules/history.md)     |
| `Alt+4`  | [Repeater](modules/repeater.md)   |
| `Alt+5`  | [Intruder](modules/intruder.md)   |
| `Alt+6`  | [Scanner (passive)](modules/scanner.md) |
| `Alt+7`  | [Decoder](modules/decoder.md)     |
| `Alt+8`  | [JWT workbench](modules/jwt.md)   |
| `Alt+9`  | [Settings](modules/settings.md)   |
| `Alt+0`  | [Help / keyboard map](modules/help.md) |
| `Tab`    | Move to next focusable element |
| `?`      | Open the in-app keyboard map (Help) |

Source: `base.html` nav `accesskey` attributes; KEYMAP entries 1-12.

## Intercept detail (`/proxy/intercept/<id>/`)

| Shortcut | Action                             |
|----------|------------------------------------|
| `Alt+E`  | Forward edited                     |
| `Alt+A`  | Forward as-is                      |
| `Alt+P`  | Drop                               |
| `Alt+R`  | Send to [Repeater](modules/repeater.md) |
| `Alt+I`  | Send to [Intruder](modules/intruder.md) |
| `Alt+M`  | Send to [Comparer](modules/comparer.md) (side A) |
| `Alt+B`  | Send to [PoC builder](modules/poc.md) |
| `Alt+J`  | Send to [JWT workbench](modules/jwt.md) |
| `Alt+O`  | Send to [Decoder](modules/decoder.md) |

Source: `templates/proxy/intercept_detail.html`, lines L39 / L40 / L44 / L68.

## History detail (`/history/<id>/`)

| Shortcut | Action                             |
|----------|------------------------------------|
| `Alt+R`  | Send to [Repeater](modules/repeater.md) |
| `Alt+I`  | Send to [Intruder](modules/intruder.md) |
| `Alt+M`  | Send to [Comparer](modules/comparer.md) (side A) |
| `Alt+B`  | Send to [PoC builder](modules/poc.md) |
| `Alt+J`  | Send to [JWT workbench](modules/jwt.md) |
| `Alt+O`  | Send to [Decoder](modules/decoder.md) |

Source: `templates/history/detail.html` L25.

## Intruder list (`/intruder/`)

| Shortcut | Action               |
|----------|----------------------|
| `Alt+N`  | New attack          |

Source: `templates/intruder/index.html` L7.

## Intruder new-attack form (`/intruder/new/…`)

| Shortcut | Action               |
|----------|----------------------|
| `Alt+C`  | Create attack       |

Source: `templates/intruder/new.html` L215.

## Intruder detail (`/intruder/<id>/`)

| Shortcut | Action               |
|----------|----------------------|
| `Alt+S`  | Start / Restart attack |
| `Alt+P`  | Pause attack        |
| `Alt+R`  | Resume attack       |
| `Alt+C`  | Cancel attack       |
| `Alt+D`  | Delete attack       |
| `Alt+A`  | Apply filter        |

Source: `templates/intruder/detail.html` L35-L52, L123.

> **Context overlap**: `Alt+R` is "Send to Repeater" on Intercept /
> History detail, **but** "Resume attack" on Intruder detail. Same key,
> different action — the current page determines which fires.

## Scanner (`/scanner/`)

| Shortcut | Action               |
|----------|----------------------|
| `Alt+P`  | Run passive scan    |
| `Alt+A`  | Run active scan     |

Source: `templates/scanner/run.html` L31, L130.

## Send-to targets (canonical order)

The **Send to** menu on Intercept-detail and History-detail pages
renders these targets in this order with these access keys. Defined
in `reqlore/web/send_targets.py`:

| Slug       | Label                         | Access key |
|------------|-------------------------------|------------|
| `repeater` | Repeater                      | `r`        |
| `intruder` | Intruder                      | `i`        |
| `comparer` | Comparer (side A)             | `m`        |
| `poc`      | PoC builder                   | `b`        |
| `jwt`      | JWT workbench                 | `j`        |
| `decoder`  | Decoder                       | `o`        |

## Discovering the access key on a page

In the browser, hover any button — the access key is the underlined
letter in the label (when supported by the browser) or visible via
DevTools as the `accesskey="…"` attribute.

## Keeping the map honest

`KEYMAP` is **hand-maintained**. There's no live introspection of
template `accesskey` attributes. When you add a new shortcut:

1. Edit `KEYMAP` in `reqlore/web/blueprints/help_bp.py`.
2. Add `accesskey="x"` to the button / link in the template.
3. If it's a Send-to button, also update `reqlore/web/send_targets.py`
   so the order matches.
4. Add a test in `reqlore/tests/unit/test_intruder_accesskeys.py` (or
   similar) that locks the access key for that element.

The single test today —
`test_help_page_renders_intruder_shortcuts` — verifies `Alt+N`
appears on the Help page.
