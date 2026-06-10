# Settings — `/settings/`

Four per-project knobs (theme, verbosity, audio cues, opt-in update
check) plus a manual "check for updates" button. Everything else
(bind host, ports, password, session lifetime) is bootstrap-time —
environment variables or CLI flags, not the Settings UI.

## Where it is

- **URL:** `/settings/`
- **Nav:** *Settings* in the top bar (accesskey **9**).
- Per-project — values persist in the project's `.rlr` file.

## Quick start

1. Open `/settings/`.
2. Pick a **Theme** (system / light / dark / high-contrast).
3. Pick a **Verbosity** (concise / standard / verbose).
4. Optional: tick **Audio cues** (defaults off).
5. Optional: tick **Allow update check** so the *Check for updates now* button activates.
6. **Save**. Settings apply immediately — no restart.

## Routes

| URL                        | Method | What it does                                                                          |
|----------------------------|--------|---------------------------------------------------------------------------------------|
| `/settings/`               | GET    | Render the settings form pre-populated from `project_state`.                           |
| `/settings/`               | POST   | Whitelist-validate inputs, persist to `project_state`, 302 back to GET (PRG).          |
| `/settings/check-updates`  | POST   | Fetch the release manifest from GitHub and flash the comparison. Requires `update_check=1`. |

## Form fields (project-scoped)

| Panel        | Field          | Type     | Default      | Notes                                                                                                   |
|--------------|----------------|----------|--------------|---------------------------------------------------------------------------------------------------------|
| Theme        | `theme`        | radio    | `system`     | `system`, `light`, `dark`, `high-contrast`. Invalid values silently ignored.                              |
| Verbosity    | `verbosity`    | radio    | `standard`   | `concise`, `standard`, `verbose`.                                                                         |
| Audio cues   | `cues`         | checkbox | off (`0`)    | Stored as `"1"` / `"0"`. Some browsers suppress autoplay until you've clicked once on the page.            |
| Update check | `update_check` | checkbox | off (`0`)    | When `0`, the *Check for updates now* button is `disabled`. No automatic / background fetching ever.       |

Save flow:

1. POST whitelist-validates each field. Unknown values are dropped silently — the existing value stays.
2. `project.set_state(key, value)` writes through to the `project_state` SQLite table.
3. 302 to GET so a refresh doesn't resubmit.
4. Context processor re-reads `theme` / `verbosity` on the next request, so the theme flip is instant.

## Global settings (bootstrap-time only, not in the UI)

These come from environment variables, CLI flags, or the `Settings`
dataclass defaults at startup. Changing them requires a restart.

| Setting                            | Env var                       | Default      | Notes                                          |
|------------------------------------|-------------------------------|--------------|------------------------------------------------|
| `ui_host`                          | `REQLORE_UI_HOST`             | `127.0.0.1`  | UI listen address.                              |
| `ui_port`                          | `REQLORE_UI_PORT`             | `8787`       | UI listen port.                                 |
| `ui_unsafe_bind`                   | —                              | `False`      | `--unsafe-bind` CLI flag; the only way to bind a non-loopback UI address. |
| `proxy_host`                       | `REQLORE_PROXY_HOST`          | `127.0.0.1`  | Proxy bind. **Proxy is always loopback** — see [Proxy](proxy.md). |
| `proxy_port`                       | `REQLORE_PROXY_PORT`          | `8080`       | Proxy port.                                     |
| `require_password_on_unsafe_bind`  | —                              | `True`       | CLI guard; rejects `--unsafe-bind` without a password set. |
| `ui_password`                      | `REQLORE_PASSWORD`            | empty        | Plaintext password; hashed in-memory at startup. |
| `ui_password_hash`                 | `REQLORE_PASSWORD_HASH`       | empty        | Pre-computed argon2 hash; preferred over plaintext for production. |
| `session_max_age_s`                | `REQLORE_SESSION_MAX_AGE`     | `28800` (8h) | Auth session lifetime.                          |
| `default_theme`                    | —                              | `"system"`   | Fallback for projects with no saved `theme`.    |
| `default_verbosity`                | —                              | `"standard"` | Fallback for projects with no saved `verbosity`. |

Resolution order: **CLI flag > env var > project setting > user config > default**.

For login flow details see [`../login.md`](../login.md).

## Update check

- **Strictly opt-in.** No background polling. No telemetry.
- *Check for updates now* button POSTs to `/settings/check-updates`.
- Server-side, the handler verifies `update_check == "1"` before
  fetching.
- Fetches a small manifest from
  `https://raw.githubusercontent.com/ibrasonic/Reqlore/main/manifest.json`.
- Compares the manifest version against the running version via
  `update_check._parse_version()` and flashes the result.
- Network failure / unreachable URL: flashed message, no exception
  surfaces.

## Accessibility notes

- Four `<fieldset>` blocks with descriptive `<legend>`s (one per
  panel).
- Every radio / checkbox has an explicit `<label for="…">` — IDs
  `th-system`, `th-light`, `th-dark`, `th-high-contrast`, `vb-concise`,
  `vb-standard`, `vb-verbose`, `cu`, `upd`.
- **High-contrast theme** is the WCAG 2.2 AAA option. Exhaustively
  contrast-tested by `reqlore/tests/unit/test_wcag_aaa.py` across every
  colour token in the palette.
- Settings link in the top nav: `accesskey="9"`.
- Skip link `<a class="skip-link" href="#main">Skip to main content</a>`
  in `base.html`.
- Flash messages live in the global `role="alert"` region after save.
- Audio cues are **off by default** (WCAG 2.2 SC 1.4.2 — *Audio Control*).

## How it integrates

- The Flask context processor reads `theme` and `verbosity` from
  `project_state` on every request, so changes propagate without
  restart.
- The audio cue setting is consulted by every page that emits a cue —
  see [`cues.md`](cues.md) for a live preview and the available cue
  catalogue.
- The update-check button is the only outbound network call from a
  Reqlore process (apart from your own attack traffic).

## Recipes

### Switch to high-contrast theme

Open `/settings/` → tick **High contrast (WCAG 2.2 AAA)** → **Save**.
Theme applies on the next page render.

### Disable the update check after enabling it

Open `/settings/` → untick the update-check box → **Save**. The
*Check for updates now* button reverts to `disabled` on next page
load.

### Run with a password (production)

```
# One-time: generate a hash
python -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('mypass'))"

# Deploy with the hash, never the plaintext
REQLORE_PASSWORD_HASH='$argon2id$v=19$m=65536,...' reqlore both --project p.rlr --unsafe-bind
```

`REQLORE_PASSWORD_HASH` avoids leaking plaintext into the process
environment (`ps aux`-visible).

### Enable verbose logging

Not in the UI — pass `--verbose` or set `REQLORE_VERBOSE=1` on the
launch command. Bumps the logger to INFO and installs a noise filter
for mitmproxy chatter.

### Change the default theme for new projects

Edit `default_theme` in `reqlore/config.py`. Existing projects keep
their saved theme — the default only applies when the `theme` key
isn't in `project_state` yet.

## Storage footprint

| Key                                | Type       | Notes                                                       |
|------------------------------------|------------|-------------------------------------------------------------|
| `project_state["theme"]`           | text       | One of `system` / `light` / `dark` / `high-contrast`.        |
| `project_state["verbosity"]`       | text       | One of `concise` / `standard` / `verbose`.                   |
| `project_state["cues"]`            | text       | `"0"` / `"1"`.                                                |
| `project_state["update_check"]`    | text       | `"0"` / `"1"`.                                                |

Global settings are **not** persisted to the project file — they live in
the in-process `Settings` dataclass for the lifetime of the run.

## CLI

```
reqlore ui    --project <p> [--host 127.0.0.1] [--port 8787] [--unsafe-bind] [--no-password] [-v]
reqlore proxy --project <p> [--port 8080] [-v]
reqlore both  --project <p> [--host 127.0.0.1] [--ui-port 8787] [--proxy-port 8080]
                            [--unsafe-bind] [--no-password] [-v]
```

`-v` / `--verbose` is the verbose-logging knob. `--unsafe-bind` is the
only way off loopback. `--no-password` bypasses the password requirement
that `--unsafe-bind` would otherwise enforce — use only when behind a
reverse proxy with its own auth.

## Troubleshooting

| Symptom                                                | Cause                                                                  | Fix                                                                                              |
|--------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| *Check for updates now* stays disabled after save       | Page didn't re-render the disabled state after PRG redirect             | Hard-refresh `/settings/`; the button re-enables on the next render.                              |
| Save silently ignored an invalid value                  | Whitelist drop                                                          | Confirm the field is still on its previous value; pick a valid option and re-save.                |
| 400 on save                                             | CSRF token mismatch (session lost / private-browse)                     | Reload `/settings/` to get a fresh token, re-submit.                                              |
| Theme flip didn't take effect                           | Page cached by browser                                                  | Hard-refresh (Ctrl+F5).                                                                          |
| Plaintext password visible in `ps aux`                  | You used `REQLORE_PASSWORD=…`                                           | Pre-hash and use `REQLORE_PASSWORD_HASH=…` instead.                                               |
| Authenticated session times out faster than expected     | `REQLORE_SESSION_MAX_AGE` is small (default 28800 = 8h)                 | Set a larger value: `REQLORE_SESSION_MAX_AGE=86400` for 24h.                                      |
| Update check flashes a network error                    | Outbound HTTPS to GitHub is blocked                                     | Permit the manifest URL through the firewall, or skip the check and update via `pip` directly.   |

## Test contract

- `reqlore/tests/unit/test_web_smoke.py::test_settings_get` — page renders with Theme + Verbosity legends.
- `reqlore/tests/unit/test_phase7.py::test_settings_has_update_check_toggle` — the `update_check` checkbox is on the page.
- `…::test_update_check_version_parser` — version comparison logic.
- `…::test_update_check_handles_unreachable_url` — manifest fetch tolerates network errors.
- `reqlore/tests/unit/test_auth.py::test_settings_from_env_reads_password` — `REQLORE_PASSWORD` env var loaded.
- `…::test_settings_from_env_reads_password_hash` — `REQLORE_PASSWORD_HASH` loaded; `auth_enabled` flips on.
- `…::test_pre_hashed_password_accepts_login` — pre-hashed login works end-to-end.
- `reqlore/tests/unit/test_storage.py::test_state_get_set` — `project_state` round-trip for the `theme` key.
- `reqlore/tests/unit/test_a11y.py::test_wcag_pass_high_contrast_theme` — high-contrast theme passes WCAG contrast.
- `reqlore/tests/unit/test_wcag_aaa.py` — exhaustive AAA contrast sweep across every colour token.
