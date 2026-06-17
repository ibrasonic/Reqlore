# Reqlore — User Guide

This is the **entry point**. It covers install, first run, the CLI, and links
into one reference page per panel under [`modules/`](modules/).

If you have used a traditional pentest GUI before, the mental model is the same: a local UI
on `http://127.0.0.1:8787`, an intercepting MITM proxy on
`127.0.0.1:8080`, and a set of workbenches that operate on captured requests
and findings stored in a single SQLite project file (`*.rlr`).

---

## Table of contents

1. [Install](#install)
2. [First run](#first-run)
3. [CLI reference](#cli-reference)
4. [Environment variables](#environment-variables)
5. [Module index](#module-index)
6. [Cross-cutting topics](#cross-cutting-topics)
7. [Where to go next](#where-to-go-next)

---

## Install

Requires **Python 3.12+** (3.14 tested).

### One-shot installer (recommended)

```bash
# Linux / macOS
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
sh install.sh
```

```bat
:: Windows
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
install.bat
```

The script creates a `.venv/`, installs Reqlore, and (on Linux/macOS) tries to
install [`pipx`](https://pipx.pypa.io) via your system package manager so you
get a global `reqlore` command. Override with `REQLORE_NO_PIPX=1`.

### Manual install

```powershell
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
py -m pytest reqlore/tests/unit -q          # should be 1368 passed, 239 skipped
```

### Optional extras

| Extra           | Purpose                                                            |
| --------------- | ------------------------------------------------------------------ |
| `[dev]`         | `pytest`, `ruff`, `mypy`                                           |
| `[h3]`          | HTTP/3 over QUIC engine (`aioquic`)                                |
| `[impersonate]` | TLS-fingerprint engines (`curl-cffi`: chrome120, safari17_0, …)    |
| `[report]`      | `.docx` report export (`python-docx`)                              |
| `[plugins]`     | Hot-reload plugin folder (`watchdog`)                              |
| `[yaml]`        | YAML job runner (`PyYAML`)                                         |
| `[a11y]`        | Headless axe-core CI gate (`playwright`, `axe-playwright-python`)  |
| `[schedule]`    | APScheduler backend for the Scheduler module                       |

Install several at once: `pip install -e ".[dev,h3,impersonate,report,yaml,schedule]"`.

### Uninstall

```bash
sh uninstall.sh                 # Linux / macOS  (add --purge-data to drop ./data)
```

```bat
uninstall.bat                   :: Windows
```

> **Debian / Ubuntu / Kali:** `pip install .` against system Python is blocked
> by [PEP 668](https://peps.python.org/pep-0668/). Use `install.sh` or create
> a venv first. If `venv` is missing: `sudo apt install python3-venv`.

---

## First run

```powershell
reqlore init my.rlr
reqlore both --project my.rlr           # UI on 8787, proxy on 8080
```

Open `http://127.0.0.1:8787` in any browser. Trust the proxy CA by visiting
`/proxy/` → **Download CA** → import into the browser's *Authorities* store.

For a one-step alternative that launches a dedicated Firefox already proxied
and CA-trusted, see [`browser-launcher.md`](browser-launcher.md):

```powershell
reqlore browser
```

A **project** is a single SQLite file. It holds history, findings, scheduler
jobs, match/replace rules, plugin state, settings, and the proxy CA. Move it
like any file.

---

## CLI reference

```text
reqlore init <project_path>
reqlore ui     --project <p> [--host H] [--port N] [--unsafe-bind] [--no-password]
reqlore proxy  --project <p> [--port N]
reqlore both   --project <p> [--host H] [--ui-port N] [--proxy-port N] [--unsafe-bind] [--no-password]
reqlore scan   --project <p> [--limit N]
reqlore report --project <p> --out FILE [--format md|html|docx]
reqlore run    --project <p> JOB.{yaml|yml|json} [--strict]
reqlore import-har --project <p> SESSION.har
reqlore browser  [--proxy-port N] [--url URL]
                 [--firefox-version V] [--firefox-zip FILE]
                 [--use-system] [--wait]
reqlore prefetch-firefox [--firefox-version V] [--firefox-zip FILE] [--force]
```

`--unsafe-bind` is the only way to bind a non-loopback address. When set,
Reqlore refuses to start unless you also set `REQLORE_PASSWORD` /
`REQLORE_PASSWORD_HASH` (or you explicitly opt out with `--no-password`
because you front it with your own auth layer). Details:
[`login.md`](login.md).

---

## Environment variables

CLI flag > env var > project setting > user config > defaults.

| Variable                | Overrides                          | Notes                                                                 |
| ----------------------- | ---------------------------------- | --------------------------------------------------------------------- |
| `REQLORE_UI_HOST`       | `--host`                           | Default `127.0.0.1`.                                                  |
| `REQLORE_UI_PORT`       | `--port` / `--ui-port`             | Default `8787`.                                                       |
| `REQLORE_PROXY_HOST`    | (proxy bind host)                  | Always `127.0.0.1`; setting otherwise is unsupported.                 |
| `REQLORE_PROXY_PORT`    | `--port` (proxy) / `--proxy-port`  | Default `8080`.                                                       |
| `REQLORE_PASSWORD`      | (UI password, plaintext)           | argon2id-hashed once at startup.                                      |
| `REQLORE_PASSWORD_HASH` | (UI password, pre-hashed)          | Use in systemd / container secrets so plaintext never lives in env.   |
| `REQLORE_SESSION_MAX_AGE` | (login cookie lifetime, seconds) | Default `28800` (8h). Min `60`.                                       |
| `REQLORE_VERBOSE`       | `-v` / `--verbose`                 | `1` to enable INFO logging globally.                                  |
| `REQLORE_NO_PIPX`       | (installer)                        | `1` forces venv install instead of pipx.                              |
| `REQLORE_VENV`          | (installer)                        | Custom venv path (default `.venv`).                                   |
| `REQLORE_NO_AUTODEPS`   | (browser launcher)                 | `1` to skip auto-install of Linux libs Firefox needs.                 |
| `REQLORE_DATA`          | (Docker)                           | Project data dir inside container; default `/data`.                   |

**Pre-hashing a password** (recommended for shared deployments):

```powershell
py -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('your-passphrase'))"
```

---

## Module index

Every panel has its own page under [`modules/`](modules/). Each page follows the
same shape: Purpose → Where it is → Quick start → Interface → Integration →
Engines → Keyboard map → Accessibility → Recipes → Troubleshooting → CLI →
Storage.

### Core

- [Dashboard](modules/dashboard.md) — at-a-glance counts and last-update state.
- [Proxy](modules/proxy.md) — intercepting MITM, held-request queue, Send-to.
- [History](modules/history.md) — every captured request; live auto-refresh; per-row Actions menu.
- [Search](modules/search.md) — FTS5 over headers, bodies, findings.
- [Sitemap](modules/sitemap.md) — host/path tree linked back to history.

### Attack workbenches

- [Repeater](modules/repeater.md) — edit + replay any request, any engine.
- [Intruder](modules/intruder.md) — Sniper / Battering ram / Pitchfork / Cluster bomb; payload processors including `jwt:`.
- [Param miner](modules/param-miner.md) — query / body / header parameter discovery.
- [Scanner](modules/scanner.md) — passive + active checks; presets; manual finding entry; suppressions.
- [Comparer](modules/comparer.md) — side-by-side, unified diff, `.diff` download.
- [Decoder](modules/decoder.md) — every encoder/decoder; `smart_decode`; JWT decode.
- [JWT workbench](modules/jwt.md) — parse, verify, re-sign; alg-none; HS-secret crack; `kid` injection.

### Specialist workbenches

- [GraphQL](modules/graphql.md) — queries with variables; introspection; field fuzzing; persisted-query forging.
- [WebSocket](modules/websocket.md) — connect, frame, transcript; CSWSH test rig.
- [SAML](modules/saml.md) — parse responses; re-sign; mutate NameID; XSW variants.
- [PoC builder](modules/poc.md) — self-submitting HTML form, `fetch()`, `curl`, raw bytes.
- [Macros](modules/macros.md) — request chains with response-to-request variable extraction.
- [Sequencer](modules/sequencer.md) — FIPS bitstream + chi-square entropy on captured tokens.
- [OAST receiver](modules/oast.md) — HTTP/DNS/SMTP callback receiver; drives `OASTSSRFCheck`.
- [HTTP/2 workbench](modules/h2.md) — per-frame HTTP/2 over a single connection.
- [Smuggling lab](modules/smuggling.md) — CL.TE / TE.CL / TE.TE / H2.CL templates.
- [Scheduler](modules/scheduler.md) — recurring passive scans; APScheduler or thread fallback.

### Plumbing

- [Match & Replace](modules/matchreplace.md) — persistent proxy rewrite rules.
- [Reporter](modules/reporter.md) — Markdown / HTML / DOCX export of findings.
- [Plugins](modules/plugins.md) — installed plugins UI; loaded state; routes / panels / handlers.
- [Audio cues](modules/cues.md) — opt-in non-speech cues for events.
- [Settings](modules/settings.md) — theme, verbosity, keyboard map, audio cues, update check.
- [Help](modules/help.md) — searchable shortcut map + self-test.

---

## Cross-cutting topics

- [`engines.md`](engines.md) — the six request engines, picking criteria, gotchas.
- [`login.md`](login.md) — UI auth (argon2id), `--no-password`, reverse-proxy fronting.
- [`browser-launcher.md`](browser-launcher.md) — `reqlore browser` Firefox cache & prefetch.
- [`workflows.md`](workflows.md) — end-to-end worked attack chains.
- [`KEYBINDINGS.md`](KEYBINDINGS.md) — consolidated keyboard map.
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — symptom → fix lookup.
- [`ACCESSIBILITY.md`](ACCESSIBILITY.md) — WCAG 2.2 AA conformance + AAA-strict patterns.
- [`SECURITY.md`](SECURITY.md) — threat model of Reqlore itself.
- [`PLUGINS.md`](PLUGINS.md) — plugin authoring API.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — process model, storage, engine layer.
- [`ROADMAP.md`](ROADMAP.md) — phase plan.
- [`FEATURES.md`](FEATURES.md) — status matrix.
- [`internal/`](internal/) — historical dev plans, not user-facing.

---

## Where to go next

- **New user?** [`modules/proxy.md`](modules/proxy.md) → [`modules/history.md`](modules/history.md) → [`modules/repeater.md`](modules/repeater.md).
- **Migrating from another pentest GUI?** [`workflows.md`](workflows.md) is the fastest map between classic desktop-suite menus and Reqlore panels.
- **Screen-reader user?** [`ACCESSIBILITY.md`](ACCESSIBILITY.md) and the *Accessibility notes* section in each module page.
- **Setting up CI?** [`engines.md`](engines.md) + [`RUNNER.md`](RUNNER.md) + `reqlore run job.yaml`.
- **Air-gapped / offline?** [`browser-launcher.md`](browser-launcher.md) (`prefetch-firefox`) + the `--firefox-zip` flag.
