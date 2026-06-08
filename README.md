# Weblore

Burp-grade web application pentesting suite. Python-native. Accessible-first. Local web UI.

> **Status:** Phase 8 complete — 333/333 unit tests pass. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## What it is

A local web app on `http://127.0.0.1:8787` that gives you:

- An intercepting MITM proxy with held-request queue and per-rule filters.
- HTTP history with full search, filter, export.
- A Repeater (edit + replay any request) — six engines (httpx / raw / h3 / curl-cffi × 3).
- An Intruder (sniper / battering ram / pitchfork / cluster bomb) — same six engines.
- A Param miner, GraphQL / WebSocket / SAML / HTTP-2 / smuggling workbenches.
- A passive + active scanner (with built-in OAST-SSRF check), a Sequencer, a Macro engine.
- A Decoder/Encoder, JWT workbench, Comparer, Sitemap, Match-and-replace, Reporter.
- A Scheduler for recurring passive scans (APScheduler optional, thread fallback).
- A HAR importer (`weblore import-har`), an opt-in update check, a plugin API.
- A Settings page with themes (light / dark / high-contrast), verbosity profiles, audio cues, and a remappable keyboard map.

Full per-module walkthrough: [`docs/USAGE.md`](docs/USAGE.md).

## Why

Burp Suite is the industry standard but its Java Swing UI is a barrier for screen-reader users. Weblore is built ground-up as plain semantic HTML5 + Jinja2, which is the most reliable substrate for NVDA, JAWS, Orca, and VoiceOver. Targets **WCAG 2.2 AA**; details in [`docs/ACCESSIBILITY.md`](docs/ACCESSIBILITY.md).

## Install

Requires **Python 3.12+**. Pick the path that matches your platform.

### Quickest: one-shot installer (Linux / macOS / Windows)

```bash
# Linux / macOS
git clone https://github.com/ibrasonic/Weblore.git
cd Weblore
sh install.sh
```

```bat
:: Windows (cmd or PowerShell)
git clone https://github.com/ibrasonic/Weblore.git
cd Weblore
install.bat
```

The installer creates a virtual environment in `.venv/`, installs Weblore
into it, and prints how to run the `weblore` command. On Linux/macOS, if
[`pipx`](https://pipx.pypa.io) is available it's used instead (preferred
— you get a global `weblore` command with no activation step).

Then:

```
weblore init demo.weblore
weblore both --project demo.weblore   # UI on http://127.0.0.1:8787, proxy on 127.0.0.1:8080
```

(On Windows, prefix the command with `.venv\Scripts\` or activate the venv with `.venv\Scripts\activate.bat`.)

### Manual install (contributors / hacking)

```powershell
git clone https://github.com/ibrasonic/Weblore.git
cd Weblore
py -m venv .venv
.venv\Scripts\Activate.ps1            # Linux/macOS: source .venv/bin/activate
py -m pip install -e ".[dev]"         # editable install + test/lint tools
py -m pytest weblore/tests/unit -q    # should be 346 passed
weblore init demo.weblore
weblore both --project demo.weblore
```

Other subcommands:

```
weblore ui    --project demo.weblore   # UI only
weblore proxy --project demo.weblore   # MITM only
weblore browser                        # spawn Firefox pre-pointed at the proxy
```

Optional extras: `[h3]`, `[impersonate]`, `[report]`, `[plugins]`, `[yaml]`, `[a11y]`, `[schedule]` — see [`docs/USAGE.md`](docs/USAGE.md#install).

> **Debian/Ubuntu/Kali users:** `pip install .` against system Python is blocked by [PEP 668](https://peps.python.org/pep-0668/). Use `install.sh` (recommended), or `python3 -m venv .venv && source .venv/bin/activate` first. If `venv` is missing, `sudo apt install python3-venv`.

## Run with Docker

```powershell
docker compose up --build
# UI:    http://127.0.0.1:8787
# Proxy: 127.0.0.1:8080
```

Project file persists in `./data/my.weblore`. Both listeners are pinned to loopback on the host. Details: [`docs/USAGE.md`](docs/USAGE.md#docker).

## Documentation

| File | What |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | **Complete user guide — every module, every shortcut, every flag.** |
| [`docs/STORY-blind-pentester.txt`](docs/STORY-blind-pentester.txt) | A narrated, blind-pentester walkthrough of vuln-bank / vuln-shop / vuln-social. |
| [`docs/PLAN.md`](docs/PLAN.md) | Top-level why + non-goals |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Process model, engines, storage |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Module-by-module status |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phase plan |
| [`docs/ACCESSIBILITY.md`](docs/ACCESSIBILITY.md) | WCAG checklist + patterns |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model of the tool |
| [`docs/PLUGINS.md`](docs/PLUGINS.md) | Plugin API |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Dev workflow |

## License

**Source-available, noncommercial.** Weblore is released under the
[PolyForm Noncommercial License 1.0.0](LICENSE). You're free to use,
modify, study, and contribute it for any noncommercial purpose —
research, learning, hobby work, education, charity, public safety,
etc. Pull requests are very welcome. Commercial use (selling it,
re-selling derivatives, paid consulting *built around* Weblore as the
product) is not permitted under this license; contact the author
(`ibrahim.badawy@aucegypt.edu`) if you need a commercial arrangement.

Copyright (c) 2026 Ibrahim Badawy.
