# Weblore

Burp-grade web application pentesting suite. Python-native. Accessible-first. Local web UI.

> **Status:** Phase 7 complete — see [`docs/ROADMAP.md`](docs/ROADMAP.md). 240/240 unit tests pass, 28/28 routes serve 200.

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

## Install (dev)

```powershell
git clone <repo>
cd Weblore
py -m pip install -e .[dev]
weblore init demo.weblore
weblore ui    --project demo.weblore     # browse http://127.0.0.1:8787
weblore proxy --project demo.weblore     # MITM on 127.0.0.1:8080
weblore both  --project demo.weblore     # UI + proxy in one process
weblore browser                          # spawn a pre-configured Firefox
```

Optional extras: `[h3]`, `[impersonate]`, `[report]`, `[plugins]`, `[yaml]`, `[a11y]`, `[schedule]` — see [`docs/USAGE.md`](docs/USAGE.md#install).

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
