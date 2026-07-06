# Reqlore

Professional-grade web application pentesting suite. Python-native. Accessible-first. Local web UI.

> **Status:** Active development past Phase 9. Full unit suite: **2883 passed, 368 skipped**. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## What it is

A local web app on `http://127.0.0.1:8787` that gives you:

- An intercepting MITM proxy with held-request queue and per-rule filters.
- HTTP history with full search, filter, export.
- A Repeater (edit + replay any request) — six engines (httpx / raw / h3 / curl-cffi × 3).
- An Intruder (sniper / battering ram / pitchfork / cluster bomb) — same six engines.
- A Param miner, GraphQL / WebSocket / SAML / HTTP-2 / smuggling workbenches.
- A passive + active scanner (with built-in OAST-SSRF check), a Sequencer, a Macro engine.
- A Decoder/Encoder, JWT workbench (decode / sign / alg-switch / RS→HS key confusion with smart PEM/JWK/JWKS/URL input), Comparer, Sitemap, Match-and-replace, Reporter.
- A Scheduler for recurring passive scans (APScheduler optional, thread fallback).
- A HAR importer (`reqlore import-har`), an opt-in update check, a plugin API.
- A Settings page with themes (light / dark / high-contrast), verbosity profiles, audio cues, and a remappable keyboard map.

Full per-module walkthrough: [`docs/USAGE.md`](docs/USAGE.md).

## Why

The industry-standard desktop pentest suites are built on Java/JavaFX Swing UIs that are a barrier for screen-reader users. Reqlore is built ground-up as plain semantic HTML5 + Jinja2, which is the most reliable substrate for NVDA, JAWS, Orca, and VoiceOver. Targets **WCAG 2.2 AA**; details in [`docs/ACCESSIBILITY.md`](docs/ACCESSIBILITY.md).

## Install

Requires **Python 3.12+**. Pick the path that matches your platform.

### Quickest: one-shot installer (Linux / macOS / Windows)

```bash
# Linux / macOS
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
sh install.sh
```

```bat
:: Windows (cmd or PowerShell)
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
install.bat
```

The installer creates a virtual environment in `.venv/`, installs Reqlore
into it, and prints how to run the `reqlore` command. On Linux/macOS the
script tries to install [`pipx`](https://pipx.pypa.io) automatically via your
system package manager (`apt`/`dnf`/`pacman`/`zypper`/`apk`/`brew`, with
`sudo` if needed) so you get a global `reqlore` command with no activation
step; set `REQLORE_NO_PIPX=1` to skip and go straight to the venv path.

Then:

```
reqlore init demo.rlr
reqlore both --project demo.rlr   # UI on http://127.0.0.1:8787, proxy on 127.0.0.1:8080
```

(On Windows, prefix the command with `.venv\Scripts\` or activate the venv with `.venv\Scripts\activate.bat`.)

### Manual install (contributors / hacking)

```powershell
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
py -m venv .venv
.venv\Scripts\Activate.ps1            # Linux/macOS: source .venv/bin/activate
py -m pip install -e ".[dev]"         # editable install + test/lint tools
py -m pytest reqlore/tests/unit -q    # should be 2883 passed, 368 skipped
reqlore init demo.rlr
reqlore both --project demo.rlr
```

Other subcommands:

```
reqlore ui    --project demo.rlr   # UI only
reqlore proxy --project demo.rlr   # MITM only
reqlore browser                        # spawn Firefox pre-pointed at the proxy
```

Optional extras: `[h3]`, `[impersonate]`, `[report]`, `[plugins]`, `[yaml]`, `[a11y]`, `[schedule]` — see [`docs/USAGE.md`](docs/USAGE.md#install).

> **Debian/Ubuntu/Kali users:** `pip install .` against system Python is blocked by [PEP 668](https://peps.python.org/pep-0668/). Use `install.sh` (recommended), or `python3 -m venv .venv && source .venv/bin/activate` first. If `venv` is missing, `sudo apt install python3-venv`.

### Uninstall

```bash
sh uninstall.sh                 # Linux / macOS
sh uninstall.sh --purge-data    # also drop ./data and demo.rlr* files
```

```bat
:: Windows
uninstall.bat
uninstall.bat --purge-data
```

Removes the pipx-installed `reqlore` and/or the local `.venv/`. Does **not** remove pipx itself, Python, or the mitmproxy CA you may have trusted in your browser/OS keystore — those are kept because you might want them for other tools.

## Run with Docker

```powershell
# 1. set a UI login password once (Compose auto-reads .env):
echo REQLORE_PASSWORD=your-strong-password > .env
# 2. build + start:
docker compose up -d --build
# UI:    http://127.0.0.1:8787   (log in with that password)
# Proxy: 127.0.0.1:8080
```

The password is hashed (argon2id) on first start and stored in
`./data/.reqlore-auth` — the plaintext never touches disk, and later launches
reuse the hash (you can delete `.env` afterwards). Prefer an interactive prompt
over a file? Skip `.env` and run `docker compose run --rm reqlore set-password`
once. Project file persists in `./data/my.rlr`; both listeners are pinned to
loopback on the host. Details: [`docs/USAGE.md`](docs/USAGE.md#docker).

## Documentation

Start with [`docs/USAGE.md`](docs/USAGE.md) — it indexes everything else.

| File | What |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | **Entry point.** Install, first run, CLI, links into the per-module guides. |
| [`docs/modules/`](docs/modules/) | One reference page per panel (Proxy, History, Repeater, Intruder, Scanner, …). |
| [`docs/engines.md`](docs/engines.md) | The six request engines (`httpx`, `raw`, `h3`, `curl-cffi:*`) and when to pick each. |
| [`docs/workflows.md`](docs/workflows.md) | End-to-end worked engagements (auth bypass, IDOR, SSRF, JWT, smuggling). |
| [`docs/KEYBINDINGS.md`](docs/KEYBINDINGS.md) | Consolidated keyboard map across every page. |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Symptom → fix lookup. |
| [`docs/login.md`](docs/login.md) | argon2id UI password gate, `--no-password`, reverse-proxy fronting. |
| [`docs/browser-launcher.md`](docs/browser-launcher.md) | `reqlore browser` Firefox cache, prefetch, WSL → host, auto-deps. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Process model, engines, storage. |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Module-by-module status matrix. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phase plan. |
| [`docs/ACCESSIBILITY.md`](docs/ACCESSIBILITY.md) | WCAG 2.2 AA conformance + AAA-strict patterns. |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model of the tool itself. |
| [`docs/PLUGINS.md`](docs/PLUGINS.md) | Plugin API. |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Dev workflow. |

## License

**Open source under the [Apache License 2.0](LICENSE).** You're free
to use, modify, distribute, and embed Reqlore in any setting —
personal, academic, charitable, or commercial — including inside
security teams at companies that hire blind and low-vision
practitioners, and inside paid consulting engagements. The Apache 2.0
license also grants an explicit patent license, which is why most
mainstream open-source security tooling (e.g. OWASP ZAP) standardises
on it. The only obligations are the usual ones: keep the copyright
notice and the LICENSE file with copies, state significant changes
you make, and don't use the Reqlore name or logo to imply endorsement
of your fork. Contributions are welcome — by submitting a pull
request you license your contribution under the same terms
(Apache 2.0, § 5).

Report security issues privately to
[ibrahim.m.badawy@gmail.com](mailto:ibrahim.m.badawy@gmail.com) — see
[docs/SECURITY.md](docs/SECURITY.md) for the disclosure policy.

Copyright (c) 2026 Ibrahim Badawy.
