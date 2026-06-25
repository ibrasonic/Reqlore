# Troubleshooting

Symptoms and fixes from across the toolkit. For per-module gotchas, see
the *Troubleshooting* section on each [module page](modules/).

---

## Install / startup

| Symptom                                            | Cause                                                     | Fix                                                                       |
|----------------------------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------|
| `reqlore: command not found`                       | Not installed, or venv not on PATH                        | `pip install reqlore`. Verify with `which reqlore` / `where reqlore`.     |
| `ImportError: No module named '<pkg>'`             | Optional extra not installed                              | See *Optional extras* below.                                              |
| `Address already in use` on startup                | Another Reqlore (or anything) on the bound port            | Stop the other; or `reqlore web --ui-port <other>` / `--proxy-port <other>`. |
| Web UI 404s every route                            | Project file missing or unwritable                        | Confirm `--project <path>` is readable + writable; default is `data/my.rlr`. |
| `sqlite3.OperationalError: database is locked`     | Another process has the `.rlr` open                       | Only one Reqlore process per project file.                                |

### Optional extras

| Symptom                                                  | Missing extra              | Install                                       |
|----------------------------------------------------------|----------------------------|-----------------------------------------------|
| `Response(status=0, error="aioquic …")`                  | `[h3]`                     | `pip install reqlore[h3]`                     |
| `Response(status=0, error="curl_cffi …")`                | `[impersonate]`            | `pip install reqlore[impersonate]`            |
| WebSocket workbench: "websockets is not installed"        | `[websocket]`              | `pip install reqlore[websocket]`              |
| `reqlore browser` errors before Firefox download          | `[browser]`                | `pip install reqlore[browser]`                |
| Scheduler reports backend `thread` instead of APScheduler | `[schedule]`               | `pip install reqlore[schedule]`               |
| Plugins "Hot reload" button does nothing                  | `watchdog`                 | `pip install watchdog`                        |

---

## Proxy / TLS

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Browser shows cert errors on HTTPS pages                 | Reqlore CA not trusted                                                  | Use [Browser launcher](browser-launcher.md) (trusts it automatically), or install `~/.reqlore/ca/reqlore-ca.pem` into your OS / browser store manually. |
| Some mobile apps refuse the proxy                         | Apps may pin certs                                                      | Cert pinning is by design; expected. Use a non-pinning version or a jailbroken device. (Out of scope for the toolkit.) |
| Localhost (`127.0.0.1`) bypasses the proxy in Firefox     | Firefox bypasses by default                                              | Reqlore's launcher sets `network.proxy.allow_hijacking_localhost=true`. Re-launch via `reqlore browser`. |
| Match & Replace rules don't fire                         | Rule is disabled, or `host_regex` doesn't match                          | Toggle `enabled`; double-check the regex.                                                        |
| Smuggling payload never desyncs                          | Sent via `httpx` / `curl-cffi` — both normalise TE/CL                    | Switch [Repeater](modules/repeater.md) engine to `raw`. See [engines.md](engines.md).            |
| Intercept matches a rule but holds nothing               | `restrict_to_scope` is checked and the host is out-of-scope per Sitemap | Either add the host to your Sitemap include scope (**Settings → Scope**) or untick **Only hold requests for hosts that are in scope** on the intercept filter. Detail in [proxy.md](modules/proxy.md#intercept-rules). |

---

## Browser launcher

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Download fails with `SHA256 mismatch`                     | Mozilla mirror wedged / version respun                                  | Re-run; if persistent, pin via `--firefox-version 127.0`.                                        |
| Firefox crashes on launch (Linux)                         | Missing system lib                                                       | Re-run — `ensure_linux_runtime()` auto-installs via the package manager (unless `REQLORE_NO_AUTODEPS=1`). |
| "Profile is in use"                                        | Stale lock                                                              | `rm ~/.reqlore/firefox-profile/lock`.                                                            |
| WSL: nothing happens                                       | Launcher opens on the Windows host instead                              | Look at Windows side. Configure proxy + CA on Windows manually with the printed instructions.    |
| Air-gapped install can't find Firefox                      | Cache copied to wrong path                                              | Cache root is per-user: `~/.local/share/reqlore/firefox/<version>/`.                              |

See [Browser launcher](browser-launcher.md) for full detail.

---

## Auth / sessions

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Replayed Repeater request returns 401 / 403              | Captured cookie has expired                                              | Re-capture in History, or use a [Macro](modules/macros.md) to refresh.                            |
| Macro's `{{session}}` is empty                            | `Set-Cookie` wasn't in the previous step's response                     | Open the previous response in History; confirm.                                                  |
| Active scan loses session mid-way                         | No `replay_macro` configured                                            | Wire up a login macro via `replay_every_n_probes`. See [login.md](login.md).                     |
| Match & Replace leaks API key to third parties            | No `host_regex` set                                                     | Always restrict by host.                                                                         |

---

## Auth Matrix

- **Shadow worker is on but no cells appear.** Open **Auth Matrix →
  Shadow worker**. If *Skipped (out of scope)* equals *Enqueued*,
  the host isn't in your project's include scope — broaden the
  scope under **Settings → Scope** (or clear it). If *Processed*
  is 0 with no skips and no enqueues, the proxy is not routing
  responses through the shadow hook; restart `reqlore both`.
- **Every cell verdict is `identical`.** Only one session is
  marked *active*, so the self-baseline guard collapses every
  comparison to the source identity. Activate a second session in
  **Auth Matrix → Sessions**.
- **`bypass-suspect` everywhere.** The baseline session is in the
  compare list, or `privileged_floor` is too low. Don't include the
  baseline in compare; bump `privileged_floor` to 95+ for noisy
  apps. Detail in [auth-matrix.md](modules/auth-matrix.md#verdict-labels).
- **Active run stops at `timeout`.** Hit the default 10-minute
  watchdog cap. Split the run into smaller batches via the
  *History rows* field, or set `inter_request_sleep_s=0` if you'd
  bumped it.
- **TLS handshake fails on the replayed request.** *Verify TLS* is
  off by default; if you ticked it for a self-signed target,
  untick and re-run.
- **302 → /login surfaces as `bypass-suspect` instead of
  `denied-correctly`.** *Follow redirects* is on; the runner ends
  up at the login form (status 200) and similarity is incidentally
  high. Untick *Follow redirects* — auth-bypass tests want to see
  the raw 302.
- **Issue won't go away after dismissing the cell.** Dismissal
  updates the cell verdict only; the finding lives in the *Issues*
  table. Close it from the Scanner / Issues view.

## Scanner

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Passive scan returns nothing                              | History is empty                                                        | Drive some traffic through the proxy first.                                                       |
| Active scan stalls                                        | One target endpoint is slow / 502                                       | Reduce concurrency in active options; or pre-filter the queue.                                    |
| Findings appear twice                                     | Duplicate rule_id from multiple plugins or re-runs                      | The findings table dedupes by `(rule_id, host, url)`; check for duplicate plugins.                |
| `oast-ssrf` check reports nothing                          | OAST receiver not running                                              | Start [OAST](modules/oast.md) → **Start receiver** before running the scan.                       |
| Custom rule crashes the scanner                           | Plugin rule raised an exception                                          | Rules are caught per-rule; check stderr for the traceback; fix and reload. See [Plugins](modules/plugins.md). |

---

## Intruder

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Attack runs but every result is identical                | Insertion points not marked                                              | Wrap the variable region in `§…§` in the request template.                                       |
| Pause button greyed out                                  | Attack already finished                                                  | Start a new attack.                                                                              |
| Engine dropdown missing `curl-cffi:*` profiles            | `[impersonate]` extra missing                                            | `pip install reqlore[impersonate]`.                                                              |
| Results table empty after a "successful" run             | Filter is hiding rows                                                    | Clear the filter (Alt+A).                                                                         |

---

## Repeater

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `Response(status=0, error=…)`                            | Transport refused — extra missing, connection error, or timeout         | Check `error` text. See [engines.md](engines.md) for per-engine cases.                            |
| `Transfer-Encoding` dropped from outbound request         | Engine normalised it                                                    | Switch to `raw`.                                                                                  |
| Smuggling payload doesn't desync                          | Engine normalises TE/CL                                                  | Switch to `raw`. See [Smuggling](modules/smuggling.md).                                          |

---

## OAST

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| No callbacks arriving                                    | Target can't reach `127.0.0.1:<port>`                                   | Use a public callback host; or run Reqlore on the target's network.                              |
| All hits show `token=_`                                  | Probes hit unknown paths                                                 | Either prefix the probe path with your token, or accept unknown hits as suspicious.              |
| Log feels truncated                                      | Bounded at 5000 entries                                                  | **Clear** between batches; export findings.                                                       |
| DNS exfiltration not detected                            | HTTP-only receiver                                                       | Use a dedicated interactsh client.                                                                |

---

## Scheduler

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Jobs don't run after restart                              | Scheduler is stopped by default                                          | Click **Start scheduler** after each restart.                                                     |
| Backend says `thread`, not `apscheduler`                 | `[schedule]` extra missing                                              | `pip install reqlore[schedule]` for better precision.                                            |
| Exception in scan silently lost                          | `_thread_loop()` catches and ignores                                    | Tail Reqlore stderr; or run via `/scanner/` to surface the traceback.                            |
| Start refused: "Scheduler is already running for this project (pid X on host Y)" | Another Reqlore process holds the cross-process lock at `project_state["sched:lock"]` | Stop the other process, or wait ≈ 30 s for its TTL to expire. Detail in [scheduler.md](modules/scheduler.md#multi-process-safety). |

---

## GraphQL / WebSocket / SAML

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| GraphQL "Variables JSON is invalid"                       | Unquoted key / single quotes / trailing comma                            | Validate JSON externally; paste valid JSON.                                                       |
| WebSocket "websockets is not installed"                   | `[websocket]` extra missing                                              | `pip install reqlore[websocket]`.                                                                 |
| WebSocket binary send: `ValueError: non-hexadecimal`      | Binary input must be hex                                                 | Hex-encode first ([Decoder](modules/decoder.md) `hex_encode`).                                   |
| SAML decoder picks the wrong binding                      | Auto-detect tries Raw → POST → Redirect                                  | Re-paste without wrapping; padding fixes are automatic.                                          |

---

## Reporter

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `docx` export fails                                       | `python-docx` not installed                                              | `pip install python-docx`.                                                                       |
| Empty report                                             | No findings recorded                                                     | Run [Scanner](modules/scanner.md) first; confirm findings on the Scanner page.                   |
| Markdown looks weird in certain renderers                | Tight tables / non-ASCII bullets                                          | Try HTML export instead.                                                                         |

---

## Plugins

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Plugin shows `error` status                              | Import error or invalid `PLUGIN_INFO`                                    | Click the `<details>` for the traceback; fix; **Reload**.                                        |
| Plugin loaded but no rules fire                          | Disabled, or `scanner_rules()` returned empty                            | Toggle **Enable**; check rules count in the table.                                                |
| Copy-as link 404s                                        | Two plugins registered the same handler name                              | Prefix by plugin: `php-curl`, `node-fetch`.                                                       |
| Hot reload does nothing                                  | `watchdog` not installed                                                 | `pip install watchdog`; **Reload plugins**; **Enable hot reload**.                                |

---

## Cues / audio

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| No sound from cues                                       | Off by default; or browser autoplay policy blocking                      | Tick **Cues** in [Settings](modules/settings.md); click in the page once to unlock autoplay.      |
| `/cues/<name>.wav` returns 404                            | Unknown cue                                                              | Check `/cues/` for canonical names.                                                              |

---

## Tests

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Tests skipped (`SKIPPED`)                                | Optional extra missing — tests are gated on availability                | Install the corresponding extra (see *Optional extras*).                                          |
| `test_phase8_browser` slow                                | Tests use offline fixtures via monkeypatch                              | They should be fast; if hanging, check for an accidental live network call.                       |

---

## Where to find more help

- Per-module troubleshooting tables: [docs/modules/](modules/).
- Architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md).
- Security model: [SECURITY.md](SECURITY.md).
- Accessibility commitments: [ACCESSIBILITY.md](ACCESSIBILITY.md).
- Issue tracker: see project [README.md](../README.md) for the link.
