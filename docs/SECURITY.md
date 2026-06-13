# Reqlore — Security of the tool itself

Reqlore is itself a high-privilege tool: it sees plaintext of all proxied traffic, it can issue any HTTP request, and it stores secrets (CA private key, session tokens, JWT keys). The threat model below describes how we keep that contained.

## Threat model

| Actor | Capability | Mitigation |
|---|---|---|
| Local unprivileged process | Can read `~/.reqlore/*` if perms wrong | CA key written with 0600 (Unix) / DACL owner-only (Windows). All sensitive files under user profile, not world-readable. |
| Local browser tab on the same machine | Can hit `127.0.0.1:8787` and try CSRF | UI CSRF tokens on every form (itsdangerous). Strict `Content-Type` checks on JSON endpoints. Origin/Referer enforcement. |
| Pentest target server | Returns crafted HTML/JS that lands in our UI | All rendered target HTML is shown in a sandboxed `<iframe sandbox>`. Response bodies are escaped before insertion into UI templates. No raw `\| safe` on user-influenced data. |
| Pentest target server (XSS in proxy) | Tries to break out of "rendered for preview" | Same iframe sandbox. CSP `default-src 'self'` on the UI itself. |
| Network attacker on LAN | Tries to reach `:8787` or `:8080` | Default bind 127.0.0.1 only. To expose, user must pass `--unsafe-bind` and set a password. |
| Untrusted plugin | Tries to read project file / exfil | Plugins run in-process (Python has no real sandbox). We warn loudly before enabling unsigned plugins. Optional Ed25519 signing for published plugins. |

## Hard rules

1. **No bind to 0.0.0.0 by default.** `--unsafe-bind` is the only way to bind a non-loopback address, and Reqlore refuses to start in that mode unless one of `REQLORE_PASSWORD` (plaintext, hashed at startup) or `REQLORE_PASSWORD_HASH` (pre-computed argon2id hash) is set, **or** you explicitly opt out with `--no-password` for the case where you front Reqlore with your own authenticating reverse proxy. See [UI authentication](#ui-authentication) below.
2. **CA key is never logged.** Logger redacts paths matching CA key location.
3. **Project files** never contain secrets in cleartext beyond what the user explicitly stored — but they ARE sensitive (full history, CA cert chain). Encryption at rest (optional, argon2 → AES-256-GCM via cryptography) is on by default for new projects.
4. **CSP on UI:** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.
5. **CSRF tokens** on every state-changing form (`X-Reqlore-CSRF` header on fetch, hidden field on form POSTs).
6. **Strict same-origin** for the UI; no CORS allowances.
7. **HttpOnly + SameSite=Strict + Secure** session cookie (Secure only when behind TLS).
8. **No outbound calls without consent.** Update check, interactsh, telemetry — all opt-in toggles, off by default.
9. **Dependencies pinned** in `pyproject.toml` with hash verification (`pip install --require-hashes` for releases). Renovate-bot bumps reviewed before merge.
10. **SBOM** generated per release (`cyclonedx-py`).

## Audit-friendly choices

- Server-rendered HTML: review surface is small, no bundler.
- Single language (Python 3.14+) for the entire codebase.
- **No `subprocess` / `os.system` / shell-out anywhere.** The `curl_render` engine is pure string formatting — it builds a `curl …` command as text for "Copy as curl" export and never executes it. The runtime sender engines are `httpx` (Python lib) and stdlib `socket`+`ssl`. The optional `curl-cffi` extra (Phase 5, off by default) is a Python library binding to `libcurl-impersonate`, not the `curl` CLI.
- No `eval` / `exec` / `pickle.loads` of untrusted data anywhere. Project files use SQLite + a documented schema; payload presets are JSON only.
- Logging uses the stdlib `logging` module with structured fields; secrets are redacted by a `SecretsFilter`.

## Reporting vulnerabilities

Report security issues privately by email to
**ibrahim.m.badawy@gmail.com** with subject line starting
`[reqlore-security]`. Please include reproduction steps, the
Reqlore version (`reqlore --version`), and your assessment of impact.

Policy:

- I aim to acknowledge within 7 days and to ship a fix or a public
  workaround within 90 days of acknowledgement.
- Coordinated disclosure: please give me until the fix is released
  before publishing details. CVE assignment and credit on request.
- GitHub Security Advisories on this repo are also welcome and route
  to the same inbox; use whichever channel is easier.

## UI authentication

The web UI is loopback-only by default. Loopback (`127.0.0.1`, `::1`) bypasses
the password check unconditionally — if you can reach `127.0.0.1` you already
have a shell on the box and the project file on disk, so a password would only
provide false friction.

When you bind to any other interface with `--unsafe-bind`, Reqlore enforces
authentication. Configure it with **one** of:

- `REQLORE_PASSWORD=<passphrase>` — Reqlore hashes this once at startup using
  argon2id (`time_cost=3, memory_cost=64 MiB, parallelism=2`, the OWASP 2024
  baseline) and discards the plaintext from process memory immediately. Use
  this for local lab work where leaving the plaintext in your shell is fine.
- `REQLORE_PASSWORD_HASH=<argon2id hash>` — a pre-computed argon2id hash
  (string starts with `$argon2id$`). Use this in systemd unit files, Docker
  secrets, Kubernetes secrets — anywhere the plaintext should never appear in
  an environment variable or process listing. Generate it with:

  ```powershell
  py -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('your-passphrase-here'))"
  ```

- `--no-password` (escape hatch) — accept full responsibility for placing an
  authenticating reverse proxy in front of Reqlore (nginx `auth_basic`, Caddy
  `basic_auth`, `oauth2-proxy`, Cloudflare Access, etc.). Reqlore prints a
  loud warning to stderr at startup so this can't happen by accident in a
  log review.

### Login flow & hardening

- The session cookie is `HttpOnly`, `SameSite=Strict`, signed with
  itsdangerous, and lives for `REQLORE_SESSION_MAX_AGE` seconds (default 8h).
  In a TLS-fronted deployment the cookie also gets the `Secure` flag.
- On successful login the Flask session is **rotated** (new signing salt,
  new cookie value) to defeat session fixation against the pre-login state.
- The `?next=` parameter on `/login` is validated: it must start with `/`
  and not `//`, so a crafted login link cannot redirect you to an attacker
  page after you authenticate.
- Failed logins are throttled per source IP with exponential backoff capped
  at 60 s. The throttle store is in-process only, so a crash clears it —
  that's acceptable because rate is enforced at the network edge, not the
  account layer, and Reqlore is a single-operator tool.
- Non-browser callers (any request carrying `X-Reqlore-CSRF` or any
  non-`GET` request) get a `401 Unauthorized` response instead of an HTML
  redirect to `/login`, so JSON tooling and the in-UI fetch layer can
  detect the auth boundary without parsing HTML.
- No built-in TLS. If you bind to a non-loopback interface for anyone
  outside your own machine, front Reqlore with a reverse proxy that
  terminates TLS — Caddy is the lowest-friction option.

### What authentication does *not* protect

The password gate is for the **web UI** specifically. The proxy listener
(`reqlore proxy` / `reqlore both --proxy-port`) does not and cannot accept a
password — proxies that prompt for credentials break every HTTP client. The
proxy is loopback-only by design and has no `--unsafe-bind`. If you need to
proxy traffic from another host, tunnel to it (SSH `-L`, WireGuard, Tailscale)
rather than exposing the proxy port.
