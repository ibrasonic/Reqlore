# Weblore — Security of the tool itself

Weblore is itself a high-privilege tool: it sees plaintext of all proxied traffic, it can issue any HTTP request, and it stores secrets (CA private key, session tokens, JWT keys). The threat model below describes how we keep that contained.

## Threat model

| Actor | Capability | Mitigation |
|---|---|---|
| Local unprivileged process | Can read `~/.weblore/*` if perms wrong | CA key written with 0600 (Unix) / DACL owner-only (Windows). All sensitive files under user profile, not world-readable. |
| Local browser tab on the same machine | Can hit `127.0.0.1:8787` and try CSRF | UI CSRF tokens on every form (itsdangerous). Strict `Content-Type` checks on JSON endpoints. Origin/Referer enforcement. |
| Pentest target server | Returns crafted HTML/JS that lands in our UI | All rendered target HTML is shown in a sandboxed `<iframe sandbox>`. Response bodies are escaped before insertion into UI templates. No raw `\| safe` on user-influenced data. |
| Pentest target server (XSS in proxy) | Tries to break out of "rendered for preview" | Same iframe sandbox. CSP `default-src 'self'` on the UI itself. |
| Network attacker on LAN | Tries to reach `:8787` or `:8080` | Default bind 127.0.0.1 only. To expose, user must pass `--unsafe-bind` and set a password. |
| Untrusted plugin | Tries to read project file / exfil | Plugins run in-process (Python has no real sandbox). We warn loudly before enabling unsigned plugins. Optional Ed25519 signing for published plugins. |

## Hard rules

1. **No bind to 0.0.0.0 by default.** `--unsafe-bind 0.0.0.0` requires also setting `WEBLORE_PASSWORD` (argon2-cffi).
2. **CA key is never logged.** Logger redacts paths matching CA key location.
3. **Project files** never contain secrets in cleartext beyond what the user explicitly stored — but they ARE sensitive (full history, CA cert chain). Encryption at rest (optional, argon2 → AES-256-GCM via cryptography) is on by default for new projects.
4. **CSP on UI:** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.
5. **CSRF tokens** on every state-changing form (`X-Weblore-CSRF` header on fetch, hidden field on form POSTs).
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

`SECURITY.md` at repo root will publish `security@<your-domain>` PGP key and a 90-day disclosure window.
