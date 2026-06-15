# Browser launcher — `reqlore browser`

Spawn a pre-configured Firefox profile that already trusts the Reqlore
CA and proxies every byte through Reqlore's MITM. The first run
downloads Firefox into a per-user cache (~40-70 MiB depending on
platform); subsequent runs are instant. Air-gapped boxes prefetch via
the helper script.

> **Optional extra.** `pip install reqlore[browser]`. (The extra pulls
> `playwright` because the [Accessibility tests](../docs/ACCESSIBILITY.md)
> use it. The launcher itself does not depend on Playwright.)

## Quick start

```bash
reqlore browser
```

That's it. Reqlore:

1. Downloads Firefox if the cached install is missing.
2. Generates / loads the Reqlore CA from `~/.reqlore/ca/`.
3. Writes a `distribution/policies.json` next to the Firefox binary that:
   - Trusts the Reqlore CA (no user prompt).
   - Locks the HTTP / HTTPS proxy to the running Reqlore proxy.
4. Spawns Firefox with the dedicated profile under `~/.reqlore/firefox-profile/`.
5. Opens the Reqlore UI URL.

Browse the target as you normally would; every request lands in
[History](modules/history.md) and is visible in [Proxy](modules/proxy.md).

## CLI

```text
reqlore browser [OPTIONS]

  --project PATH            Project .rlr file. When given, DOM Hunter is force-installed
                            into the profile (see modules/dom-hunter.md).
  --proxy-port INT          Proxy port to connect Firefox to (default: from settings).
  --url STR                 Initial URL to open (default: http://127.0.0.1:8787/).
  --firefox-version STR     Pin a Firefox version (e.g. "127.0"). Default: latest from Mozilla.
  --firefox-zip PATH        Use a pre-downloaded archive (.zip / .tar.xz / .exe). Skips download.
  --use-system              Prefer host Firefox install over the managed cache.
  --channel {release,devedition}
                            Firefox release channel to download. Defaults to 'devedition'
                            when --project is given (the DOM Hunter sideload uses an
                            unsigned XPI, which Release/Beta silently reject), else 'release'.
  --wait                    Block until Firefox exits (default: spawn-and-return).
```

Handler: `cmd_browser()` in `reqlore/cli.py`.

## Prefetch (offline / CI)

For air-gapped boxes or reproducible CI, download once on an
internet-connected host:

```bash
./scripts/prefetch-firefox.sh             # latest version
./scripts/prefetch-firefox.sh 127.0       # pinned
FORCE=1 ./scripts/prefetch-firefox.sh     # re-download
```

PowerShell equivalent:

```powershell
.\scripts\prefetch-firefox.ps1
.\scripts\prefetch-firefox.ps1 -Version 127.0
.\scripts\prefetch-firefox.ps1 -Force
```

Both wrap `python -m reqlore.cli prefetch-firefox`. Then tar / zip the
entire cache root (see *Layout* below) and unpack on the air-gapped
host. The next `reqlore browser` reuses the cache.

## Layout

### Cache root (Firefox binaries)

| OS              | Path                                                          |
|-----------------|---------------------------------------------------------------|
| Windows         | `%APPDATA%\reqlore\firefox\` (`~\AppData\Roaming\reqlore\firefox`) |
| macOS / Linux   | `$XDG_DATA_HOME/reqlore/firefox/` (`~/.local/share/reqlore/firefox`) |

Per-version tree (Release stays at the root for back-compat; non-Release
channels nest under a channel directory):

```
~/.local/share/reqlore/firefox/
├── 127.0/firefox/firefox            (Release — Linux executable)
├── 128.0/firefox/firefox
├── devedition/
│   └── 143.0b9/firefox/firefox      (Dev Edition — used when --project is given)
└── firefox-profile/                 (shared across versions and channels)
    ├── user.js
    └── …
```

Helpers: `cache_root()`, `cached_install(version, *, channel)`,
`profile_root()` in `reqlore/browser.py`. The channel table is
`reqlore.browser.CHANNELS`.

### Profile

`~/.reqlore/firefox-profile/`. Persists across launches (cookies,
cache, history accumulate). Firefox is launched with `--profile <dir>
--no-remote` to isolate it from your default profile.

`user.js` is seeded on first launch to suppress first-run nags and to
set `network.proxy.allow_hijacking_localhost = true` so localhost
traffic goes through the proxy.

### CA certificate

`~/.reqlore/ca/`:

| File              | Notes                                                         |
|-------------------|---------------------------------------------------------------|
| `reqlore-ca.pem`  | Public certificate. Installed into Firefox via policies.json. |
| `reqlore-ca.key`  | Private key. **0600** on POSIX. Never share.                  |

Subject: `CN=Reqlore Local Root CA, O=Reqlore`. RSA 2048, valid for
5 years. Generated on first run by `ensure_ca(ca_dir)` in
`reqlore/proxy/ca.py`.

## How Firefox gets trust + proxy

Reqlore avoids `certutil` and the NSS cert DB. Instead it uses
Mozilla's **Enterprise Policy** mechanism — `distribution/policies.json`
next to the Firefox binary:

```json
{
  "policies": {
    "Certificates": {
      "Install": ["/home/you/.reqlore/ca/reqlore-ca.pem"],
      "ImportEnterpriseRoots": false
    },
    "Proxy": {
      "Mode": "manual",
      "HTTPProxy": "127.0.0.1:8080",
      "SSLProxy": "127.0.0.1:8080",
      "UseHTTPProxyForAllProtocols": true,
      "Passthrough": "",
      "Locked": true
    }
  }
}
```

- `Locked: true` blocks user override via `about:preferences`.
- `Certificates.Install` adds the PEM to the runtime cert store at
  startup — no UI prompt.

Implementation: `install_policies()` in `reqlore/browser.py`.

## Download details

If `--firefox-version` isn't pinned, Reqlore fetches the latest from
`https://product-details.mozilla.org/1.0/firefox_versions.json`.
Version string is validated against `^\d+\.\d+(\.\d+)?$`.

Archives come from `https://archive.mozilla.org/pub/firefox/releases/<version>/<platform>/<lang>/`:

| Platform       | Filename                            |
|----------------|-------------------------------------|
| Windows 64-bit | `Firefox Setup <version>.exe` (NSIS; extracted silently with `/S`) |
| Linux x86_64   | `firefox-<version>.tar.xz`          |
| macOS          | not auto-downloaded — falls back to host Firefox.app on PATH |

SHA256 verified against the release's `SHA256SUMS` file. Mismatch →
delete + raise.

## Linux runtime dependencies

On first Linux launch, `ensure_linux_runtime()` runs `ldd` against the
Firefox binary and, if any soname is missing, attempts to install it
via the detected package manager (`apt`, `dnf`, `pacman`, `zypper`,
`apk`). Typical libs: `libasound2`, `libdbus-glib-1-2`, `libgtk-3-0`,
`libx11-xcb1`, `libxt6`, `libpci3`.

Disable with `REQLORE_NO_AUTODEPS=1`.

## WSL

`is_wsl()` checks `/proc/version` and `$WSL_DISTRO_NAME`. In WSL,
`reqlore browser` does **not** launch Firefox inside the WSL VM —
instead it opens the Reqlore UI on the Windows host browser via
`cmd.exe /c start` (or `wslview` if available), prints the proxy
address and CA cert path, and leaves you to configure the Windows
browser by hand.

## Recipes

### Open Reqlore UI

```bash
reqlore browser
```

### Open a specific target

```bash
reqlore browser --url https://target.example.com/login
```

### Use system Firefox (skip download)

```bash
reqlore browser --use-system
```

### Pin to a version that you know works

```bash
reqlore browser --firefox-version 127.0
```

### Use a downloaded zip

```bash
reqlore browser --firefox-zip ~/Downloads/firefox-127.0.tar.xz
```

### Air-gapped install

1. On internet host: `./scripts/prefetch-firefox.sh 127.0`.
2. `tar -czf reqlore-firefox.tar.gz ~/.local/share/reqlore/firefox/`.
3. Copy to air-gapped host; `tar -xzf` to the same path.
4. `reqlore browser` — uses the cached install.

### Reset the profile

`rm -rf ~/.reqlore/firefox-profile/` — next launch reseeds `user.js`.

### Rotate the CA

`rm -rf ~/.reqlore/ca/` — next proxy / browser launch regenerates the
CA and policies.json. Existing browser profiles will trust the new CA
on next start (policies.json is re-installed).

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `reqlore: command not found`                              | Not installed, or the venv isn't on PATH                                | `pip install reqlore`; check `which reqlore`.                                                    |
| `SHA256 mismatch` on download                             | Mirror is wedged or version was re-spun                                 | Re-run; if persistent, pin a known-good version.                                                  |
| Firefox crashes immediately on Linux                     | Missing system lib                                                       | Re-run; check `ldd` output. If `REQLORE_NO_AUTODEPS=1` was set, install libs manually.            |
| "Profile is in use" error                                 | Another Firefox is using `--no-remote` on the same profile               | Close the other; or `rm ~/.reqlore/firefox-profile/lock`.                                         |
| HTTPS pages still show cert errors                        | policies.json didn't take                                                | Confirm `distribution/policies.json` exists next to firefox.exe; re-launch. Restart Firefox cleanly. |
| Localhost (`127.0.0.1:5000`) bypasses the proxy           | Firefox bypasses localhost by default                                   | Reqlore sets `network.proxy.allow_hijacking_localhost=true` in user.js. Wipe `~/.reqlore/firefox-profile/user.js` and re-launch if it's been overwritten. |
| WSL: nothing happens                                      | Launcher opened on the Windows host browser                              | Look at the Windows side; configure proxy + CA there manually using the printed instructions.    |
| Air-gapped install can't find a binary                    | Cache wasn't copied to the exact same path                              | `cache_root()` is per-user — make sure `~/.local/share/reqlore/firefox/<version>/` exists.        |

## Test contract

`reqlore/tests/unit/test_phase8_browser.py`:

- `test_detect_platform_returns_known_or_none` — `PlatformSpec` shape.
- `test_cache_root_creates_dir` — cache dir bootstrap.
- `test_cached_install_path` — path construction.
- `test_find_firefox_prefers_cache` — discovery order.
- `test_find_firefox_falls_back_to_shutil_which` — system fallback.
- `test_build_archive_url_win64` / `test_build_archive_url_linux` — URL generation.
- `test_latest_version_validates_payload` / `test_latest_version_rejects_bad_payload` — JSON validation.
- Offline archive fixtures: `_fake_zip_archive()`, `_fake_tarxz_archive()`.

All paths are exercised via monkeypatch — no real Firefox downloads
during the test run.
