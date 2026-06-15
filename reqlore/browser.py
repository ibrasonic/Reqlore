"""Portable-Firefox launcher for Reqlore.

Lets the user spin up a *dedicated* Firefox profile pre-configured to:
  - route all HTTP/HTTPS traffic through Reqlore's MITM proxy (127.0.0.1:8080)
  - trust Reqlore's CA (via Firefox enterprise policies)
  - open the Reqlore UI on first launch
  - leave the host's existing Firefox install (if any) completely untouched

If Firefox is already on PATH we use it. Otherwise we download the official
portable build from `archive.mozilla.org` on first run, cache it under
``~/.reqlore/firefox/<version>/``, and reuse it forever after.

For offline / air-gapped use, call :func:`download_firefox` ahead of time
with ``--firefox-zip`` pointing at a pre-staged archive.

Only stdlib + ``cryptography`` (already a dependency). No new pip deps.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

VERSIONS_JSON_URL = "https://product-details.mozilla.org/1.0/firefox_versions.json"
ARCHIVE_BASE = "https://archive.mozilla.org/pub/firefox/releases"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_LANG = "en-US"

# Per-channel download config. Release is the small, fast default. Dev
# Edition is what we ship when DOM Hunter is enabled because it honours
# `xpinstall.signatures.required=false` (Release / Beta do not, so an
# unsigned, sideloaded XPI is silently dropped).
CHANNELS: dict[str, dict[str, str]] = {
    "release": {
        "archive_base": "https://archive.mozilla.org/pub/firefox/releases",
        "version_key": "LATEST_FIREFOX_VERSION",
    },
    "devedition": {
        "archive_base": "https://archive.mozilla.org/pub/devedition/releases",
        "version_key": "FIREFOX_DEVEDITION",
    },
}
DEFAULT_CHANNEL = "release"
# Version strings accept the optional Dev-Edition beta suffix (e.g. 143.0b9).
_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?(b\d+)?$")


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlatformSpec:
    """Per-OS build descriptor."""
    key: str                # "win64" | "linux64" | "macos"
    archive_name: str       # e.g. "firefox-127.0.zip"
    archive_subdir: str     # subdir inside the archive layout
    exe_relpath: str        # path to the firefox executable inside the extracted tree
    extractor: str          # "zip" | "tar.xz" | "dmg"


def detect_platform() -> PlatformSpec | None:
    """Return the platform spec for the current OS, or None if unsupported."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows" and ("64" in machine or machine in {"amd64", "x86_64"}):
        # Mozilla only ships the NSIS installer on Windows (no plain zip).
        # We run it silently into our cache dir — no admin, no shortcuts,
        # no maintenance service, and (critically) the `distribution/`
        # folder is created so policies.json has a home.
        return PlatformSpec(
            key="win64",
            archive_name="Firefox Setup {ver}.exe",
            archive_subdir="win64/{lang}",
            exe_relpath="firefox.exe",
            extractor="exe-installer",
        )
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return PlatformSpec(
            key="linux-x86_64",
            archive_name="firefox-{ver}.tar.xz",
            archive_subdir="linux-x86_64/{lang}",
            exe_relpath="firefox/firefox",
            extractor="tar.xz",
        )
    if system == "Darwin":
        # macOS ships a .dmg which requires hdiutil to mount; we don't
        # auto-install on macOS — fall back to "use Firefox.app on PATH".
        return None
    return None


# ---------------------------------------------------------------------------
# Cache layout
# ---------------------------------------------------------------------------

def cache_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "reqlore" / "firefox"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# WSL detection + Windows-host hand-off
# ---------------------------------------------------------------------------

def is_wsl() -> bool:
    """True when running inside the Windows Subsystem for Linux.

    Detects WSL1 and WSL2 by reading ``/proc/version`` (contains
    ``microsoft`` or ``WSL`` on every WSL kernel since 2017) and by
    honouring the ``$WSL_DISTRO_NAME`` env var that WSL2 always sets.
    Pure function, safe to call on any platform — Windows / macOS /
    native Linux all return False.
    """
    if platform.system() != "Linux":
        return False
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        proc_version = Path("/proc/version").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    lowered = proc_version.lower()
    return "microsoft" in lowered or "wsl" in lowered


def open_on_windows_host(url: str, *, timeout_s: float = 10.0) -> str | None:
    """Open *url* on the Windows host browser from inside WSL.

    Tries ``cmd.exe /c start "" <url>`` first (present on every WSL
    install) and falls back to ``wslview <url>`` (from the ``wslu``
    package). Returns the name of the opener that worked
    (``"cmd.exe"`` or ``"wslview"``), or ``None`` if neither succeeded.

    The empty-string title in ``start "" <url>`` is required: Windows
    treats the first quoted argument as the window title, not the URL.
    """
    candidates: list[tuple[str, list[str]]] = []
    cmd_exe = shutil.which("cmd.exe") or "/mnt/c/Windows/System32/cmd.exe"
    if Path(cmd_exe).exists() or shutil.which("cmd.exe"):
        candidates.append(("cmd.exe", [cmd_exe, "/c", "start", "", url]))
    wslview = shutil.which("wslview")
    if wslview:
        candidates.append(("wslview", [wslview, url]))

    for name, argv in candidates:
        try:
            proc = subprocess.run(  # noqa: S603
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_s,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.info("WSL host opener %s failed: %s", name, exc)
            continue
        if proc.returncode == 0:
            log.info("opened %s via %s", url, name)
            return name
        log.info("WSL host opener %s exited %d", name, proc.returncode)
    return None


def profile_root() -> Path:
    """Where the dedicated Firefox profile lives."""
    return cache_root().parent / "firefox-profile"


def cached_install(version: str, *, channel: str = DEFAULT_CHANNEL) -> Path:
    """Path to the per-version extracted Firefox tree.

    Channel-keyed subdir so Release and Dev Edition can coexist in the
    cache without colliding. Release stays at ``<cache>/<version>/`` for
    backward compat with existing installs.
    """
    if channel == DEFAULT_CHANNEL:
        return cache_root() / version
    return cache_root() / channel / version


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_firefox(*, prefer_cache: bool = True,
                 channel: str | None = None) -> Path | None:
    """Return an absolute path to a usable firefox executable.

    If ``prefer_cache`` is True (the default) we prefer our managed cache
    over a host install — guarantees the user gets the policies.json setup.
    When ``channel`` is given (``"release"`` / ``"devedition"``) we only
    consider the cache subtree for that channel; ``None`` means "any".
    """
    spec = detect_platform()
    if prefer_cache and spec is not None:
        roots: list[Path] = []
        cache = cache_root()
        if channel == "devedition":
            roots.append(cache / "devedition")
        elif channel == "release":
            roots.append(cache)
        else:
            roots.append(cache)
            roots.append(cache / "devedition")
        for root in roots:
            if not root.exists():
                continue
            # Pick the most-recent version dir that contains the exe.
            candidates = sorted(
                (p for p in root.iterdir()
                 if p.is_dir() and _VERSION_RE.match(p.name)),
                key=lambda p: p.name, reverse=True,
            )
            for c in candidates:
                exe = c / spec.exe_relpath
                if exe.exists():
                    return exe

    # System fallback.
    for name in ("firefox", "firefox.exe"):
        p = shutil.which(name)
        if p:
            return Path(p)

    # macOS Firefox.app
    mac_app = Path("/Applications/Firefox.app/Contents/MacOS/firefox")
    if mac_app.exists():
        return mac_app

    return None


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def latest_version(timeout_s: float = DEFAULT_TIMEOUT_S,
                   *, channel: str = DEFAULT_CHANNEL) -> str:
    """Fetch the current version string for ``channel`` from Mozilla."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown Firefox channel: {channel!r}")
    key = CHANNELS[channel]["version_key"]
    req = urllib.request.Request(
        VERSIONS_JSON_URL, headers={"User-Agent": "reqlore-browser/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as r:  # noqa: S310
        data = json.loads(r.read().decode("utf-8"))
    ver = data.get(key)
    if not isinstance(ver, str) or not _VERSION_RE.match(ver):
        raise RuntimeError(f"unexpected version payload from Mozilla: {ver!r}")
    return ver


def _build_archive_url(spec: PlatformSpec, version: str, lang: str,
                       *, channel: str = DEFAULT_CHANNEL) -> str:
    base = CHANNELS[channel]["archive_base"]
    subdir = spec.archive_subdir.format(lang=lang)
    fname = spec.archive_name.format(ver=version)
    quoted = urllib.parse.quote(fname)
    return f"{base}/{version}/{subdir}/{quoted}"


def _sha256_sums_url(version: str,
                     *, channel: str = DEFAULT_CHANNEL) -> str:
    base = CHANNELS[channel]["archive_base"]
    return f"{base}/{version}/SHA256SUMS"


def _fetch_expected_sha(version: str, archive_basename: str, lang: str,
                        spec: PlatformSpec, timeout_s: float,
                        *, channel: str = DEFAULT_CHANNEL) -> str | None:
    """Parse Mozilla's SHA256SUMS file for the archive's expected hash.

    Returns None if the line isn't found (e.g. very old version layout) —
    we treat that as 'skip verification, log a warning'.
    """
    req = urllib.request.Request(
        _sha256_sums_url(version, channel=channel),
        headers={"User-Agent": "reqlore-browser/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:  # noqa: S310
            body = r.read().decode("utf-8", errors="replace")
    except Exception as exc:
        log.warning("could not fetch SHA256SUMS for %s: %s", version, exc)
        return None
    needle = f"{spec.archive_subdir.format(lang=lang)}/{archive_basename}"
    for line in body.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[1] == needle:
            return parts[0].lower()
    return None


def _download(url: str, dest: Path, timeout_s: float,
              progress: bool = True) -> None:
    log.info("downloading %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "reqlore-browser/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_s) as r, open(dest, "wb") as f:  # noqa: S310
        total = int(r.headers.get("Content-Length") or 0)
        seen = 0
        chunk = 1024 * 64
        last_pct = -1
        while True:
            buf = r.read(chunk)
            if not buf:
                break
            f.write(buf)
            seen += len(buf)
            if progress and total:
                pct = (seen * 100) // total
                if pct != last_pct and pct % 5 == 0:
                    log.info("  ... %d%% (%d / %d KiB)",
                             pct, seen // 1024, total // 1024)
                    last_pct = pct


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _extract(archive: Path, target: Path, kind: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(target)
        return
    if kind == "tar.xz":
        with tarfile.open(archive, mode="r:xz") as t:
            t.extractall(target, filter="data")  # py3.12+ safe extract filter
        return
    if kind == "exe-installer":
        _run_firefox_installer(archive, target)
        return
    raise RuntimeError(f"unsupported extractor: {kind}")


def _run_firefox_installer(installer: Path, target: Path) -> None:
    """Run Mozilla's NSIS Setup .exe silently into `target`.

    Mozilla's installer is portable when invoked with these flags and an
    explicit `InstallDirectoryPath`. It writes only into the target dir
    (plus a small HKCU uninstall registry entry that we ignore). No admin
    required when `target` is user-writable.
    """
    target.mkdir(parents=True, exist_ok=True)
    args = [
        str(installer),
        f"/InstallDirectoryPath={target}",
        "/TaskbarShortcut=false",
        "/DesktopShortcut=false",
        "/StartMenuShortcut=false",
        "/MaintenanceService=false",
        "/PrivateBrowsingShortcut=false",
        "/RemoveDistributionDir=false",
        "/S",
    ]
    log.info("running silent installer: %s", " ".join(args))
    proc = subprocess.run(args, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise RuntimeError(
            f"Firefox installer exited with status {proc.returncode}"
        )
    exe = target / "firefox.exe"
    if not exe.exists():
        raise RuntimeError(
            f"installer finished but {exe} not found — install layout changed?"
        )


def download_firefox(*, version: str | None = None,
                     lang: str = DEFAULT_LANG,
                     timeout_s: float = DEFAULT_TIMEOUT_S,
                     archive_path: Path | None = None,
                     force: bool = False,
                     channel: str = DEFAULT_CHANNEL) -> Path:
    """Ensure a portable Firefox is available; return path to the exe.

    Parameters
    ----------
    version:
        Pin a Firefox release (e.g. ``"127.0"``, or ``"143.0b9"`` for
        Dev Edition). Defaults to the latest published version for the
        requested ``channel`` (from product-details.mozilla.org).
    archive_path:
        If given, **skip the download** and use this local file (must be a
        Mozilla-format zip/tar.xz matching the host OS). Lets air-gapped
        users pre-stage the archive offline.
    force:
        Re-extract even if a cached install already exists.
    channel:
        ``"release"`` (default) or ``"devedition"``. Dev Edition is
        required for DOM Hunter sideloading because Release / Beta
        enforce extension signing.
    """
    if channel not in CHANNELS:
        raise ValueError(f"unknown Firefox channel: {channel!r}")
    spec = detect_platform()
    if spec is None:
        raise RuntimeError(
            "Auto-download is not supported on this OS — "
            "install Firefox manually and make sure it's on PATH."
        )

    if version is None:
        if archive_path is not None:
            m = re.search(
                r"(?:firefox-|Firefox Setup )(\d+\.\d+(?:\.\d+)?(?:b\d+)?)\."
                r"(?:zip|tar\.xz|exe|msi)$",
                archive_path.name,
            )
            if not m:
                raise RuntimeError(
                    f"cannot infer version from filename: {archive_path.name}"
                )
            version = m.group(1)
        else:
            version = latest_version(timeout_s=timeout_s, channel=channel)

    target = cached_install(version, channel=channel)
    exe = target / spec.exe_relpath
    if exe.exists() and not force:
        log.info("using cached Firefox %s at %s", version, exe)
        return exe

    if target.exists() and force:
        shutil.rmtree(target)

    if archive_path is not None:
        src = archive_path
        log.info("using local archive: %s", src)
    else:
        archive_name = spec.archive_name.format(ver=version)
        url = _build_archive_url(spec, version, lang, channel=channel)
        # Cache the installer under the channel subdir so different-channel
        # downloads with the same filename pattern don't clobber each other.
        installer_cache = (cache_root() if channel == DEFAULT_CHANNEL
                           else cache_root() / channel)
        installer_cache.mkdir(parents=True, exist_ok=True)
        src = installer_cache / archive_name
        if not src.exists() or force:
            _download(url, src, timeout_s=timeout_s)
        # Verify against Mozilla's SHA256SUMS.
        expected = _fetch_expected_sha(
            version, archive_name, lang, spec, timeout_s, channel=channel,
        )
        if expected:
            actual = _sha256_file(src)
            if actual.lower() != expected:
                src.unlink(missing_ok=True)
                raise RuntimeError(
                    f"SHA256 mismatch for {archive_name}: "
                    f"got {actual}, expected {expected}"
                )
            log.info("SHA256 verified.")
        else:
            log.warning("SHA256 entry not found — skipping verification.")

    log.info("extracting to %s ...", target)
    _extract(src, target, spec.extractor)

    if not exe.exists():
        raise RuntimeError(
            f"extracted archive but {exe} not found — layout changed?"
        )
    log.info("Firefox %s ready: %s", version, exe)
    return exe


# ---------------------------------------------------------------------------
# Policy + profile setup
# ---------------------------------------------------------------------------

def _policies_dict(*, ca_path: Path, proxy_host: str, proxy_port: int,
                   homepage_url: str,
                   dom_hunter_xpi: Path | None = None,
                   dom_hunter_bridge_url: str | None = None,
                   dom_hunter_token: str | None = None) -> dict:
    """Enterprise-policy payload — controls cert trust + proxy + lock-down.

    When ``dom_hunter_xpi`` is provided we also force-install the
    DOM Hunter add-on via ``ExtensionSettings`` (Mozilla exempts
    force-installed add-ons from signing) and seed its bridge URL +
    token via ``3rdparty.Extensions`` (read by the add-on as
    ``browser.storage.managed``).
    """
    pol: dict = {
        "policies": {
            "Certificates": {
                "Install": [str(ca_path)],
                "ImportEnterpriseRoots": False,
            },
            "Proxy": {
                "Mode": "manual",
                "HTTPProxy": f"{proxy_host}:{proxy_port}",
                "SSLProxy": f"{proxy_host}:{proxy_port}",
                "UseHTTPProxyForAllProtocols": True,
                "Passthrough": "",
                "Locked": True,
            },
            "DisableAppUpdate": True,
            "DisableTelemetry": True,
            "DisableFirefoxStudies": True,
            "DisableFirefoxAccounts": True,
            "DisablePocket": True,
            "DontCheckDefaultBrowser": True,
            "OverrideFirstRunPage": homepage_url,
            "OverridePostUpdatePage": "",
            "Homepage": {
                "URL": homepage_url,
                "StartPage": "homepage",
                "Locked": False,
            },
            "PasswordManagerEnabled": False,
            "OfferToSaveLogins": False,
            "NetworkPrediction": False,
            "DisableSafeMode": False,
        }
    }
    if dom_hunter_xpi is not None:
        ext_id = "reqlore-dom-hunter@reqlore.local"
        pol["policies"]["ExtensionSettings"] = {
            ext_id: {
                "installation_mode": "force_installed",
                "install_url": dom_hunter_xpi.as_uri(),
                "default_area": "navbar",
            }
        }
        if dom_hunter_bridge_url or dom_hunter_token:
            pol["policies"]["3rdparty"] = {
                "Extensions": {
                    ext_id: {
                        "baseUrl": dom_hunter_bridge_url or "",
                        "token": dom_hunter_token or "",
                    }
                }
            }
    return pol


def _policies_target_dir(exe: Path) -> Path:
    """Where to drop policies.json relative to the firefox exe."""
    # Windows / Linux: <install-root>/distribution/policies.json
    # macOS: <Firefox.app>/Contents/Resources/distribution/
    if sys.platform == "darwin" and "Firefox.app" in str(exe):
        root = exe.parent.parent / "Resources"
    else:
        root = exe.parent
    return root / "distribution"


def install_policies(*, exe: Path, ca_path: Path,
                     proxy_host: str, proxy_port: int,
                     homepage_url: str,
                     dom_hunter_xpi: Path | None = None,
                     dom_hunter_bridge_url: str | None = None,
                     dom_hunter_token: str | None = None) -> Path:
    """Write policies.json next to the firefox binary. Returns its path."""
    if not ca_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_path}")
    dist = _policies_target_dir(exe)
    dist.mkdir(parents=True, exist_ok=True)
    out = dist / "policies.json"
    payload = _policies_dict(
        ca_path=ca_path, proxy_host=proxy_host, proxy_port=proxy_port,
        homepage_url=homepage_url,
        dom_hunter_xpi=dom_hunter_xpi,
        dom_hunter_bridge_url=dom_hunter_bridge_url,
        dom_hunter_token=dom_hunter_token,
    )
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("wrote policies.json -> %s", out)
    return out


def ensure_profile(profile_dir: Path | None = None) -> Path:
    """Create the dedicated profile directory if it doesn't exist."""
    p = profile_dir or profile_root()
    p.mkdir(parents=True, exist_ok=True)
    # Seed a tiny user.js so Firefox doesn't show 'first-run' nags even
    # when policies.json hasn't been applied yet (first cold boot).
    user_js = p / "user.js"
    if not user_js.exists():
        user_js.write_text(
            "// Reqlore-managed profile — do not edit by hand.\n"
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("browser.startup.homepage_override.mstone", "ignore");\n'
            'user_pref("datareporting.policy.firstRunURL", "");\n'
            'user_pref("trailhead.firstrun.didSeeAboutWelcome", true);\n'
            'user_pref("browser.aboutwelcome.enabled", false);\n'
            # Without this, Firefox silently bypasses the proxy for localhost
            # / 127.0.0.1 / *.localhost, so tests against local lab apps
            # (vuln-bank :3001, vuln-shop :3002, vuln-social :3003) never
            # reach Reqlore's MITM and never appear in History.
            'user_pref("network.proxy.allow_hijacking_localhost", true);\n'
            'user_pref("network.proxy.no_proxies_on", "");\n',
            encoding="utf-8",
        )
    return p


DOM_HUNTER_EXT_ID = "reqlore-dom-hunter@reqlore.local"

# Marker block we append to user.js so the upsert is idempotent.
_DOM_HUNTER_PREFS_MARKER = "// >>> reqlore: DOM Hunter sideload prefs"
_DOM_HUNTER_PREFS_END = "// <<< reqlore: DOM Hunter sideload prefs"
_DOM_HUNTER_PREFS_BLOCK = (
    _DOM_HUNTER_PREFS_MARKER + "\n"
    # Allow loading unsigned XPIs from the profile's extensions/ folder.
    # Honoured by Firefox Developer Edition, Nightly, ESR and Unbranded
    # builds only; Release / Beta silently reject unsigned add-ons.
    'user_pref("xpinstall.signatures.required", false);\n'
    # Sideloaded add-ons would normally appear DISABLED and prompt the
    # user; 0 = auto-enable everything we drop into the profile.
    'user_pref("extensions.autoDisableScopes", 0);\n'
    # 15 = SCOPE_PROFILE|SCOPE_USER|SCOPE_APPLICATION|SCOPE_SYSTEM, so
    # the profile-level XPI is in the enabled set.
    'user_pref("extensions.enabledScopes", 15);\n'
    + _DOM_HUNTER_PREFS_END + "\n"
)


def sideload_dom_hunter(*, profile_dir: Path, xpi_path: Path) -> Path:
    """Copy the DOM Hunter XPI into the profile and enable unsigned loading.

    Profile-sideload is the fallback path for environments where the
    ``ExtensionSettings`` enterprise policy is overridden by a corporate
    HKLM registry entry (which silently replaces our distribution/
    policies.json entry wholesale, leaving no force-installed add-on).

    Returns the final on-disk XPI path inside the profile.

    Caveat: signature enforcement can only be disabled on Firefox
    Developer Edition, Nightly, ESR or Unbranded builds. On Release /
    Beta the unsigned XPI will be silently dropped at launch.
    """
    ext_dir = profile_dir / "extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    dest = ext_dir / f"{DOM_HUNTER_EXT_ID}.xpi"
    tmp = dest.with_suffix(".xpi.tmp")

    # Fast path: if the XPI already on disk matches the source byte for
    # byte, nothing to do. This is the common case when the user re-runs
    # `reqlore browser --project ...` while a managed Firefox is still
    # open with the same profile -- on Windows the running browser holds
    # an exclusive lock on the XPI and `tmp.replace(dest)` would raise
    # WinError 5 / PermissionError, but there is no actual work to do.
    if dest.exists():
        try:
            if _files_equal(xpi_path, dest):
                _ensure_dom_hunter_user_js(profile_dir)
                log.debug("DOM Hunter XPI already up to date -> %s", dest)
                return dest
        except OSError:
            # If we cannot read either file we fall through to the copy
            # attempt, which will produce a clearer error.
            pass

    # Clean up any stale .xpi.tmp left by a previous crashed run.
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass

    try:
        shutil.copy2(xpi_path, tmp)
        # Atomic-ish replace so a half-written XPI never lingers.
        tmp.replace(dest)
    except PermissionError as exc:
        # Most likely: a managed Firefox is already running against this
        # same profile and is holding the XPI open. Clean up our scratch
        # file and re-raise with a message the user can act on.
        try:
            tmp.unlink()
        except OSError:
            pass
        raise PermissionError(
            f"cannot replace DOM Hunter XPI at {dest}: file is in use "
            f"(close any running 'reqlore browser' for this profile, "
            f"then re-run). Underlying error: {exc}"
        ) from exc

    _ensure_dom_hunter_user_js(profile_dir)
    log.info("DOM Hunter XPI sideloaded -> %s", dest)
    return dest


def _files_equal(a: Path, b: Path, *, chunk: int = 1 << 16) -> bool:
    """True iff *a* and *b* have identical content. Cheap-path on size."""
    if a.stat().st_size != b.stat().st_size:
        return False
    with a.open("rb") as fa, b.open("rb") as fb:
        while True:
            ba = fa.read(chunk)
            bb = fb.read(chunk)
            if ba != bb:
                return False
            if not ba:
                return True


def _ensure_dom_hunter_user_js(profile_dir: Path) -> None:
    """Idempotently append the DOM Hunter prefs block to user.js."""
    user_js = profile_dir / "user.js"
    existing = user_js.read_text(encoding="utf-8") if user_js.exists() else ""
    if _DOM_HUNTER_PREFS_MARKER not in existing:
        user_js.write_text(existing + "\n" + _DOM_HUNTER_PREFS_BLOCK,
                           encoding="utf-8")


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

# Mozilla's portable Firefox tarball ships only its own xul/gfx code; everything
# else (ALSA, GTK, dbus-glib, X11 helpers, libpci) has to come from the host.
# A minimal cloud image (WSL Ubuntu, slim Docker, etc.) doesn't have these and
# Firefox dies at startup with `XPCOMGlueLoad error ... libasound.so.2: cannot
# open shared object file`. We detect the missing sonames with `ldd` and try
# the system package manager once before launching.
LINUX_RUNTIME_PACKAGES: dict[str, dict[str, list[str]]] = {
    # soname -> { pkgmgr -> [candidate package names; first that exists wins] }
    "libasound.so.2": {
        "apt": ["libasound2t64", "libasound2"],
        "dnf": ["alsa-lib"],
        "pacman": ["alsa-lib"],
        "zypper": ["libasound2"],
        "apk": ["alsa-lib"],
    },
    "libdbus-glib-1.so.2": {
        "apt": ["libdbus-glib-1-2"],
        "dnf": ["dbus-glib"],
        "pacman": ["dbus-glib"],
        "zypper": ["dbus-1-glib"],
        "apk": ["dbus-glib"],
    },
    "libgtk-3.so.0": {
        "apt": ["libgtk-3-0t64", "libgtk-3-0"],
        "dnf": ["gtk3"],
        "pacman": ["gtk3"],
        "zypper": ["libgtk-3-0"],
        "apk": ["gtk+3.0"],
    },
    "libX11-xcb.so.1": {
        "apt": ["libx11-xcb1"],
        "dnf": ["libX11-xcb"],
        "pacman": ["libx11"],
        "zypper": ["libX11-xcb1"],
        "apk": ["libx11"],
    },
    "libXt.so.6": {
        "apt": ["libxt6"],
        "dnf": ["libXt"],
        "pacman": ["libxt"],
        "zypper": ["libXt6"],
        "apk": ["libxt"],
    },
    "libpci.so.3": {
        "apt": ["libpci3"],
        "dnf": ["pciutils-libs"],
        "pacman": ["pciutils"],
        "zypper": ["libpci3"],
        "apk": ["pciutils-libs"],
    },
    "libdbus-1.so.3": {
        "apt": ["libdbus-1-3"],
        "dnf": ["dbus-libs"],
        "pacman": ["dbus"],
        "zypper": ["libdbus-1-3"],
        "apk": ["dbus-libs"],
    },
}

_PKGMGR_INSTALL_CMD: dict[str, list[str]] = {
    "apt":    ["apt-get", "install", "-y", "--no-install-recommends"],
    "dnf":    ["dnf", "install", "-y"],
    "pacman": ["pacman", "-S", "--noconfirm", "--needed"],
    "zypper": ["zypper", "--non-interactive", "install", "--no-recommends"],
    "apk":    ["apk", "add", "--no-cache"],
}
_PKGMGR_REFRESH_CMD: dict[str, list[str]] = {
    "apt":    ["apt-get", "update"],
    "dnf":    [],
    "pacman": ["pacman", "-Sy"],
    "zypper": ["zypper", "--non-interactive", "refresh"],
    "apk":    ["apk", "update"],
}


def _detect_linux_pkgmgr() -> str | None:
    """Pick the first package manager actually on PATH."""
    for name in ("apt-get", "dnf", "pacman", "zypper", "apk"):
        if shutil.which(name):
            return "apt" if name == "apt-get" else name
    return None


def _ldd_missing(exe: Path) -> list[str]:
    """Return sonames `ldd` reports as 'not found' for `exe`."""
    if not shutil.which("ldd"):
        return []
    try:
        r = subprocess.run(  # noqa: S603
            ["ldd", str(exe)],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = (r.stdout or "") + (r.stderr or "")
    missing: list[str] = []
    for line in out.splitlines():
        # "        libasound.so.2 => not found"
        m = re.match(r"\s*([^\s]+)\s+=>\s+not found", line)
        if m:
            soname = m.group(1)
            if soname not in missing:
                missing.append(soname)
    return missing


def _apt_pkg_exists(pkg: str) -> bool:
    r = subprocess.run(  # noqa: S603
        ["apt-cache", "show", pkg],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0 and bool((r.stdout or "").strip())


def _pick_packages(missing: list[str], pkgmgr: str) -> list[str]:
    """Resolve missing sonames to concrete package names for `pkgmgr`."""
    chosen: list[str] = []
    for soname in missing:
        candidates = LINUX_RUNTIME_PACKAGES.get(soname, {}).get(pkgmgr, [])
        if not candidates:
            continue
        picked: str | None = None
        if pkgmgr == "apt":
            for c in candidates:
                if _apt_pkg_exists(c):
                    picked = c
                    break
        picked = picked or candidates[0]
        if picked not in chosen:
            chosen.append(picked)
    return chosen


def _sudo_prefix() -> list[str] | None:
    """Return [] if root, ['sudo','-n'] if non-interactive sudo works, else None.

    `sudo -n` exits 1 immediately when a password would be required, so we
    never block the launch on a hidden prompt the user can't see.
    """
    if os.geteuid() == 0:  # type: ignore[attr-defined]
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        return None
    r = subprocess.run([sudo, "-n", "true"],  # noqa: S603
                       capture_output=True, text=True)
    if r.returncode == 0:
        return [sudo, "-n"]
    return None  # sudo exists but would prompt for a password


def ensure_linux_runtime(exe: Path) -> list[str]:
    """Best-effort: install missing host libs Firefox needs. Returns leftover sonames.

    No-op on non-Linux. Skipped entirely if REQLORE_NO_AUTODEPS=1. Only tries
    the package manager when sudo is available without a password prompt.
    """
    if platform.system() != "Linux":
        return []
    if os.environ.get("REQLORE_NO_AUTODEPS") == "1":
        return _ldd_missing(exe)

    missing = _ldd_missing(exe)
    if not missing:
        return []

    pkgmgr = _detect_linux_pkgmgr()
    if pkgmgr is None:
        log.warning("Firefox needs %s but no supported package manager was found.",
                    ", ".join(missing))
        return missing

    pkgs = _pick_packages(missing, pkgmgr)
    if not pkgs:
        log.warning("Firefox needs %s but no package mapping is known for %s.",
                    ", ".join(missing), pkgmgr)
        return missing

    sudo = _sudo_prefix()
    if sudo is None:
        cmd = " ".join(_PKGMGR_INSTALL_CMD[pkgmgr] + pkgs)
        print(
            "\nReqlore: Firefox is missing host libraries and I can't elevate "
            "non-interactively.\n"
            f"  Missing: {', '.join(missing)}\n"
            f"  Run:     sudo {cmd}\n",
            file=sys.stderr,
        )
        return missing

    print(f"\nReqlore: installing Firefox runtime deps via {pkgmgr}: "
          f"{', '.join(pkgs)}\n", file=sys.stderr)

    refresh = _PKGMGR_REFRESH_CMD.get(pkgmgr, [])
    if refresh:
        subprocess.run(sudo + refresh, check=False)  # noqa: S603
    install_cmd = sudo + _PKGMGR_INSTALL_CMD[pkgmgr] + pkgs
    r = subprocess.run(install_cmd, check=False)  # noqa: S603
    if r.returncode != 0:
        log.warning("package install exited %d; continuing anyway", r.returncode)

    leftover = _ldd_missing(exe)
    if leftover:
        log.warning("still missing after install: %s", ", ".join(leftover))
    return leftover


@dataclass
class LaunchResult:
    exe: Path
    profile: Path
    policies: Path
    pid: int | None


# Firefox writes a profile lock named `lock` (POSIX) / `parent.lock` (Windows)
# in the profile dir. If we try to launch a second instance pointed at the
# same profile, Firefox prints "Firefox is already running" and exits 1.
_FIREFOX_ALREADY_RUNNING_RE = re.compile(
    r"firefox is already running|profile is in use", re.IGNORECASE,
)
_FIREFOX_XPCOM_RE = re.compile(
    r"XPCOMGlueLoad|libxul\.so", re.IGNORECASE,
)


def _explain_firefox_exit(returncode: int, stderr_text: str) -> str:
    """Turn a Firefox crash into something a human can act on."""
    text = stderr_text.strip()
    snippet = text[-400:] if text else ""

    if _FIREFOX_ALREADY_RUNNING_RE.search(text):
        return (
            "Firefox is already running against the Reqlore profile.\n"
            "  Close the existing Reqlore-Firefox window, then re-run "
            "`reqlore browser`.\n"
            "  (Profile dir: " + str(profile_root()) + ")"
        )

    if _FIREFOX_XPCOM_RE.search(text):
        # Try to enumerate exactly what's missing so the message is concrete.
        # We can't reach `exe` here cleanly without plumbing it through, so
        # parse the soname out of the stderr itself.
        m = re.search(r"([A-Za-z0-9_.+-]+\.so(?:\.\d+)+):\s+cannot open",
                      text)
        missing_hint = f" (missing {m.group(1)})" if m else ""
        if platform.system() == "Linux":
            return (
                "Firefox can't start: required system libraries are missing"
                f"{missing_hint}.\n"
                "  Reqlore tries to install these automatically, but the "
                "step failed or was skipped.\n"
                "  Re-run with sudo on PATH (or as root), or install "
                "manually:\n"
                "    sudo apt install -y libasound2t64 libdbus-glib-1-2 "
                "libgtk-3-0 libx11-xcb1 libxt6 libpci3\n"
                "  (Use libasound2 instead of libasound2t64 on Ubuntu < 24.04.)"
            )
        return (
            f"Firefox can't load its runtime libraries{missing_hint}.\n"
            "  Last stderr lines:\n    "
            + snippet.replace("\n", "\n    ")
        )

    base = f"Firefox exited with code {returncode}."
    if snippet:
        return base + "\n  Last stderr:\n    " + snippet.replace("\n", "\n    ")
    return base


def launch(*, exe: Path, profile_dir: Path, url: str,
           extra_args: list[str] | None = None,
           wait: bool = False,
           warmup_seconds: float = 2.0) -> LaunchResult:
    """Spawn Firefox pointed at our managed profile.

    Raises RuntimeError with an actionable message if Firefox dies within
    `warmup_seconds` (typical for missing-libs / locked-profile / corrupt-
    install failures).
    """
    args = [
        str(exe),
        "--no-remote",
        "--new-instance",
        "--profile", str(profile_dir),
        url,
    ]
    if extra_args:
        args.extend(extra_args)
    log.info("launching: %s", " ".join(args))

    if wait:
        proc = subprocess.run(args, check=False)  # noqa: S603
        if proc.returncode != 0:
            raise RuntimeError(
                f"Firefox exited with code {proc.returncode}."
            )
        return LaunchResult(
            exe=exe, profile=profile_dir,
            policies=_policies_target_dir(exe) / "policies.json",
            pid=None,
        )

    # Capture stderr to a temp file so we can surface a useful message if
    # Firefox dies during startup. We don't keep it past the warmup window
    # — once Firefox is up, its stderr stays attached to the file but the
    # browser keeps running fine.
    fd, log_path = tempfile.mkstemp(prefix="reqlore-firefox-", suffix=".log")
    os.close(fd)
    log_file = Path(log_path)
    try:
        with log_file.open("wb") as ferr:
            proc = subprocess.Popen(args, stderr=ferr)  # noqa: S603

        deadline = time.monotonic() + max(0.1, warmup_seconds)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        if proc.poll() is not None:
            try:
                err = log_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                err = ""
            # Exit code 0 within the warmup window is *not* a failure:
            # on Windows, firefox.exe is a launcher stub that spawns a
            # worker firefox.exe and exits cleanly. The visible browser
            # window is now owned by the worker process, which we don't
            # track. Treat exit-0 as successful hand-off.
            if proc.returncode == 0:
                log.info("firefox launcher exited 0 (handed off to worker process)")
            else:
                raise RuntimeError(_explain_firefox_exit(proc.returncode, err))
    finally:
        # If Firefox is still running, leave the log file on disk for the
        # operator; otherwise clean it up.
        if proc.poll() is not None:
            try:
                log_file.unlink()
            except OSError:
                pass

    return LaunchResult(
        exe=exe, profile=profile_dir,
        policies=_policies_target_dir(exe) / "policies.json",
        pid=proc.pid,
    )


# ---------------------------------------------------------------------------
# Convenience: one-shot setup + launch
# ---------------------------------------------------------------------------

def run_browser(*, ca_path: Path,
                proxy_host: str = "127.0.0.1", proxy_port: int = 8080,
                ui_url: str = "http://127.0.0.1:8787/",
                version: str | None = None,
                archive_path: Path | None = None,
                prefer_cache: bool = True,
                wait: bool = False,
                project=None,
                channel: str = DEFAULT_CHANNEL) -> LaunchResult:
    """End-to-end: find/download Firefox, install policies, spawn it.

    When ``project`` is supplied we also build the DOM Hunter XPI and
    force-install it into the Reqlore profile, pre-configured with the
    project's bridge URL and bearer token. ``channel`` should be set to
    ``"devedition"`` in that case so the sideload fallback works under
    corporate ExtensionSettings policies (Release / Beta enforce signing
    and silently drop the unsigned XPI).

    Returns a :class:`LaunchResult` so callers can show the user what was set.
    """
    exe = find_firefox(prefer_cache=prefer_cache, channel=channel)
    if exe is None:
        exe = download_firefox(version=version, archive_path=archive_path,
                               channel=channel)
    leftover = ensure_linux_runtime(exe)
    if leftover:
        # ensure_linux_runtime already printed a friendly message; abort
        # before we waste time launching a Firefox that will just die.
        raise RuntimeError(
            "Firefox runtime libraries are missing and could not be "
            "installed automatically: " + ", ".join(leftover) +
            ". See message above for the install command."
        )

    xpi_path: Path | None = None
    bridge_url: str | None = None
    token: str | None = None
    if project is not None:
        try:
            from .dom_hunter import get_or_make_token
            from .dom_hunter.packager import build_xpi
        except ImportError as exc:
            log.warning("DOM Hunter package unavailable, skipping auto-install: %s", exc)
        else:
            try:
                token = get_or_make_token(project)
                bridge_url = ui_url.rstrip("/")
                xpi_dir = profile_root().parent / "dom-hunter"
                xpi_path = build_xpi(out_path=xpi_dir / "dom-hunter.xpi")
                log.info("DOM Hunter XPI built: %s", xpi_path)
            except (OSError, FileNotFoundError) as exc:
                log.warning("DOM Hunter auto-install skipped: %s", exc)
                xpi_path = None

    install_policies(
        exe=exe, ca_path=ca_path,
        proxy_host=proxy_host, proxy_port=proxy_port,
        homepage_url=ui_url,
        dom_hunter_xpi=xpi_path,
        dom_hunter_bridge_url=bridge_url,
        dom_hunter_token=token,
    )
    profile = ensure_profile()
    if xpi_path is not None:
        # Belt-and-suspenders: also sideload via the profile in case the
        # ExtensionSettings policy was overridden by a corporate registry
        # entry (HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox\\ExtensionSettings
        # replaces our distribution/policies.json entry wholesale).
        try:
            sideload_dom_hunter(profile_dir=profile, xpi_path=xpi_path)
            log.info(
                "DOM Hunter sideloaded into profile. Note: Release/Beta\n"
                "  Firefox enforces extension signing and will reject the\n"
                "  unsigned XPI. For the sideload to take effect, use\n"
                "  Firefox Developer Edition, Nightly, ESR, or an Unbranded\n"
                "  build. The ExtensionSettings policy path still works on\n"
                "  Release when no competing HKLM policy is present."
            )
        except PermissionError as exc:
            # XPI is locked by an already-running managed Firefox; the
            # in-use copy is almost certainly the one we wanted anyway,
            # so this is recoverable -- just tell the user clearly.
            log.warning(
                "DOM Hunter sideload skipped: %s "
                "(an existing 'reqlore browser' is running with the same "
                "profile -- close it first if you need to ship a new XPI)",
                exc,
            )
        except OSError as exc:
            log.warning("DOM Hunter sideload skipped: %s", exc)
    return launch(exe=exe, profile_dir=profile, url=ui_url, wait=wait)
