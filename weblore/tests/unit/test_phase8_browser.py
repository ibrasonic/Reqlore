"""Phase 8 — portable Firefox launcher.

These tests are fully offline — we never reach out to Mozilla. The network
helpers are exercised via monkeypatching.
"""
from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from weblore import browser as fxmod


# ---------------------------------------------------------------------------
# Platform spec / cache layout
# ---------------------------------------------------------------------------

def test_detect_platform_returns_known_or_none():
    spec = fxmod.detect_platform()
    # We support win64 and linux x86_64; on macOS / unsupported we return None.
    assert spec is None or spec.key in {"win64", "linux-x86_64"}


def test_cache_root_creates_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    root = fxmod.cache_root()
    assert root.exists() and root.is_dir()
    assert root.name == "firefox"


def test_cached_install_path():
    p = fxmod.cached_install("127.0")
    assert p.name == "127.0"
    assert p.parent == fxmod.cache_root()


# ---------------------------------------------------------------------------
# find_firefox
# ---------------------------------------------------------------------------

def test_find_firefox_prefers_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    spec = fxmod.detect_platform()
    if spec is None:
        pytest.skip("unsupported OS")
    # Stage a fake cached install.
    ver_dir = fxmod.cached_install("999.0")
    fake_exe = ver_dir / spec.exe_relpath
    fake_exe.parent.mkdir(parents=True, exist_ok=True)
    fake_exe.write_bytes(b"\x00")  # presence-only
    found = fxmod.find_firefox(prefer_cache=True)
    assert found is not None
    assert str(found) == str(fake_exe)


def test_find_firefox_falls_back_to_shutil_which(tmp_path, monkeypatch):
    # Empty cache root + monkeypatched shutil.which.
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(fxmod.shutil, "which",
                        lambda n: "/usr/bin/firefox" if "firefox" in n else None)
    assert fxmod.find_firefox(prefer_cache=False) == Path("/usr/bin/firefox")


# ---------------------------------------------------------------------------
# Version + URL helpers
# ---------------------------------------------------------------------------

def test_build_archive_url_win64():
    spec = fxmod.PlatformSpec(
        key="win64",
        archive_name="Firefox Setup {ver}.exe",
        archive_subdir="win64/{lang}",
        exe_relpath="firefox.exe",
        extractor="exe-installer",
    )
    url = fxmod._build_archive_url(spec, "127.0", "en-US")
    # Spaces in the filename must be URL-encoded.
    assert url == ("https://archive.mozilla.org/pub/firefox/releases/"
                   "127.0/win64/en-US/Firefox%20Setup%20127.0.exe")


def test_build_archive_url_linux():
    spec = fxmod.PlatformSpec(
        key="linux-x86_64",
        archive_name="firefox-{ver}.tar.xz",
        archive_subdir="linux-x86_64/{lang}",
        exe_relpath="firefox/firefox",
        extractor="tar.xz",
    )
    url = fxmod._build_archive_url(spec, "127.0", "en-US")
    assert url == ("https://archive.mozilla.org/pub/firefox/releases/"
                   "127.0/linux-x86_64/en-US/firefox-127.0.tar.xz")


def test_latest_version_validates_payload(monkeypatch):
    payload = json.dumps({"LATEST_FIREFOX_VERSION": "127.0.1"}).encode()

    class FakeResp:
        def read(self): return payload
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(fxmod.urllib.request, "urlopen", lambda *a, **kw: FakeResp())
    assert fxmod.latest_version() == "127.0.1"


def test_latest_version_rejects_bad_payload(monkeypatch):
    payload = json.dumps({"LATEST_FIREFOX_VERSION": "garbage"}).encode()

    class FakeResp:
        def read(self): return payload
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(fxmod.urllib.request, "urlopen", lambda *a, **kw: FakeResp())
    with pytest.raises(RuntimeError):
        fxmod.latest_version()


# ---------------------------------------------------------------------------
# download_firefox via local archive (no network)
# ---------------------------------------------------------------------------

def _fake_zip_archive(tmp_path: Path, version: str) -> Path:
    """Build a tiny zip mimicking the Mozilla layout: firefox/firefox.exe."""
    p = tmp_path / f"firefox-{version}.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("firefox/firefox.exe", b"MZ\x90\x00")  # PE header magic
        z.writestr("firefox/marker.txt", "weblore-test")
    return p


def _fake_tarxz_archive(tmp_path: Path, version: str) -> Path:
    p = tmp_path / f"firefox-{version}.tar.xz"
    with tarfile.open(p, mode="w:xz") as t:
        data = b"#!/bin/sh\necho firefox\n"
        info = tarfile.TarInfo("firefox/firefox")
        info.size = len(data)
        info.mode = 0o755
        t.addfile(info, io.BytesIO(data))
    return p


def _fake_installer(tmp_path: Path, version: str) -> Path:
    """Stand-in for `Firefox Setup <ver>.exe`. The real one is an NSIS SFX;
    we just need the filename pattern to match and the rest is stubbed."""
    p = tmp_path / f"Firefox Setup {version}.exe"
    p.write_bytes(b"MZ\x90\x00")  # PE header magic
    return p


def test_download_firefox_uses_local_archive(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    spec = fxmod.detect_platform()
    if spec is None:
        pytest.skip("unsupported OS")
    if spec.extractor == "zip":
        archive = _fake_zip_archive(tmp_path, "999.0")
    elif spec.extractor == "tar.xz":
        archive = _fake_tarxz_archive(tmp_path, "999.0")
    else:
        # exe-installer: can't run the real silent installer in a unit test;
        # stub _extract to mimic a successful install and drop the exe.
        archive = _fake_installer(tmp_path, "999.0")

        def fake_extract(arc: Path, target: Path, kind: str) -> None:
            assert kind == "exe-installer"
            target.mkdir(parents=True, exist_ok=True)
            (target / "firefox.exe").write_bytes(b"MZ\x90\x00")

        monkeypatch.setattr(fxmod, "_extract", fake_extract)

    exe = fxmod.download_firefox(archive_path=archive)
    assert exe.exists()
    assert exe.name in {"firefox.exe", "firefox"}
    # And it's in our managed cache, not the original tmp dir.
    assert fxmod.cache_root() in exe.parents


def test_download_firefox_unsupported_os_raises(monkeypatch):
    monkeypatch.setattr(fxmod, "detect_platform", lambda: None)
    with pytest.raises(RuntimeError, match="not supported"):
        fxmod.download_firefox()


def test_download_firefox_local_archive_bad_filename(tmp_path):
    bad = tmp_path / "firefox-x.zip"
    bad.write_bytes(b"")
    if fxmod.detect_platform() is None:
        pytest.skip("unsupported OS")
    with pytest.raises(RuntimeError, match="cannot infer version"):
        fxmod.download_firefox(archive_path=bad)


# ---------------------------------------------------------------------------
# Policies / profile
# ---------------------------------------------------------------------------

def test_policies_dict_shape(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    pol = fxmod._policies_dict(
        ca_path=ca, proxy_host="127.0.0.1", proxy_port=8080,
        homepage_url="http://127.0.0.1:8787/",
    )["policies"]
    assert pol["Certificates"]["Install"] == [str(ca)]
    assert pol["Proxy"]["HTTPProxy"] == "127.0.0.1:8080"
    assert pol["Proxy"]["SSLProxy"] == "127.0.0.1:8080"
    assert pol["Proxy"]["Locked"] is True
    assert pol["DisableTelemetry"] is True
    assert pol["DisableAppUpdate"] is True
    assert pol["Homepage"]["URL"] == "http://127.0.0.1:8787/"


def test_install_policies_writes_json(tmp_path):
    fake_exe = tmp_path / "ff" / "firefox.exe"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_bytes(b"")
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    out = fxmod.install_policies(
        exe=fake_exe, ca_path=ca,
        proxy_host="127.0.0.1", proxy_port=8080,
        homepage_url="http://127.0.0.1:8787/",
    )
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["policies"]["Proxy"]["HTTPProxy"] == "127.0.0.1:8080"


def test_install_policies_missing_ca_raises(tmp_path):
    fake_exe = tmp_path / "ff" / "firefox.exe"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_bytes(b"")
    with pytest.raises(FileNotFoundError):
        fxmod.install_policies(
            exe=fake_exe, ca_path=tmp_path / "missing.pem",
            proxy_host="127.0.0.1", proxy_port=8080,
            homepage_url="http://127.0.0.1:8787/",
        )


def test_ensure_profile_creates_user_js(tmp_path):
    p = fxmod.ensure_profile(tmp_path / "prof")
    assert p.exists()
    user_js = p / "user.js"
    assert user_js.exists()
    txt = user_js.read_text(encoding="utf-8")
    assert "browser.shell.checkDefaultBrowser" in txt
    # Critical: without this Firefox bypasses the proxy for localhost,
    # so requests to the bundled vuln-* labs never reach Weblore's MITM.
    assert "network.proxy.allow_hijacking_localhost" in txt
    assert "network.proxy.no_proxies_on" in txt


# ---------------------------------------------------------------------------
# launch (no real subprocess)
# ---------------------------------------------------------------------------

def test_launch_invokes_popen_with_profile(tmp_path, monkeypatch):
    fake_exe = tmp_path / "ff" / "firefox"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_bytes(b"")
    profile = tmp_path / "prof"
    profile.mkdir()

    captured = {}

    class FakeProc:
        pid = 4242

    def fake_popen(args, *a, **kw):
        captured["args"] = list(args)
        return FakeProc()

    monkeypatch.setattr(fxmod.subprocess, "Popen", fake_popen)
    res = fxmod.launch(exe=fake_exe, profile_dir=profile, url="http://x/",
                       wait=False)
    assert res.pid == 4242
    assert "--no-remote" in captured["args"]
    assert "--profile" in captured["args"]
    assert str(profile) in captured["args"]
    assert "http://x/" in captured["args"]


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_cli_browser_subparser_registered():
    from weblore.cli import build_parser
    parser = build_parser()
    # Capture --help text to assert subcommand presence.
    actions = {a.dest for a in parser._actions}
    assert "cmd" in actions
    subactions = next(a for a in parser._actions if a.dest == "cmd")
    names = set(subactions.choices.keys())
    assert "browser" in names
    assert "prefetch-firefox" in names


def test_cli_browser_parses(monkeypatch):
    from weblore.cli import build_parser
    parser = build_parser()
    ns = parser.parse_args([
        "browser",
        "--proxy-port", "8081",
        "--url", "http://127.0.0.1:8787/",
        "--use-system",
    ])
    assert ns.cmd == "browser"
    assert ns.proxy_port == 8081
    assert ns.url == "http://127.0.0.1:8787/"
    assert ns.use_system is True
    assert ns.wait is False
