"""Phase 4 of [RELIABILITY_PLAN](../../../../docs/RELIABILITY_PLAN.md):
browser launch portability for the WSL -> Windows host case.

The original bug: ``reqlore browser`` invoked from inside WSL silently
fails because the Linux Firefox binary cannot reach the Windows display
server, and the operator (whose only browser is on the Windows host)
has to copy-paste the URL by hand.

This phase locks in:
  * pure-function WSL detection (``/proc/version`` + ``$WSL_DISTRO_NAME``);
  * a two-tier opener that hands the URL to the Windows host
    (``cmd.exe /c start "" <url>`` then ``wslview <url>``);
  * ``cmd_browser`` short-circuits inside WSL so it never tries to spawn
    the unusable Linux Firefox, and always exits 0 with a copy-pasteable
    URL even when both openers fail (the UI server is up);
  * non-WSL regression guard: the WSL branch is bypassed on a real
    Linux / Windows / macOS host.

All tests monkeypatch the environment -- no real ``cmd.exe`` or
``wslview`` is invoked.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

from reqlore import browser as fxmod
from reqlore import cli as reqlore_cli

# ---------------------------------------------------------------------------
# is_wsl() -- pure function matrix
# ---------------------------------------------------------------------------

class _DummyPath:
    """Stand-in for pathlib.Path used only by is_wsl()."""

    def __init__(self, text: str | None) -> None:
        self._text = text

    def read_text(self, *_a, **_k) -> str:
        if self._text is None:
            raise FileNotFoundError("/proc/version")
        return self._text


def _patch_proc_version(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    """Make ``Path("/proc/version").read_text()`` return *text* (or raise)."""
    real_path = fxmod.Path

    def fake_path(arg, *a, **k):
        if arg == "/proc/version":
            return _DummyPath(text)
        return real_path(arg, *a, **k)

    monkeypatch.setattr(fxmod, "Path", fake_path)


@pytest.mark.parametrize(
    "system, env_var, proc_text, expected",
    [
        # Real WSL2: kernel string has "microsoft" + env var is set.
        ("Linux", "Ubuntu-22.04", "Linux 5.15.90.1-microsoft-standard-WSL2", True),
        # WSL1: env var was unset on old WSL1 builds; kernel string still mentions Microsoft.
        ("Linux", "", "Linux 4.4.0-19041-Microsoft #1237-Microsoft", True),
        # Env var set but /proc/version unreadable -- env var is enough.
        ("Linux", "Debian", None, True),
        # Vanilla Linux: no env var, no microsoft in /proc/version.
        ("Linux", "", "Linux 6.5.0-15-generic #15-Ubuntu SMP", False),
        # Vanilla Linux with /proc/version unreadable (some hardened kernels).
        ("Linux", "", None, False),
        # Windows host: short-circuits before reading anything.
        ("Windows", "", "ignored", False),
        # macOS: same short-circuit.
        ("Darwin", "", "ignored", False),
    ],
)
def test_is_wsl_matrix(monkeypatch: pytest.MonkeyPatch,
                       system: str, env_var: str,
                       proc_text: str | None, expected: bool) -> None:
    monkeypatch.setattr(fxmod.platform, "system", lambda: system)
    if env_var:
        monkeypatch.setenv("WSL_DISTRO_NAME", env_var)
    else:
        monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    _patch_proc_version(monkeypatch, proc_text)

    assert fxmod.is_wsl() is expected


# ---------------------------------------------------------------------------
# open_on_windows_host() -- opener chain
# ---------------------------------------------------------------------------

class _FakeCompleted:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _record_run(calls: list[list[str]], *, exit_codes: dict[str, int]):
    """Build a subprocess.run replacement that records argv and returns
    the configured exit code for whichever opener was invoked."""

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        # Identify which opener this is by the first argument basename.
        basename = Path(argv[0]).name.lower()
        if "cmd.exe" in basename:
            return _FakeCompleted(exit_codes.get("cmd.exe", 0))
        if "wslview" in basename:
            return _FakeCompleted(exit_codes.get("wslview", 0))
        return _FakeCompleted(127)

    return fake_run


def test_open_on_windows_host_prefers_cmd_exe(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name == "cmd.exe":
            return "/mnt/c/Windows/System32/cmd.exe"
        if name == "wslview":
            return "/usr/bin/wslview"
        return None

    monkeypatch.setattr(fxmod.shutil, "which", fake_which)
    monkeypatch.setattr(fxmod.subprocess, "run",
                        _record_run(calls, exit_codes={"cmd.exe": 0}))

    opener = fxmod.open_on_windows_host("http://127.0.0.1:8787/")

    assert opener == "cmd.exe"
    assert len(calls) == 1, "wslview must not be tried once cmd.exe succeeds"
    argv = calls[0]
    assert argv[0].endswith("cmd.exe")
    assert argv[1:4] == ["/c", "start", ""], \
        "title arg must be an empty string -- otherwise Windows treats the URL as the title"
    assert argv[4] == "http://127.0.0.1:8787/"


def test_open_on_windows_host_falls_back_to_wslview(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name == "cmd.exe":
            return "/mnt/c/Windows/System32/cmd.exe"
        if name == "wslview":
            return "/usr/bin/wslview"
        return None

    monkeypatch.setattr(fxmod.shutil, "which", fake_which)
    monkeypatch.setattr(fxmod.subprocess, "run",
                        _record_run(calls, exit_codes={"cmd.exe": 1, "wslview": 0}))

    opener = fxmod.open_on_windows_host("http://127.0.0.1:8787/")

    assert opener == "wslview"
    assert [Path(c[0]).name for c in calls] == ["cmd.exe", "wslview"]


def test_open_on_windows_host_returns_none_when_no_opener_available(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fxmod.shutil, "which", lambda _name: None)

    calls: list[list[str]] = []

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        return _FakeCompleted(0)

    monkeypatch.setattr(fxmod.subprocess, "run", fake_run)

    opener = fxmod.open_on_windows_host("http://127.0.0.1:8787/")

    # /mnt/c/Windows/System32/cmd.exe doesn't exist on the test host
    # (Windows or Linux without WSL), so the cmd.exe candidate is
    # skipped, wslview isn't on PATH, and no opener runs.
    assert opener is None
    assert calls == []


def test_open_on_windows_host_swallows_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """If cmd.exe raises (e.g. WSL interop disabled), we still try wslview."""
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name == "cmd.exe":
            return "/mnt/c/Windows/System32/cmd.exe"
        if name == "wslview":
            return "/usr/bin/wslview"
        return None

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        if "cmd.exe" in Path(argv[0]).name.lower():
            raise OSError("WSL interop is disabled")
        return _FakeCompleted(0)

    monkeypatch.setattr(fxmod.shutil, "which", fake_which)
    monkeypatch.setattr(fxmod.subprocess, "run", fake_run)

    opener = fxmod.open_on_windows_host("http://127.0.0.1:8787/")

    assert opener == "wslview"
    assert len(calls) == 2


def test_open_on_windows_host_swallows_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung cmd.exe must not block the fallback chain."""
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name == "cmd.exe":
            return "/mnt/c/Windows/System32/cmd.exe"
        if name == "wslview":
            return "/usr/bin/wslview"
        return None

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        if "cmd.exe" in Path(argv[0]).name.lower():
            raise subprocess.TimeoutExpired(cmd=argv, timeout=10.0)
        return _FakeCompleted(0)

    monkeypatch.setattr(fxmod.shutil, "which", fake_which)
    monkeypatch.setattr(fxmod.subprocess, "run", fake_run)

    opener = fxmod.open_on_windows_host("http://127.0.0.1:8787/")

    assert opener == "wslview"


# ---------------------------------------------------------------------------
# cmd_browser -- WSL short-circuit
# ---------------------------------------------------------------------------

def _browser_args(**overrides):
    """Build the argparse.Namespace shape that cmd_browser expects."""
    defaults = {
        "proxy_port": None,
        "url": None,
        "firefox_zip": None,
        "firefox_version": None,
        "use_system": False,
        "wait": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_cmd_browser_wsl_handoff_uses_host_opener_and_exits_zero(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture) -> None:
    """Inside WSL we must NEVER spawn the Linux Firefox -- short-circuit
    to the host opener and exit 0 with a copy-pasteable URL."""

    # Redirect the user dir (where the CA lives) into the tmp dir so
    # the test doesn't write into the operator's real %APPDATA%.
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # Pin a deterministic UI URL.
    monkeypatch.setenv("REQLORE_UI_HOST", "127.0.0.1")
    monkeypatch.setenv("REQLORE_UI_PORT", "8787")

    monkeypatch.setattr(fxmod, "is_wsl", lambda: True)
    opened: list[str] = []

    def fake_open(url, **_kw):
        opened.append(url)
        return "cmd.exe"

    monkeypatch.setattr(fxmod, "open_on_windows_host", fake_open)

    # Sentinel: if cmd_browser ever falls through to run_browser inside
    # WSL we want to know about it loudly.
    def boom(**_kw):
        raise AssertionError("run_browser must not be called inside WSL")

    monkeypatch.setattr(fxmod, "run_browser", boom)

    rc = reqlore_cli.cmd_browser(_browser_args())

    assert rc == 0
    assert opened == ["http://127.0.0.1:8787/"]
    out = capsys.readouterr().out
    assert "Reqlore UI: http://127.0.0.1:8787/" in out
    assert "127.0.0.1:8080" in out  # proxy line
    assert "CA cert:" in out
    assert "cmd.exe" in out


def test_cmd_browser_wsl_prints_url_and_exits_zero_when_no_opener_works(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture) -> None:
    """No working opener is NOT a failure -- the UI server is up;
    the operator can paste the URL into a Windows browser by hand."""

    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("REQLORE_UI_HOST", "127.0.0.1")
    monkeypatch.setenv("REQLORE_UI_PORT", "8787")

    monkeypatch.setattr(fxmod, "is_wsl", lambda: True)
    monkeypatch.setattr(fxmod, "open_on_windows_host", lambda url, **_kw: None)

    def boom(**_kw):
        raise AssertionError("run_browser must not be called inside WSL")

    monkeypatch.setattr(fxmod, "run_browser", boom)

    rc = reqlore_cli.cmd_browser(_browser_args())

    assert rc == 0, "UI server is up; exit 0 even though no auto-opener worked"
    out = capsys.readouterr().out
    assert "http://127.0.0.1:8787/" in out
    assert "manually" in out.lower()


def test_cmd_browser_non_wsl_path_is_unchanged(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path) -> None:
    """Regression guard: on real Linux / Windows / macOS the WSL branch
    must be bypassed and run_browser must be called as before."""

    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(fxmod, "is_wsl", lambda: False)

    # open_on_windows_host must never be touched off-WSL.
    def boom_opener(url, **_kw):
        raise AssertionError("open_on_windows_host must not be called off WSL")

    monkeypatch.setattr(fxmod, "open_on_windows_host", boom_opener)

    called: dict[str, object] = {}

    class _FakeResult:
        pid = 1234
        exe = Path("/usr/bin/firefox")
        profile = tmp_path / "profile"
        policies = tmp_path / "policies.json"

    def fake_run_browser(**kwargs):
        called.update(kwargs)
        return _FakeResult()

    monkeypatch.setattr(fxmod, "run_browser", fake_run_browser)

    rc = reqlore_cli.cmd_browser(_browser_args(url="http://127.0.0.1:8787/"))

    assert rc == 0
    assert called["ui_url"] == "http://127.0.0.1:8787/"
    assert called["proxy_host"] == "127.0.0.1"
