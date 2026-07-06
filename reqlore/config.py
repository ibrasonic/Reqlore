"""Runtime configuration.

Resolution order (highest wins):
    CLI flag > environment variable > project setting > user config > defaults
"""
from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path


def _user_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    d = base / "reqlore"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "reqlore"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Settings:
    # UI
    ui_host: str = "127.0.0.1"
    ui_port: int = 8787
    ui_unsafe_bind: bool = False

    # Proxy
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    proxy_intercept_default: bool = False

    # Paths
    user_dir: Path = field(default_factory=_user_dir)
    data_dir: Path = field(default_factory=_data_dir)

    # Theme / a11y defaults applied to a new project
    default_theme: str = "system"    # "light" | "dark" | "high-contrast" | "system"
    default_verbosity: str = "standard"  # "concise" | "standard" | "verbose"

    # Security
    require_password_on_unsafe_bind: bool = True
    # If set, the UI requires a login. Either a plaintext password
    # (hashed in-memory at startup) or a pre-computed argon2 hash.
    ui_password: str = ""
    ui_password_hash: str = ""
    # Cookie session lifetime in seconds (default 8 hours).
    session_max_age_s: int = 8 * 3600

    @property
    def auth_enabled(self) -> bool:
        return bool(self.ui_password or self.ui_password_hash)

    @property
    def ca_dir(self) -> Path:
        d = self.user_dir / "ca"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def plugins_dir(self) -> Path:
        d = self.user_dir / "plugins"
        d.mkdir(parents=True, exist_ok=True)
        return d


def settings_from_env(base: Settings | None = None) -> Settings:
    s = base or Settings()
    if v := os.environ.get("REQLORE_UI_HOST"):
        s.ui_host = v
    if v := os.environ.get("REQLORE_UI_PORT"):
        s.ui_port = int(v)
    if v := os.environ.get("REQLORE_PROXY_HOST"):
        s.proxy_host = v
    if v := os.environ.get("REQLORE_PROXY_PORT"):
        s.proxy_port = int(v)
    if v := os.environ.get("REQLORE_PASSWORD"):
        s.ui_password = v
    if v := os.environ.get("REQLORE_PASSWORD_HASH"):
        s.ui_password_hash = v
    if v := os.environ.get("REQLORE_SESSION_MAX_AGE"):
        with contextlib.suppress(ValueError):
            s.session_max_age_s = max(60, int(v))
    return s
