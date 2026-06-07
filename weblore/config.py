"""Runtime configuration.

Resolution order (highest wins):
    CLI flag > environment variable > project setting > user config > defaults
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _user_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    d = base / "weblore"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "weblore"
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
    if v := os.environ.get("WEBLORE_UI_HOST"):
        s.ui_host = v
    if v := os.environ.get("WEBLORE_UI_PORT"):
        s.ui_port = int(v)
    if v := os.environ.get("WEBLORE_PROXY_HOST"):
        s.proxy_host = v
    if v := os.environ.get("WEBLORE_PROXY_PORT"):
        s.proxy_port = int(v)
    return s
