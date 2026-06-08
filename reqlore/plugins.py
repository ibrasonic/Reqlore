"""Reqlore plugin loader.

A plugin is a single ``.py`` file dropped into ``<user>/.reqlore/plugins/`` (or
a project-local ``plugins/`` folder). It must expose a module-level
``PLUGIN_INFO`` dict and optionally one of the entry points described below.

Entry points
------------
``scanner_rules() -> list[Rule]``
    Return extra passive-scanner rules. Each rule must follow the
    ``(ctx: RuleContext) -> Iterable[Finding]`` signature from
    :mod:`reqlore.scanner.passive`.

``register(app)`` (optional)
    Lets a plugin register a Flask blueprint or after-request hook. Receives
    the live :class:`flask.Flask` instance.

Discovery
---------
The loader scans the configured plugin directories on demand. Hot reload is
opt-in: if ``watchdog`` is installed and the user enables it in Settings, the
loader will rebuild its registry whenever a file in the plugin directory
changes. Without watchdog, click "Reload plugins" in Settings.

Safety
------
Plugins run in the same process — they are trusted code, not a sandbox. The
loader catches and reports import errors so a broken plugin disables itself
instead of taking the whole app down.
"""
from __future__ import annotations

import importlib.util
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class PluginRecord:
    name: str
    path: Path
    info: dict[str, Any] = field(default_factory=dict)
    module: Any = None
    rules: list[Callable] = field(default_factory=list)
    register: Callable | None = None
    copy_as_handlers: list[Any] = field(default_factory=list)
    error: str = ""
    loaded_at: int = 0
    enabled: bool = True

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        if not self.enabled:
            return "disabled"
        return "loaded"

    @property
    def version(self) -> str:
        return str(self.info.get("version", "?"))

    @property
    def description(self) -> str:
        return str(self.info.get("description", ""))


class PluginRegistry:
    """In-process registry of discovered plugins. Thread-safe."""

    def __init__(self, dirs: list[Path]):
        self.dirs = [Path(d) for d in dirs]
        self._lock = threading.RLock()
        self._plugins: dict[str, PluginRecord] = {}
        self._observers: list[Any] = []

    # ---- public API ----
    def discover(self) -> list[PluginRecord]:
        """Force a full re-scan. Returns the new plugin list."""
        with self._lock:
            old = {n: p.enabled for n, p in self._plugins.items()}
            self._plugins.clear()
            for d in self.dirs:
                if not d.exists():
                    continue
                for path in sorted(d.glob("*.py")):
                    if path.name.startswith("_"):
                        continue
                    rec = self._load_one(path)
                    if rec.name in old:
                        rec.enabled = old[rec.name]
                    self._plugins[rec.name] = rec
            return list(self._plugins.values())

    def list(self) -> list[PluginRecord]:
        with self._lock:
            return list(self._plugins.values())

    def get(self, name: str) -> PluginRecord | None:
        with self._lock:
            return self._plugins.get(name)

    def toggle(self, name: str) -> bool:
        with self._lock:
            rec = self._plugins.get(name)
            if not rec:
                return False
            rec.enabled = not rec.enabled
            return rec.enabled

    def active_rules(self) -> list[Callable]:
        with self._lock:
            out: list[Callable] = []
            for rec in self._plugins.values():
                if rec.enabled and not rec.error:
                    out.extend(rec.rules)
            return out

    def active_copy_as(self) -> list[Any]:
        """Flatten all enabled plugins' copy_as() handlers."""
        with self._lock:
            out: list[Any] = []
            for rec in self._plugins.values():
                if rec.enabled and not rec.error:
                    out.extend(rec.copy_as_handlers)
            return out

    def call_register(self, app) -> None:
        with self._lock:
            for rec in self._plugins.values():
                if rec.enabled and rec.register:
                    try:
                        rec.register(app)
                    except Exception as exc:  # pragma: no cover
                        rec.error = f"register() failed: {exc}"

    # ---- watchdog hot-reload (opt-in) ----
    def start_watch(self) -> bool:
        """Start a watchdog Observer if the library is installed.
        Returns True if hot-reload is now active."""
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return False

        registry = self

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):  # type: ignore[override]
                if event.is_directory:
                    return
                if not str(event.src_path).endswith(".py"):
                    return
                registry.discover()

        with self._lock:
            self.stop_watch()
            obs = Observer()
            for d in self.dirs:
                if d.exists():
                    obs.schedule(_Handler(), str(d), recursive=False)
            obs.daemon = True
            obs.start()
            self._observers.append(obs)
        return True

    def stop_watch(self) -> None:
        with self._lock:
            for obs in self._observers:
                try:
                    obs.stop()
                    obs.join(timeout=1)
                except Exception:
                    pass
            self._observers.clear()

    # ---- internals ----
    def _load_one(self, path: Path) -> PluginRecord:
        modname = f"reqlore_plugin_{path.stem}"
        rec = PluginRecord(name=path.stem, path=path, loaded_at=int(time.time()))
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            if not spec or not spec.loader:
                raise ImportError("spec_from_file_location returned None")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[modname] = mod
            spec.loader.exec_module(mod)
            info = getattr(mod, "PLUGIN_INFO", None)
            if not isinstance(info, dict):
                raise ValueError("plugin is missing a PLUGIN_INFO dict")
            rec.module = mod
            rec.info = info
            rec.name = str(info.get("name", path.stem))
            if hasattr(mod, "scanner_rules"):
                rules = mod.scanner_rules()
                if not isinstance(rules, list):
                    raise TypeError("scanner_rules() must return a list")
                rec.rules = list(rules)
            if hasattr(mod, "copy_as"):
                handlers = mod.copy_as()
                if not isinstance(handlers, list):
                    raise TypeError("copy_as() must return a list")
                rec.copy_as_handlers = list(handlers)
            if hasattr(mod, "register"):
                rec.register = mod.register
        except Exception:
            rec.error = traceback.format_exc(limit=4)
        return rec


# ---- module-level singleton helpers ----
_REGISTRY: PluginRegistry | None = None
_REG_LOCK = threading.Lock()


def get_registry(dirs: list[Path] | None = None) -> PluginRegistry:
    """Return the process-wide registry, creating it on first call."""
    global _REGISTRY
    with _REG_LOCK:
        if _REGISTRY is None:
            if dirs is None:
                dirs = default_plugin_dirs()
            _REGISTRY = PluginRegistry(dirs)
            _REGISTRY.discover()
        return _REGISTRY


def reset_registry() -> None:
    """Test-only: forget the current singleton."""
    global _REGISTRY
    with _REG_LOCK:
        if _REGISTRY is not None:
            _REGISTRY.stop_watch()
        _REGISTRY = None


def default_plugin_dirs() -> list[Path]:
    """User-scoped plugin directory under the home folder."""
    return [Path.home() / ".rlr" / "plugins"]
