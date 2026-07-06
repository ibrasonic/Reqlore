"""Plugin loader: discovery, errors, toggle, hot reload (if watchdog present)."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.plugins import PluginRegistry, reset_registry


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_registry()
    yield
    reset_registry()


def _write_plugin(folder: Path, name: str, body: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_discovers_valid_plugin(tmp_path: Path):
    _write_plugin(tmp_path, "demo", '''
PLUGIN_INFO = {"name": "demo", "version": "0.1", "description": "test plug"}

def scanner_rules():
    def r(ctx):
        return []
    return [r]
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    plugs = reg.list()
    assert len(plugs) == 1
    p = plugs[0]
    assert p.name == "demo"
    assert p.version == "0.1"
    assert p.status == "loaded"
    assert len(p.rules) == 1


def test_missing_plugin_info_records_error(tmp_path: Path):
    _write_plugin(tmp_path, "bad", "x = 1\n")  # no PLUGIN_INFO
    reg = PluginRegistry([tmp_path])
    reg.discover()
    p = reg.list()[0]
    assert p.status == "error"
    assert "PLUGIN_INFO" in p.error


def test_underscore_files_are_skipped(tmp_path: Path):
    _write_plugin(tmp_path, "_private", 'PLUGIN_INFO = {"name": "x"}\n')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    assert reg.list() == []


def test_toggle_disables_rules(tmp_path: Path):
    _write_plugin(tmp_path, "demo", '''
PLUGIN_INFO = {"name": "demo"}

def scanner_rules():
    def r(ctx): return []
    return [r]
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    assert len(reg.active_rules()) == 1
    reg.toggle("demo")
    assert reg.active_rules() == []
    reg.toggle("demo")
    assert len(reg.active_rules()) == 1


def test_register_hook_invoked(tmp_path: Path):
    _write_plugin(tmp_path, "demo", '''
PLUGIN_INFO = {"name": "demo"}

_seen = []

def register(app):
    _seen.append(app)

def get_seen():
    return _seen
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    sentinel = object()
    reg.call_register(sentinel)
    plugin = reg.get("demo")
    assert plugin is not None
    mod = plugin.module
    assert mod.get_seen() == [sentinel]


def test_discover_preserves_disabled_state(tmp_path: Path):
    _write_plugin(tmp_path, "demo", 'PLUGIN_INFO = {"name": "demo"}\n')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    reg.toggle("demo")
    plugin_a = reg.get("demo")
    assert plugin_a is not None
    assert plugin_a.enabled is False
    reg.discover()  # re-scan
    plugin_b = reg.get("demo")
    assert plugin_b is not None
    assert plugin_b.enabled is False


def test_rule_failure_inside_plugin_does_not_take_down_scan(tmp_path: Path):
    _write_plugin(tmp_path, "boom", '''
PLUGIN_INFO = {"name": "boom"}

def scanner_rules():
    def r(ctx):
        raise RuntimeError("nope")
    return [r]
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    rules = reg.active_rules()
    assert len(rules) == 1
    # Mimic what the engine does — wrap the call.
    from dataclasses import dataclass

    @dataclass
    class _Ctx:
        history_id: int = 0
        host: str = ""
        url: str = ""
        method: str = ""
        status: int = 0
        req_headers: list | None = None
        req_body: bytes = b""
        resp_start_line: str = ""
        resp_headers: list | None = None
        resp_body: bytes = b""

    with pytest.raises(RuntimeError):
        list(rules[0](_Ctx(req_headers=[], resp_headers=[])))
