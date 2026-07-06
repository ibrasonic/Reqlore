"""Spec-file loader for the headless ``reqlore intruder`` CLI.

The spec is JSON (or YAML, if PyYAML is installed). It describes a single
attack: template, payload sources, options. ``build_attack`` materialises the
spec into the keyword args that ``Project.create_intruder`` expects.

Keeping this module tiny and import-light means the CLI starts fast and the
schema is easy to audit in security reviews.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .intruder import (
    COMMON_PASSWORDS,
    DEFAULT_MARKER,
    WORDLISTS,
    find_positions,
    load_wordlist_file,
    payloads_brute,
    payloads_from_text,
    payloads_numbers,
)

_VALID_ATTACK_TYPES = ("sniper", "battering", "pitchfork", "clusterbomb")
_VALID_SOURCES = ("text", "numbers", "brute", "common_pw", "wordlist", "wordlist_file")


class SpecError(ValueError):
    """Raised when a spec file is missing required fields or has bad values."""


@dataclass
class BuiltAttack:
    name: str
    attack_type: str
    template: bytes
    positions: list[tuple[int, int]]
    payloads: list[list[str]]
    options: dict[str, Any]
    url: str
    engine: str


def load_spec(path: str | Path) -> dict:
    """Return the parsed spec dict from ``path`` (.json/.yaml/.yml)."""
    p = Path(path)
    if not p.is_file():
        raise SpecError(f"Spec file not found: {path}")
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SpecError(
                "PyYAML is required to load YAML specs. Install with "
                "'pip install pyyaml' or use a .json spec.") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"Invalid YAML: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"Invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError("Spec root must be a mapping (object).")
    return data


def _payload_set_from_entry(entry: dict, *, base_dir: Path) -> list[str]:
    src = entry.get("source", "text")
    if src not in _VALID_SOURCES:
        raise SpecError(
            f"Unknown payload source {src!r}. "
            f"Valid: {', '.join(_VALID_SOURCES)}.")
    if src == "text":
        values = entry.get("values")
        if values is None:
            text = entry.get("text", "")
            return payloads_from_text(text)
        if not isinstance(values, list):
            raise SpecError("'values' must be a list of strings.")
        return [str(v) for v in values]
    if src == "numbers":
        return payloads_numbers(
            int(entry.get("start", 0)),
            int(entry.get("end", 0)),
            int(entry.get("step", 1)),
        )
    if src == "brute":
        gen = payloads_brute(
            str(entry.get("alphabet", "")),
            int(entry.get("min", 1)),
            int(entry.get("max", 1)),
        )
        cap = int(entry.get("max_count", 50_000))
        out: list[str] = []
        for value in gen:
            out.append(value)
            if len(out) >= cap:
                break
        return out
    if src == "common_pw":
        return list(COMMON_PASSWORDS)
    if src == "wordlist":
        name = entry.get("name", "")
        wl = WORDLISTS.get(name)
        if wl is None:
            raise SpecError(
                f"Unknown built-in wordlist {name!r}. "
                f"Available: {', '.join(sorted(WORDLISTS))}.")
        return list(wl)
    # wordlist_file
    raw = entry.get("path", "")
    if not raw:
        raise SpecError("'path' is required for wordlist_file source.")
    p = Path(raw)
    if not p.is_absolute():
        p = (base_dir / p).resolve()
    return load_wordlist_file(str(p))


def build_attack(spec: dict, *, base_dir: Path | None = None) -> BuiltAttack:
    """Validate ``spec`` and return a ``BuiltAttack`` ready for ``create_intruder``."""
    base_dir = base_dir or Path.cwd()

    name = str(spec.get("name") or "attack").strip() or "attack"
    attack_type = str(spec.get("attack_type", "sniper"))
    if attack_type not in _VALID_ATTACK_TYPES:
        raise SpecError(
            f"Unknown attack_type {attack_type!r}. "
            f"Valid: {', '.join(_VALID_ATTACK_TYPES)}.")
    url = str(spec.get("url") or "")
    if not url:
        raise SpecError("'url' is required.")
    engine = str(spec.get("engine", "httpx"))
    marker = str(spec.get("marker", DEFAULT_MARKER))

    template_text = spec.get("template")
    if not isinstance(template_text, str) or not template_text.strip():
        raise SpecError("'template' (raw HTTP request) is required.")
    template = template_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
    positions = find_positions(template, marker)
    if not positions:
        raise SpecError(
            f"No markers in template. Wrap insertion points with {marker} "
            f"(e.g. {marker}payload{marker}).")

    raw_payloads = spec.get("payloads")
    if not isinstance(raw_payloads, list) or not raw_payloads:
        raise SpecError("'payloads' must be a non-empty list of payload-set entries.")
    payload_sets: list[list[str]] = []
    for i, entry in enumerate(raw_payloads):
        if not isinstance(entry, dict):
            raise SpecError(f"payloads[{i}] must be a mapping.")
        payload_sets.append(_payload_set_from_entry(entry, base_dir=base_dir))
    if not payload_sets[0]:
        raise SpecError("First payload set is empty.")
    if attack_type in ("sniper", "battering"):
        payload_sets = payload_sets[:1]

    raw_opts = spec.get("options", {}) or {}
    if not isinstance(raw_opts, dict):
        raise SpecError("'options' must be a mapping.")
    options = {
        "concurrency": int(raw_opts.get("concurrency", 4)),
        "delay_ms": int(raw_opts.get("delay_ms", 0)),
        "max_requests": int(raw_opts.get("max_requests", 1000)),
        "processors": [str(p) for p in raw_opts.get("processors", [])],
        "grep": [str(g) for g in raw_opts.get("grep", [])],
        "retries": max(0, int(raw_opts.get("retries", 0))),
        "stop_on_match": bool(raw_opts.get("stop_on_match", False)),
        "stop_on_status": [int(s) for s in raw_opts.get("stop_on_status", [])],
        "timeout": float(raw_opts.get("timeout", 15.0)),
        "follow_redirects": bool(raw_opts.get("follow_redirects", False)),
        "verify_tls": bool(raw_opts.get("verify_tls", True)),
    }

    return BuiltAttack(
        name=name, attack_type=attack_type, template=template,
        positions=positions, payloads=payload_sets, options=options,
        url=url, engine=engine,
    )
