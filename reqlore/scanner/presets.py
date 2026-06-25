"""Phase 9 — Scan presets (Lightweight / Fast / Balanced / Deep).

Burp Suite Professional ships four standard scan configurations.
``reqlore`` mirrors the same four names so a tester comparing tools
isn't surprised by what each preset implies. The presets bundle the
half-dozen knobs an operator would otherwise have to tune
individually (intensity tiers, probe budgets, rate-delay, redirect
follow, wall-clock cap, JS-static/dynamic opt-ins) into a single
named choice.

Public surface::

    from reqlore.scanner.presets import (
        SCAN_PRESETS, PRESET_NAMES, DEFAULT_PRESET, apply_preset,
    )

    opts = apply_preset("balanced")              # ActiveOptions
    opts = apply_preset("deep", base=existing)   # override a base
    opts = apply_preset("custom", base=existing) # passthrough

The preset table is data, not policy — the scanner itself doesn't
know about presets; it only reads ``ActiveOptions``. A caller picks
a preset, the dataclass is materialised, and the scanner runs.

Wall-clock enforcement is the responsibility of
``ActiveScanner.run_on_project`` (Phase 9 also adds
``ActiveOptions.wall_clock_seconds``); the preset table just
populates the field.
"""
from __future__ import annotations

from dataclasses import asdict, fields, replace
from types import MappingProxyType

from .active import ActiveOptions


# The canonical four. Names match Burp's UI labels so muscle memory
# carries over. ``custom`` is a sentinel that means "the operator
# tuned things manually — don't overwrite their choices".
PRESET_NAMES: tuple[str, ...] = (
    "lightweight", "fast", "balanced", "deep", "custom",
)

DEFAULT_PRESET: str = "balanced"


# Per-preset deltas applied on top of ``ActiveOptions()`` defaults.
# Anything not listed here keeps the dataclass default. Values were
# chosen to land within a single order of magnitude of Burp's
# defaults so a comparison run produces a similar workload.
_PRESET_TABLE: dict[str, dict] = {
    "lightweight": dict(
        intensity_levels=frozenset({"light"}),
        max_probes_per_check=10,
        max_probes_per_target=2,
        max_insertion_points_per_row=50,
        rate_delay_ms=0,
        follow_redirects=False,
        wall_clock_seconds=15 * 60,
        allow_smuggling_probes=False,
        allow_credential_probes=False,
        allow_race_probes=False,
        allow_dom_xss_probes=False,
        js_analysis_mode="off",
    ),
    "fast": dict(
        intensity_levels=frozenset({"light", "medium"}),
        max_probes_per_check=25,
        max_probes_per_target=3,
        max_insertion_points_per_row=100,
        rate_delay_ms=0,
        follow_redirects=False,
        wall_clock_seconds=25 * 60,
        allow_smuggling_probes=False,
        allow_credential_probes=False,
        allow_race_probes=False,
        allow_dom_xss_probes=False,
        js_analysis_mode="off",
    ),
    "balanced": dict(
        intensity_levels=frozenset({"light", "medium"}),
        max_probes_per_check=50,
        max_probes_per_target=4,
        max_insertion_points_per_row=200,
        rate_delay_ms=50,
        follow_redirects=True,
        wall_clock_seconds=60 * 60,
        allow_smuggling_probes=False,
        allow_credential_probes=False,
        allow_race_probes=False,
        allow_dom_xss_probes=False,
        # Phase 13 — run the static AST analyser on every JS / HTML
        # response, and spin up the headless browser only when a
        # static finding suggests it's worth confirming. Cheapest
        # path to runtime evidence.
        js_analysis_mode="static_plus_confirm",
    ),
    "deep": dict(
        intensity_levels=frozenset({"light", "medium", "intrusive"}),
        max_probes_per_check=200,
        max_probes_per_target=8,
        max_insertion_points_per_row=400,
        rate_delay_ms=100,
        follow_redirects=True,
        wall_clock_seconds=None,
        allow_smuggling_probes=True,
        # Credential-spray and race probes stay opt-in even under
        # "deep" because they have account-locking / state-mutating
        # side-effects. Operators must still tick the confirm box.
        allow_credential_probes=False,
        allow_race_probes=False,
        allow_dom_xss_probes=True,
        # Phase 13 — full dynamic DOM analysis with event driving.
        # Most expensive mode; gated to ``deep`` only.
        js_analysis_mode="static_plus_dynamic",
    ),
}


# Human-readable description for each preset. Surfaced by the web UI
# and the CLI ``--help`` text so an operator picks with intent.
_PRESET_DESCRIPTIONS: dict[str, str] = {
    "lightweight": (
        "Light-intensity checks only. Smallest probe budget, no "
        "redirect follow, 15-minute wall-clock cap. Suitable for "
        "smoke-testing production behind a change window."
    ),
    "fast": (
        "Light + medium intensity. 25 probes per check, no rate "
        "delay, 25-minute cap. Good first pass on a fresh target."
    ),
    "balanced": (
        "Light + medium intensity, 50 probes per check, 50 ms "
        "rate delay, redirect follow on, 60-minute cap, JS static "
        "analysis with on-demand dynamic confirmation. The "
        "everyday default."
    ),
    "deep": (
        "Light + medium + intrusive intensity, 200 probes per "
        "check, 100 ms rate delay, redirect follow on, no time "
        "cap, JS dynamic DOM analysis on (event driving), HTTP "
        "smuggling probes on. Credential-spray and race probes "
        "still require explicit opt-in even at this level."
    ),
    "custom": (
        "Honour the per-field options the caller supplied; the "
        "preset table is not applied."
    ),
}


# Frozen read-only views — callers can introspect but not mutate.
SCAN_PRESETS = MappingProxyType({
    name: MappingProxyType(dict(table))
    for name, table in _PRESET_TABLE.items()
})
PRESET_DESCRIPTIONS = MappingProxyType(dict(_PRESET_DESCRIPTIONS))


# Field allow-list — any new ActiveOptions field a preset wants to
# touch must be added here. Forces the preset table to evolve in
# lockstep with the dataclass instead of silently no-op'ing when
# someone misspells a field name.
_ALLOWED_PRESET_FIELDS: frozenset[str] = frozenset({
    "intensity_levels",
    "max_probes_per_check",
    "max_probes_per_target",
    "max_insertion_points_per_row",
    "rate_delay_ms",
    "follow_redirects",
    "wall_clock_seconds",
    "allow_smuggling_probes",
    "allow_credential_probes",
    "allow_race_probes",
    "allow_dom_xss_probes",
    "js_analysis_mode",
})


def _validate_preset_table() -> None:
    """Raise at import time if the table references unknown fields,
    so a typo can't ship a broken preset."""
    valid_fields = {f.name for f in fields(ActiveOptions)}
    for name, table in _PRESET_TABLE.items():
        unknown = set(table) - valid_fields
        if unknown:
            raise RuntimeError(
                f"SCAN_PRESETS[{name!r}] references unknown "
                f"ActiveOptions field(s): {sorted(unknown)!r}"
            )
        disallowed = set(table) - _ALLOWED_PRESET_FIELDS
        if disallowed:
            raise RuntimeError(
                f"SCAN_PRESETS[{name!r}] touches non-preset-allowed "
                f"field(s): {sorted(disallowed)!r}; add them to "
                f"_ALLOWED_PRESET_FIELDS if intentional."
            )


_validate_preset_table()


def apply_preset(name: str, *, base: ActiveOptions | None = None
                  ) -> ActiveOptions:
    """Return an :class:`ActiveOptions` populated from preset ``name``.

    Parameters
    ----------
    name
        One of :data:`PRESET_NAMES`. Case-insensitive; whitespace is
        stripped. Unknown names raise :class:`ValueError`.
    base
        Optional baseline. When supplied, fields the preset doesn't
        touch (``enabled_checks``, ``alt_identity``, OAST handle,
        macro hook, …) are preserved from ``base``. When ``None``,
        the dataclass defaults are used.

    The ``"custom"`` preset returns ``base`` unchanged (or a fresh
    default ``ActiveOptions`` when no base was given).
    """
    key = (name or "").strip().lower()
    if key not in SCAN_PRESETS and key != "custom":
        raise ValueError(
            f"unknown scan preset {name!r}; valid: {PRESET_NAMES}"
        )
    if base is None:
        base = ActiveOptions()
    if key == "custom":
        return base
    return replace(base, **dict(SCAN_PRESETS[key]))


def preset_summary(name: str) -> dict[str, object]:
    """Return a JSON-serialisable view of a preset for UI rendering.

    The intensity set is collapsed to a sorted list so the result is
    deterministic across runs.
    """
    key = (name or "").strip().lower()
    if key == "custom":
        return {
            "name": "custom",
            "description": PRESET_DESCRIPTIONS["custom"],
            "fields": {},
        }
    if key not in SCAN_PRESETS:
        raise ValueError(
            f"unknown scan preset {name!r}; valid: {PRESET_NAMES}"
        )
    out: dict[str, object] = {}
    for fld, val in SCAN_PRESETS[key].items():
        if isinstance(val, frozenset):
            out[fld] = sorted(val)
        else:
            out[fld] = val
    return {
        "name": key,
        "description": PRESET_DESCRIPTIONS[key],
        "fields": out,
    }


def all_summaries() -> list[dict[str, object]]:
    """Return summaries for every named preset, in canonical order."""
    return [preset_summary(n) for n in PRESET_NAMES]


__all__ = [
    "PRESET_NAMES",
    "DEFAULT_PRESET",
    "SCAN_PRESETS",
    "PRESET_DESCRIPTIONS",
    "apply_preset",
    "preset_summary",
    "all_summaries",
]
