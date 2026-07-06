"""Settings: theme, verbosity, keyboard map (display only for now)."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ...scanner.consolidation import (
    ConsolidationSettings,
)
from ...scanner.consolidation import (
    load_settings as load_consolidation_settings,
)
from ...scanner.consolidation import (
    save_settings as save_consolidation_settings,
)
from ...update_check import UpdateInfo
from ...update_check import check as run_update_check

bp = Blueprint("settings", __name__)


THEMES = [
    ("system", "Match the operating system"),
    ("light", "Light"),
    ("dark", "Dark"),
    ("high-contrast", "High contrast (WCAG 2.2 AAA)"),
]
VERBOSITIES = [
    ("concise", "Concise — minimum prose, dense data"),
    ("standard", "Standard — balanced (default)"),
    ("verbose", "Verbose — full descriptions, extra context"),
]


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        theme = request.form.get("theme", "system")
        if theme in {t for t, _ in THEMES}:
            g.project.set_state("theme", theme)
        verb = request.form.get("verbosity", "standard")
        if verb in {v for v, _ in VERBOSITIES}:
            g.project.set_state("verbosity", verb)
        cues = "1" if request.form.get("cues") == "1" else "0"
        g.project.set_state("cues", cues)
        upd = "1" if request.form.get("update_check") == "1" else "0"
        g.project.set_state("update_check", upd)
        # Phase 11 — issue consolidation. Each input is independent;
        # a bad int value is reported back to the operator instead
        # of silently reverting to defaults, so a typo can't quietly
        # disable consolidation on the next scan.
        try:
            new_cs = ConsolidationSettings(
                enabled=request.form.get("consolidation_enabled") == "1",
                path_rollup_threshold=int(
                    request.form.get("consolidation_path_rollup_threshold")
                    or "5"
                ),
                ip_lightweight_threshold=int(
                    request.form.get("consolidation_ip_lightweight_threshold")
                    or "50"
                ),
                cross_host_enabled=(
                    request.form.get("consolidation_cross_host_enabled") == "1"
                ),
            )
            save_consolidation_settings(g.project, new_cs)
        except (TypeError, ValueError) as exc:
            flash(f"Consolidation settings rejected: {exc}", "err")
        return redirect(url_for(".index"))
    cs = load_consolidation_settings(g.project)
    return render_template(
        "settings/index.html",
        themes=THEMES, verbosities=VERBOSITIES,
        current_theme=g.project.get_state("theme", g.settings.default_theme),
        current_verbosity=g.project.get_state("verbosity", g.settings.default_verbosity),
        cues_on=g.project.get_state("cues", "0") == "1",
        update_check_on=g.project.get_state("update_check", "0") == "1",
        update_info=None,
        consolidation=cs,
    )


@bp.route("/check-updates", methods=["POST"])
def check_updates():
    """Opt-in one-shot update check; only runs when the user clicks the button."""
    if g.project.get_state("update_check", "0") != "1":
        flash("Update checks are disabled. Enable them and save first.", "err")
        return redirect(url_for(".index"))
    info: UpdateInfo = run_update_check()
    if info.error:
        flash(f"Update check failed: {info.error}", "warn")
    elif info.update_available:
        flash(f"Update available: {info.latest_version} (current {info.current_version}).",
              "warn")
    else:
        flash(f"You are on the latest version ({info.current_version}).", "ok")
    return redirect(url_for(".index"))
