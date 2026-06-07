"""Settings: theme, verbosity, keyboard map (display only for now)."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ...update_check import UpdateInfo, check as run_update_check

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
        return redirect(url_for(".index"))
    return render_template(
        "settings/index.html",
        themes=THEMES, verbosities=VERBOSITIES,
        current_theme=g.project.get_state("theme", g.settings.default_theme),
        current_verbosity=g.project.get_state("verbosity", g.settings.default_verbosity),
        cues_on=g.project.get_state("cues", "0") == "1",
        update_check_on=g.project.get_state("update_check", "0") == "1",
        update_info=None,
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
