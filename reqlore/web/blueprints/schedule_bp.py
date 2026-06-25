"""Scheduled passive scans blueprint."""
from __future__ import annotations

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request, url_for,
)

from ...scheduler import Scheduler, SchedulerLockError

bp = Blueprint("schedule", __name__)


_AUTO_START_KEY = "sched:auto_start"


def _get(app) -> Scheduler:
    if "reqlore_scheduler" not in app.extensions:
        app.extensions["reqlore_scheduler"] = Scheduler(g.project)
    return app.extensions["reqlore_scheduler"]


@bp.route("/")
def index():
    sched = _get(current_app)
    auto_start = g.project.get_state(_AUTO_START_KEY, "0") == "1"
    return render_template("schedule/index.html",
                            status=sched.status(),
                            auto_start=auto_start)


@bp.route("/start", methods=["POST"])
def start():
    sched = _get(current_app)
    try:
        backend = sched.start()
    except SchedulerLockError as exc:
        flash(str(exc), "err")
        return redirect(url_for(".index"))
    flash(f"Scheduler started (backend={backend}).", "ok")
    return redirect(url_for(".index"))


@bp.route("/stop", methods=["POST"])
def stop():
    sched = _get(current_app)
    sched.stop()
    flash("Scheduler stopped.", "ok")
    return redirect(url_for(".index"))


@bp.route("/add", methods=["POST"])
def add():
    sched = _get(current_app)
    name = (request.form.get("name") or "").strip()
    try:
        interval = max(30, int(request.form.get("interval_s", "3600")))
    except ValueError:
        interval = 3600
    try:
        limit = max(1, min(50_000, int(request.form.get("scan_limit", "1000"))))
    except ValueError:
        limit = 1000
    if not name:
        flash("Job name is required.", "err")
        return redirect(url_for(".index"))
    try:
        sched.add_job(name=name, interval_s=interval, scan_limit=limit)
        flash(f"Job '{name}' added (every {interval}s, limit {limit}).", "ok")
    except ValueError as exc:
        flash(str(exc), "err")
    return redirect(url_for(".index"))


@bp.route("/remove/<name>", methods=["POST"])
def remove(name: str):
    sched = _get(current_app)
    if sched.remove_job(name):
        flash(f"Job '{name}' removed.", "ok")
    else:
        flash(f"Job '{name}' not found.", "err")
    return redirect(url_for(".index"))


@bp.route("/run/<name>", methods=["POST"])
def run(name: str):
    sched = _get(current_app)
    try:
        n = sched.run_now(name)
        flash(f"Job '{name}' ran: {n} new finding(s).", "ok")
    except KeyError:
        flash(f"Job '{name}' not found.", "err")
    return redirect(url_for(".index"))


@bp.route("/<name>/toggle", methods=["POST"])
def toggle_job(name: str):
    """Flip a single job's enabled flag without removing it.

    Disabled jobs stay in the persisted list (so `Run now` still works)
    but the background loop skips them.
    """
    sched = _get(current_app)
    current = next((j for j in sched.list_jobs() if j.name == name), None)
    if current is None:
        flash(f"Job '{name}' not found.", "err")
        return redirect(url_for(".index"))
    sched.set_enabled(name, not current.enabled)
    state = "enabled" if not current.enabled else "disabled"
    flash(f"Job '{name}' {state}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/auto-start", methods=["POST"])
def toggle_auto_start():
    """Toggle whether the scheduler starts itself on the next app boot.

    Off by default (SC 3.2.5 Change on Request — background work
    only runs after the operator opts in). The boot hook in
    ``reqlore.web.__init__`` reads ``sched:auto_start`` once during
    app creation.
    """
    new_val = "1" if g.project.get_state(_AUTO_START_KEY, "0") != "1" else "0"
    g.project.set_state(_AUTO_START_KEY, new_val)
    if new_val == "1":
        flash("Scheduler will auto-start on next app boot.", "ok")
    else:
        flash("Scheduler auto-start disabled.", "ok")
    return redirect(url_for(".index"))
