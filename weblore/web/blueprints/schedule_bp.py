"""Scheduled passive scans blueprint."""
from __future__ import annotations

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request, url_for,
)

from ...scheduler import Scheduler

bp = Blueprint("schedule", __name__)


def _get(app) -> Scheduler:
    if "weblore_scheduler" not in app.extensions:
        app.extensions["weblore_scheduler"] = Scheduler(g.project)
    return app.extensions["weblore_scheduler"]


@bp.route("/")
def index():
    sched = _get(current_app)
    return render_template("schedule/index.html", status=sched.status())


@bp.route("/start", methods=["POST"])
def start():
    sched = _get(current_app)
    backend = sched.start()
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
