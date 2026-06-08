"""Plugins UI: list discovered plugins, reload, toggle, optional hot-watch."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ...plugins import get_registry

bp = Blueprint("plugins", __name__)


@bp.route("/")
def index():
    reg = get_registry()
    return render_template("plugins/index.html", plugins=reg.list(),
                           dirs=[str(d) for d in reg.dirs])


@bp.route("/reload", methods=["POST"])
def reload_plugins():
    reg = get_registry()
    plugs = reg.discover()
    ok = sum(1 for p in plugs if not p.error)
    err = sum(1 for p in plugs if p.error)
    flash(f"Discovered {len(plugs)} plugin(s): {ok} loaded, {err} with errors.",
          "ok" if err == 0 else "warn")
    return redirect(url_for(".index"))


@bp.route("/<name>/toggle", methods=["POST"])
def toggle(name: str):
    reg = get_registry()
    if reg.get(name) is None:
        flash(f"No plugin named '{name}'.", "err")
    else:
        new_state = reg.toggle(name)
        flash(f"Plugin '{name}' {'enabled' if new_state else 'disabled'}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/watch", methods=["POST"])
def watch():
    reg = get_registry()
    on = request.form.get("on") == "1"
    if on:
        started = reg.start_watch()
        if started:
            g.project.set_state("plugin_watch", "1")
            flash("Hot reload enabled — changes in the plugin folder reload automatically.", "ok")
        else:
            flash("Hot reload requires the 'watchdog' package (pip install watchdog).", "warn")
    else:
        reg.stop_watch()
        g.project.set_state("plugin_watch", "0")
        flash("Hot reload disabled.", "ok")
    return redirect(url_for(".index"))
