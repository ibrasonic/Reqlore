"""OAST blueprint: start/stop local callback receiver; list interactions."""
from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ...oast import LocalOAST

bp = Blueprint("oast", __name__)


def _get_oast(app) -> LocalOAST:
    if "reqlore_oast" not in app.extensions:
        app.extensions["reqlore_oast"] = LocalOAST(host="127.0.0.1", port=0)
    return app.extensions["reqlore_oast"]


@bp.route("/", methods=["GET"])
def index():
    oast = _get_oast(current_app)
    status = oast.status()
    interactions = oast.interactions()
    return render_template("oast/index.html",
                            status=status, interactions=interactions)


@bp.route("/start", methods=["POST"])
def start():
    oast = _get_oast(current_app)
    port = oast.start()
    flash(f"OAST receiver listening on http://127.0.0.1:{port}/", "ok")
    return redirect(url_for("oast.index"))


@bp.route("/stop", methods=["POST"])
def stop():
    oast = _get_oast(current_app)
    oast.stop()
    flash("OAST receiver stopped.", "ok")
    return redirect(url_for("oast.index"))


@bp.route("/new-token", methods=["POST"])
def new_token():
    oast = _get_oast(current_app)
    if not oast.is_running():
        oast.start()
    tok = oast.new_token()
    flash(f"New token: {tok} (URL: {oast.url_for(tok)})", "ok")
    return redirect(url_for("oast.index"))


@bp.route("/clear", methods=["POST"])
def clear():
    oast = _get_oast(current_app)
    oast.clear()
    flash("Interactions cleared.", "ok")
    return redirect(url_for("oast.index"))
