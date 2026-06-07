"""Dashboard / home page."""
from __future__ import annotations

from flask import Blueprint, g, render_template

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    meta = g.project.meta()
    return render_template("dashboard.html", meta=meta)
