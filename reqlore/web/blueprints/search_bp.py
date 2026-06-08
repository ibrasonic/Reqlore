"""Project-wide search across history req/resp bodies and URLs."""
from __future__ import annotations

from flask import Blueprint, g, render_template, request

bp = Blueprint("search", __name__)


@bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    where = request.args.get("where", "any")
    results = g.project.search(q, where=where) if q else []
    return render_template("search/index.html", q=q, where=where, results=results)
