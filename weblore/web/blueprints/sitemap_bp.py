"""Sitemap + scope rules."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

bp = Blueprint("sitemap", __name__)


@bp.route("/")
def index():
    host = request.args.get("host") or None
    nodes = g.project.sitemap(host=host)
    hosts = g.project.hosts()
    scope = g.project.list_scope()
    return render_template("sitemap/index.html", nodes=nodes, hosts=hosts,
                           current_host=host, scope=scope)


@bp.route("/scope/add", methods=["POST"])
def add_scope():
    kind = request.form.get("kind", "include")
    pattern = request.form.get("pattern", "").strip()
    target = request.form.get("target", "host")
    if not pattern:
        flash("Pattern required.", "err")
    else:
        g.project.add_scope(kind, pattern, target)
        flash("Scope rule added.", "ok")
    return redirect(url_for("sitemap.index"))


@bp.route("/scope/<int:sid>/toggle", methods=["POST"])
def toggle_scope(sid: int):
    g.project.toggle_scope(sid)
    return redirect(url_for("sitemap.index"))


@bp.route("/scope/<int:sid>/delete", methods=["POST"])
def delete_scope(sid: int):
    g.project.delete_scope(sid)
    return redirect(url_for("sitemap.index"))
