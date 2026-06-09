"""SAML inspector blueprint."""
from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, url_for

from .._prg import PRGCache
from ...saml import inspect

bp = Blueprint("saml", __name__)

_cache = PRGCache()


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        blob = request.form.get("blob", "")
        result = inspect(blob) if blob else None
        token = _cache.put({"blob": blob, "result": result})
        return redirect(url_for(".index", t=token))
    stashed = _cache.get(request.args.get("t")) or {}
    return render_template("saml/index.html",
                            blob=stashed.get("blob", ""),
                            r=stashed.get("result"))
