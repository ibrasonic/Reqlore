"""SAML inspector blueprint."""
from __future__ import annotations

from flask import Blueprint, render_template, request

from ...saml import inspect

bp = Blueprint("saml", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    blob = request.form.get("blob", "") if request.method == "POST" else ""
    result = inspect(blob) if blob else None
    return render_template("saml/index.html", blob=blob, r=result)
