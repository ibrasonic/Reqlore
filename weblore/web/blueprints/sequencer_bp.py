"""Sequencer blueprint: paste tokens, get an entropy report."""
from __future__ import annotations

from flask import Blueprint, render_template, request

from ...sequencer import analyse, collect_tokens

bp = Blueprint("sequencer", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    tokens_text = request.form.get("tokens", "")
    result = None
    if request.method == "POST" and tokens_text.strip():
        tokens = collect_tokens(tokens_text)
        result = analyse(tokens)
    return render_template("sequencer/index.html",
                            tokens_text=tokens_text, result=result)
