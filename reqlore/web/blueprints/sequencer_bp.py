"""Sequencer blueprint: paste tokens, get an entropy report."""
from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, url_for

from .._prg import PRGCache
from ...sequencer import analyse, collect_tokens

bp = Blueprint("sequencer", __name__)

_cache = PRGCache()


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        tokens_text = request.form.get("tokens", "")
        result = None
        if tokens_text.strip():
            tokens = collect_tokens(tokens_text)
            result = analyse(tokens)
        token = _cache.put({"tokens_text": tokens_text, "result": result})
        return redirect(url_for(".index", t=token))
    stashed = _cache.get(request.args.get("t")) or {}
    return render_template("sequencer/index.html",
                            tokens_text=stashed.get("tokens_text", ""),
                            result=stashed.get("result"))
