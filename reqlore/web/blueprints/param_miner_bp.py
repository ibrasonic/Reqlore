"""Param-miner blueprint — surface :mod:`reqlore.param_miner` in the UI."""
from __future__ import annotations

from flask import Blueprint, g, render_template, request

from ...param_miner import DEFAULT_WORDS, MineOptions, mine

bp = Blueprint("param_miner", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    form = {
        "url": request.form.get("url", ""),
        "method": request.form.get("method", "GET"),
        "location": request.form.get("location", "query"),
        "max_words": request.form.get("max_words", "50"),
        "rate_delay": request.form.get("rate_delay", "0"),
        "extra": request.form.get("extra", ""),
    }
    result = None
    error = ""
    if request.method == "POST" and form["url"].strip():
        try:
            max_words = max(1, min(int(form["max_words"] or 50), len(DEFAULT_WORDS)))
        except ValueError:
            max_words = 50
        try:
            delay = max(0, min(2000, int(form["rate_delay"] or 0)))
        except ValueError:
            delay = 0
        location = form["location"] if form["location"] in ("query", "body", "header") else "query"
        method = (form["method"] or "GET").upper()
        opts = MineOptions(location=location, method=method,
                           max_words=max_words, rate_delay_ms=delay)
        extra_words = [w.strip() for w in form["extra"].splitlines() if w.strip()]
        wordlist = list(DEFAULT_WORDS) + extra_words
        try:
            result = mine(form["url"].strip(), words=wordlist, options=opts)
        except Exception as exc:  # network / DNS errors should be visible, not 500
            error = f"{type(exc).__name__}: {exc}"
    return render_template("param_miner/index.html", form=form,
                            result=result, error=error,
                            word_count=len(DEFAULT_WORDS))
