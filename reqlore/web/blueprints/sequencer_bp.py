"""Sequencer blueprint: paste tokens, get a Burp-Sequencer-style entropy
report (basic Shannon + per-position) plus optional deep statistical
battery (transition / FIPS bit-level tests / correlation)."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from .._prg import PRGCache
from ...sequencer import analyse, analyse_deep, collect_tokens

bp = Blueprint("sequencer", __name__)

_cache = PRGCache()

# Significance levels the user can pick from. Order matters: dropdown
# rendered in this order. 0.01 is the default scientific level.
SIGNIFICANCE_OPTIONS = [
    ("0.05",   "0.05 -- 5% (weaker evidence required)"),
    ("0.01",   "0.01 -- 1% (default, common scientific level)"),
    ("0.001",  "0.001 -- 0.1% (stronger evidence required)"),
    ("0.0001", "0.0001 -- 0.01% (FIPS-style strict)"),
]
_VALID_SIG = {key for key, _ in SIGNIFICANCE_OPTIONS}


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        tokens_text = request.form.get("tokens", "")
        sig_raw = request.form.get("significance", "0.01")
        if sig_raw not in _VALID_SIG:
            sig_raw = "0.01"
        significance = float(sig_raw)
        deep_on = request.form.get("deep") == "1"

        result = None
        if tokens_text.strip():
            tokens = collect_tokens(tokens_text)
            if deep_on:
                result = analyse_deep(tokens, significance=significance)
            else:
                result = analyse(tokens)
        else:
            flash("Paste at least one token before analysing.", "warn")

        token = _cache.put({
            "tokens_text": tokens_text,
            "result": result,
            "significance": sig_raw,
            "deep_on": deep_on,
        })
        return redirect(url_for(".index", t=token))

    stashed = _cache.get(request.args.get("t")) or {}
    return render_template(
        "sequencer/index.html",
        tokens_text=stashed.get("tokens_text", ""),
        result=stashed.get("result"),
        significance=stashed.get("significance", "0.01"),
        deep_on=stashed.get("deep_on", True),
        significance_options=SIGNIFICANCE_OPTIONS,
    )
