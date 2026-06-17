"""Sequencer blueprint.

Two surfaces share the same module:

1. **Paste analyser** (the original) -- ``GET/POST /sequencer/``.
   Operator pastes one token per line, picks a significance level,
   optionally turns on deep analysis, presses **Analyse**.

2. **Live capture** -- ``/sequencer/capture/...``. Operator picks a
   request (typically via *Send to Sequencer* on a History row),
   configures an extractor (cookie / header / regex / json), sets a
   sample target, presses **Start**. Reqlore re-fires the request in
   a background thread, extracts the token from each response, and
   the operator can analyse the live-collected pile with the same
   deep statistical battery as the paste flow.

The capture half is the live-capture feature; the paste half is
preserved unchanged so existing tests and muscle memory keep working.
"""
from __future__ import annotations

from flask import (
    Blueprint, Response as FlaskResponse, abort, flash, g, jsonify, redirect,
    render_template, request, url_for,
)

from .._prg import PRGCache
from ...sequencer import analyse, analyse_deep, collect_tokens
from ...sequencer_capture import (
    EXTRACTOR_KINDS, CaptureRunner, get_runner, parse_target_from_history,
    register, unregister,
)

bp = Blueprint("sequencer", __name__)

_cache = PRGCache()

SIGNIFICANCE_OPTIONS = [
    ("0.05",   "0.05 -- 5% (weaker evidence required)"),
    ("0.01",   "0.01 -- 1% (default, common scientific level)"),
    ("0.001",  "0.001 -- 0.1% (stronger evidence required)"),
    ("0.0001", "0.0001 -- 0.01% (FIPS-style strict)"),
]
_VALID_SIG = {key for key, _ in SIGNIFICANCE_OPTIONS}

EXTRACTOR_LABELS = {
    "cookie": "Cookie value (Set-Cookie header)",
    "header": "Response header value",
    "regex":  "Regular expression in response body (one capture group)",
    "json":   "JSON path in response body (dot-separated)",
}

ENGINE_OPTIONS = [
    ("httpx", "httpx -- default Python engine"),
    ("raw",   "raw -- byte-exact, no header rewriting"),
]


# ===================================================================
# Paste analyser (unchanged behaviour)
# ===================================================================

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
    captures = g.project.list_sequencer_captures()
    return render_template(
        "sequencer/index.html",
        tokens_text=stashed.get("tokens_text", ""),
        result=stashed.get("result"),
        significance=stashed.get("significance", "0.01"),
        deep_on=stashed.get("deep_on", True),
        significance_options=SIGNIFICANCE_OPTIONS,
        captures=captures,
    )


# ===================================================================
# Live capture
# ===================================================================

def _form_default() -> dict:
    return {
        "name": "Capture",
        "url": "http://127.0.0.1/",
        "engine": "httpx",
        "extractor_kind": "cookie",
        "extractor_arg": "",
        "max_samples": "200",
        "delay_ms": "0",
        "concurrency": "1",
        "significance": "0.01",
        "template": (
            "GET / HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "User-Agent: reqlore\r\n"
            "Accept: */*\r\n"
            "\r\n"
        ),
    }


@bp.route("/capture/new", methods=["GET", "POST"])
def capture_new():
    form = _form_default()
    error = ""
    if request.method == "GET":
        hid = request.args.get("from_history")
        if hid:
            try:
                row = g.project.get_history(int(hid))
            except ValueError:
                row = None
            if row:
                hint = parse_target_from_history(row.req_blob, row.url)
                form["url"] = row.url
                form["template"] = row.req_blob.decode(
                    "latin-1", errors="replace").replace("\r\n", "\n")
                form["name"] = f"Reqlore_{row.id}"
                form["extractor_kind"] = hint["extractor_kind"]
                form["extractor_arg"] = hint["extractor_arg"]

    if request.method == "POST":
        for k in form:
            if k in request.form:
                form[k] = request.form[k]
        kind = form["extractor_kind"]
        if kind not in EXTRACTOR_KINDS:
            error = f"Unknown extractor: {kind!r}."
        if not error and not form["extractor_arg"].strip():
            error = ("Extractor argument is required (cookie name, header "
                     "name, regex, or JSON path).")
        if not error and form["significance"] not in _VALID_SIG:
            form["significance"] = "0.01"
        if not error and form["engine"] not in {e for e, _ in ENGINE_OPTIONS}:
            error = f"Unknown engine: {form['engine']!r}."
        try:
            max_samples = max(8, min(20000, int(form["max_samples"] or 200)))
        except ValueError:
            max_samples = 200
        try:
            delay_ms = max(0, int(form["delay_ms"] or 0))
        except ValueError:
            delay_ms = 0
        try:
            concurrency = max(1, min(8, int(form["concurrency"] or 1)))
        except ValueError:
            concurrency = 1
        if not error:
            template_bytes = (form["template"].replace("\r\n", "\n")
                              .replace("\n", "\r\n").encode("utf-8"))
            cid = g.project.create_sequencer_capture(
                name=form["name"] or "Capture",
                url=form["url"] or "http://127.0.0.1/",
                template=template_bytes,
                engine=form["engine"],
                extractor_kind=kind,
                extractor_arg=form["extractor_arg"],
                max_samples=max_samples,
                delay_ms=delay_ms,
                concurrency=concurrency,
                significance=form["significance"],
            )
            flash("Capture created. Press Start to begin collecting tokens.",
                  "ok")
            return redirect(url_for(".capture_detail", cid=cid))

    return render_template(
        "sequencer/capture_new.html",
        form=form, error=error,
        extractor_labels=EXTRACTOR_LABELS,
        engine_options=ENGINE_OPTIONS,
        significance_options=SIGNIFICANCE_OPTIONS,
    )


@bp.route("/capture/<int:cid>")
def capture_detail(cid: int):
    cap = g.project.get_sequencer_capture(cid)
    if not cap:
        abort(404)
    runner = get_runner(cid)
    live = bool(runner and runner.is_running())
    # Reconcile stale state: a 'running' or 'paused' DB row with no
    # in-process runner means the server restarted while a capture was
    # active. Persist 'idle' so the controls and status agree.
    if not live and cap["status"] in ("running", "paused"):
        g.project.set_sequencer_capture_status(
            cid, "idle",
            stop_reason=cap["stop_reason"] or "server restarted; press Start to resume",
        )
        cap = g.project.get_sequencer_capture(cid)
    auto = request.args.get("auto") == "1"
    samples = g.project.list_sequencer_samples(cid, limit=20)
    total = g.project.count_sequencer_samples(cid)
    return render_template(
        "sequencer/capture_detail.html",
        cap=cap, samples=samples, total=total, live=live, auto=auto,
        runner_collected=(runner.collected if runner else total),
        runner_errors=(runner.errors if runner else cap["error_count"]),
        extractor_labels=EXTRACTOR_LABELS,
    )


@bp.route("/capture/<int:cid>/samples.json")
def capture_samples_json(cid: int):
    cap = g.project.get_sequencer_capture(cid)
    if not cap:
        abort(404)
    runner = get_runner(cid)
    return jsonify({
        "status": cap["status"],
        "stop_reason": cap["stop_reason"],
        "collected": g.project.count_sequencer_samples(cid),
        "max_samples": cap["max_samples"],
        "errors": (runner.errors if runner else cap["error_count"]),
        "live": bool(runner and runner.is_running()),
    })


@bp.route("/capture/<int:cid>/start", methods=["POST"])
def capture_start(cid: int):
    cap = g.project.get_sequencer_capture(cid)
    if not cap:
        abort(404)
    existing = get_runner(cid)
    if existing and existing.is_running():
        flash("Capture already running.", "warn")
    else:
        runner = CaptureRunner(g.project, cid)
        register(runner)
        runner.start()
        flash("Capture started.", "ok")
    return redirect(url_for(".capture_detail", cid=cid))


@bp.route("/capture/<int:cid>/pause", methods=["POST"])
def capture_pause(cid: int):
    r = get_runner(cid)
    if r and r.is_running() and not r.is_paused():
        r.pause()
        flash("Capture paused. Press Resume to continue.", "ok")
    else:
        flash("Capture is not running.", "warn")
    return redirect(url_for(".capture_detail", cid=cid))


@bp.route("/capture/<int:cid>/resume", methods=["POST"])
def capture_resume(cid: int):
    r = get_runner(cid)
    if r and r.is_paused():
        r.resume()
        flash("Capture resumed.", "ok")
    else:
        flash("Capture is not paused.", "warn")
    return redirect(url_for(".capture_detail", cid=cid))


@bp.route("/capture/<int:cid>/cancel", methods=["POST"])
def capture_cancel(cid: int):
    r = get_runner(cid)
    if r:
        r.cancel()
        flash("Capture cancelled.", "ok")
    else:
        flash("Capture is not running.", "warn")
    return redirect(url_for(".capture_detail", cid=cid))


@bp.route("/capture/<int:cid>/delete", methods=["POST"])
def capture_delete(cid: int):
    r = get_runner(cid)
    if r and r.is_running():
        flash("Stop the capture before deleting it.", "warn")
        return redirect(url_for(".capture_detail", cid=cid))
    g.project.delete_sequencer_capture(cid)
    unregister(cid)
    flash("Capture deleted.", "ok")
    return redirect(url_for(".index"))


@bp.route("/capture/<int:cid>/export.txt")
def capture_export_txt(cid: int):
    cap = g.project.get_sequencer_capture(cid)
    if not cap:
        abort(404)
    tokens = g.project.list_sequencer_tokens(cid)
    body = "\n".join(tokens) + ("\n" if tokens else "")
    return FlaskResponse(
        body, mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="capture-{cid}.txt"'},
    )


@bp.route("/capture/<int:cid>/analyse", methods=["POST"])
def capture_analyse(cid: int):
    """Run deep analysis over the live-captured tokens and forward to
    the paste page so the operator sees the same UI."""
    cap = g.project.get_sequencer_capture(cid)
    if not cap:
        abort(404)
    tokens = g.project.list_sequencer_tokens(cid)
    if not tokens:
        flash("No tokens captured yet -- nothing to analyse.", "warn")
        return redirect(url_for(".capture_detail", cid=cid))
    sig_raw = cap["significance"] if cap["significance"] in _VALID_SIG else "0.01"
    significance = float(sig_raw)
    result = analyse_deep(tokens, significance=significance)
    tokens_text = "\n".join(tokens)
    token = _cache.put({
        "tokens_text": tokens_text,
        "result": result,
        "significance": sig_raw,
        "deep_on": True,
    })
    return redirect(url_for(".index", t=token))
