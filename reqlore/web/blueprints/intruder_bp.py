"""Intruder UI."""
from __future__ import annotations

import csv
import io
import json
import os
import re as _re
from datetime import UTC, datetime
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ...intruder import (
    COMMON_PASSWORDS,
    DEFAULT_MARKER,
    WORDLISTS,
    AttackRunner,
    count_wordlist_lines,
    find_positions,
    get_runner,
    load_wordlist_bytes,
    payloads_brute,
    payloads_from_text,
    payloads_numbers,
    processor_names,
    register,
    wordlist_names,
)

bp = Blueprint("intruder", __name__)


ATTACK_TYPES = [
    ("sniper", "Sniper — one position at a time (single payload set)"),
    ("battering", "Battering Ram — same payload in every position"),
    ("pitchfork", "Pitchfork — N sets advance in lockstep"),
    ("clusterbomb", "Cluster Bomb — every combination (cartesian)"),
]


@bp.route("/")
def index():
    attacks = g.project.list_intruder()
    return render_template("intruder/index.html", attacks=attacks)


@bp.route("/new", methods=["GET", "POST"])
def new():
    form = {
        "name": "",
        "attack_type": "sniper",
        "engine": "httpx",
        "url": "http://127.0.0.1/",
        "template": (
            f"GET /?q={DEFAULT_MARKER}admin{DEFAULT_MARKER} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nUser-Agent: reqlore\r\nAccept: */*\r\n\r\n"
        ),
        "marker": DEFAULT_MARKER,
        "concurrency": "4",
        "delay_ms": "0",
        "max_requests": "1000",
        "processors": "",
        "grep": "",
        "payloads_text": "admin\nroot\nguest\ntest\nuser",
        "payloads_set2": "",
        "payloads_set3": "",
        "payloads_set4": "",
        "source": "text",
        "num_start": "0",
        "num_end": "100",
        "num_step": "1",
        "brute_alphabet": "abc",
        "brute_min": "1",
        "brute_max": "3",
        "wordlist_name": "common_passwords",
        "wordlist_path": "",
        "retries": "0",
        "stop_on_match": "",
        "stop_on_status": "",
    }
    # Per-position source config for pitchfork / cluster-bomb attacks.
    # Set 1 uses the un-suffixed fields above (backward-compatible). Sets
    # 2-4 each carry a full copy of the source-selector inputs so a
    # multi-position attack can pair, e.g., a text list with a number
    # range (IDOR + username fuzz). Empty ``source_setN`` means "skip
    # this set" for non-text sources, or "fall back to reading
    # payloads_setN as text" so the pre-existing text-only workflow
    # keeps working. See _collect_payload_sets below.
    for n in (2, 3, 4):
        form.update({
            f"source_set{n}": "",
            f"num_start_set{n}": "0",
            f"num_end_set{n}": "100",
            f"num_step_set{n}": "1",
            f"brute_alphabet_set{n}": "abc",
            f"brute_min_set{n}": "1",
            f"brute_max_set{n}": "3",
            f"wordlist_name_set{n}": "common_passwords",
            f"wordlist_path_set{n}": "",
        })
    error = ""
    # Pre-fill the request template from a History row when arriving via
    # "Send to Intruder" from another panel (Proxy queue, History, etc.).
    if request.method == "GET":
        hid = request.args.get("from_history")
        if hid:
            try:
                row = g.project.get_history(int(hid))
            except ValueError:
                row = None
            if row:
                form["url"] = row.url
                form["template"] = row.req_blob.decode(
                    "latin-1", errors="replace").replace("\r\n", "\n")
                form["name"] = f"Reqlore_{row.id}"
    if request.method == "POST":
        for k in form:
            if k in request.form:
                form[k] = request.form[k]

        template = form["template"].replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
        marker = form["marker"] or DEFAULT_MARKER
        positions = find_positions(template, marker)
        if not positions:
            error = (f"No markers found. Wrap insertion points with {marker} "
                     f"(e.g. {marker}payload{marker}).")
        else:
            try:
                payload_sets = _collect_payload_sets(form)
            except ValueError as exc:
                payload_sets = []
                error = str(exc)
            if not error and (not payload_sets or not payload_sets[0]):
                error = "Payload set is empty."
            if not error:
                stop_codes: list[int] = []
                for tok in (form["stop_on_status"] or "").replace(";", ",").split(","):
                    tok = tok.strip()
                    if tok.isdigit():
                        stop_codes.append(int(tok))
                options = {
                    "concurrency": int(form["concurrency"] or 4),
                    "delay_ms": int(form["delay_ms"] or 0),
                    "max_requests": int(form["max_requests"] or 1000),
                    "processors": [
                        p.strip() for p in (form["processors"] or "").split(",")
                        if p.strip()
                    ],
                    "grep": [g for g in (form["grep"] or "").splitlines() if g.strip()],
                    "retries": max(0, int(form["retries"] or 0)),
                    "stop_on_match": bool(form.get("stop_on_match")),
                    "stop_on_status": stop_codes,
                }
                aid = g.project.create_intruder(
                    name=form["name"] or "Attack",
                    attack_type=form["attack_type"],
                    template=template,
                    positions=positions,
                    payloads=payload_sets,
                    options=options,
                    url=form["url"],
                    engine=form["engine"],
                )
                flash(f"Created attack #{aid}.", "ok")
                return redirect(url_for("intruder.detail", aid=aid))
    return render_template(
        "intruder/new.html", form=form, attack_types=ATTACK_TYPES,
        processors=processor_names(), wordlists=wordlist_names(),
        error=error, marker=DEFAULT_MARKER,
    )


def _collect_payload_sets(form: dict) -> list:
    """Return a list of payload-set entries for storage.

    Each entry is either a ``list[str]`` (inline values, used for every
    source except ``wordlist_path``) or a ``{"kind": "path", "path": str}``
    dict for the streaming server-path source. Both shapes round-trip
    through ``intruder.build_sources_from_storage`` at run time.

    For Sniper / Battering Ram only Set 1 (the un-suffixed source +
    input fields) is consumed. For Pitchfork / Cluster Bomb every set
    with a non-empty source_setN (or a filled payloads_setN textarea
    when the global source is ``text``) contributes an independent
    payload source, so a two-position attack can pair a text list with
    a number range and a three-position attack can add a wordlist on
    top -- one dropdown per marker, each with the full source menu.
    """
    attack_type = form["attack_type"]
    set1 = _collect_one_set(form, form.get("source", "text"), suffix="")
    if attack_type in ("sniper", "battering"):
        return [set1] if set1 is not None else []

    sets: list = []
    if set1 is not None:
        sets.append(set1)
    global_src = form.get("source", "text")
    for n in (2, 3, 4):
        suffix = f"_set{n}"
        per_set_src = (form.get(f"source_set{n}") or "").strip()
        if per_set_src:
            one = _collect_one_set(form, per_set_src, suffix=suffix)
        elif global_src == "text":
            # Backward-compat: an operator on the "text" global source
            # who just fills payloads_set2/3/4 keeps the pre-existing
            # multi-text-set workflow (docs and tests rely on this).
            text = (form.get(f"payloads{suffix}") or "").strip()
            one = payloads_from_text(text) if text else None
        else:
            # Non-text global source, no per-set override: skip this
            # set. The operator must pick a per-set source explicitly
            # to add a Set N when Set 1 is anything other than text.
            one = None
        if one is not None:
            sets.append(one)
    return sets


def _collect_one_set(form: dict, src: str, *, suffix: str):
    """Materialise a single payload set for the given ``src`` and ``suffix``.

    ``suffix`` is ``""`` for Set 1 (un-suffixed field names) or
    ``"_set2"`` / ``"_set3"`` / ``"_set4"`` for the extra pitchfork /
    cluster-bomb positions. Returns ``list[str]`` for inline sources,
    ``{"kind": "path", "path": str}`` for streaming, or ``None`` when
    a text set is empty (skipped by the caller). Raises ``ValueError``
    on user input problems so the blueprint can surface them inline.
    """
    set_label = "set 1" if not suffix else "set " + suffix.rsplit("_set", 1)[1]

    if src == "text":
        # Set 1 uses ``payloads_text``; Sets 2-4 use ``payloads_set{n}``
        # (kept for backward compat with the pre-existing text-only
        # multi-set UI and tests).
        key = "payloads_text" if not suffix else f"payloads{suffix}"
        s = (form.get(key) or "").strip()
        if not s:
            # Set 1 empty -> return empty list so the "Payload set is
            # empty" guard in ``new()`` fires. Sets 2-4 empty -> None
            # so the caller skips them.
            return [] if not suffix else None
        return payloads_from_text(s)

    if src == "numbers":
        return payloads_numbers(
            int(form.get(f"num_start{suffix}") or 0),
            int(form.get(f"num_end{suffix}") or 0),
            int(form.get(f"num_step{suffix}") or 1),
        )

    if src == "brute":
        # cap brute force to avoid runaway clusterbombs in the UI
        return list(_capped(payloads_brute(
            form.get(f"brute_alphabet{suffix}", ""),
            int(form.get(f"brute_min{suffix}") or 1),
            int(form.get(f"brute_max{suffix}") or 1),
        ), 50_000))

    if src == "common_pw":
        return list(COMMON_PASSWORDS)

    if src == "wordlist":
        name = form.get(f"wordlist_name{suffix}", "")
        wl = WORDLISTS.get(name)
        if wl is None:
            raise ValueError(f"Unknown built-in wordlist for {set_label}: {name!r}")
        return list(wl)

    if src == "wordlist_file":
        # The UI uploads the file as multipart/form-data so the operator
        # never has to type a server-side path. CLI/spec users still get
        # `load_wordlist_file(path)` via reqlore.intruder.
        field = "wordlist_upload" if not suffix else f"wordlist_upload{suffix}"
        upload = request.files.get(field)
        if upload is None or not upload.filename:
            raise ValueError(f"No wordlist file selected for {set_label}.")
        return load_wordlist_bytes(upload.read())

    if src == "wordlist_path":
        # Streaming source: store only the absolute path, never read the
        # file into memory. The runner opens it fresh on each pass via
        # ``from_path`` so even rockyou-class wordlists stay O(1) RAM.
        raw = (form.get(f"wordlist_path{suffix}") or "").strip()
        if not raw:
            raise ValueError(
                f"Server path is required for the streaming wordlist source ({set_label}).")
        p = Path(raw)
        if not p.is_absolute():
            raise ValueError(
                f"Server path must be absolute for {set_label} "
                f"(e.g. /usr/share/wordlists/rockyou.txt).")
        if not p.is_file():
            raise ValueError(f"File not found for {set_label}: {raw}")
        if not os.access(p, os.R_OK):
            raise ValueError(
                f"File not readable by the Reqlore process for {set_label}: {raw}")
        try:
            count_wordlist_lines(p)
        except OSError as exc:
            raise ValueError(f"Cannot read server path for {set_label}: {exc}") from exc
        return {"kind": "path", "path": str(p)}

    raise ValueError(f"Unknown payload source for {set_label}: {src!r}")


def _capped(gen, n: int) -> list[str]:
    out: list[str] = []
    for x in gen:
        out.append(x)
        if len(out) >= n:
            break
    return out


@bp.route("/<int:aid>")
def detail(aid: int):
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    sort = request.args.get("sort", "seq")
    desc = request.args.get("desc") == "1"
    auto = request.args.get("auto") == "1"
    filters = _parse_filters(request.args)
    all_results = g.project.list_intruder_results(aid, sort=sort, desc=desc)
    results, dedup_count = _apply_filters(all_results, filters)
    runner = get_runner(aid)
    live = bool(runner and runner.is_running())
    return render_template(
        "intruder/detail.html", attack=attack, results=results,
        sort=sort, desc=desc, auto=auto, live=live,
        total=len(all_results), filtered=len(results),
        unique_responses=len({r["body_md5"] for r in all_results if r["body_md5"]}),
        dedup_hidden=dedup_count, filters=filters,
        total_jobs=(runner.total_jobs if runner else 0),
        stop_reason=(runner.stop_reason if runner else ""),
    )


def _parse_filters(args) -> dict:
    """Return a normalised filter dict from request args."""
    sc = args.get("sc", "")  # status class: 2xx/3xx/4xx/5xx or ''
    if sc not in ("", "2xx", "3xx", "4xx", "5xx"):
        sc = ""

    def _int_or_none(s: str | None):
        try:
            return int(s) if s is not None and s != "" else None
        except ValueError:
            return None

    return {
        "sc": sc,
        "len_min": _int_or_none(args.get("len_min")),
        "len_max": _int_or_none(args.get("len_max")),
        "q": (args.get("q") or "").strip(),
        "matched": args.get("matched", ""),  # '', 'yes', 'no'
        "dedup": args.get("dedup") == "1",
    }


def _apply_filters(rows: list[dict], f: dict) -> tuple[list[dict], int]:
    """Return ``(visible_rows, n_dedup_hidden)``."""
    out: list[dict] = []
    seen_hashes: set[str] = set()
    dedup_hidden = 0
    for r in rows:
        s = r["status"]
        if f["sc"] == "2xx" and not (200 <= s < 300):
            continue
        if f["sc"] == "3xx" and not (300 <= s < 400):
            continue
        if f["sc"] == "4xx" and not (400 <= s < 500):
            continue
        if f["sc"] == "5xx" and not (500 <= s < 600):
            continue
        if f["len_min"] is not None and r["len_resp"] < f["len_min"]:
            continue
        if f["len_max"] is not None and r["len_resp"] > f["len_max"]:
            continue
        if f["matched"] == "yes" and not r["matched"]:
            continue
        if f["matched"] == "no" and r["matched"]:
            continue
        if f["q"]:
            hay = " ".join([*(str(p) for p in r["payloads"]), r["grep_hits"]]).lower()
            if f["q"].lower() not in hay:
                continue
        if f["dedup"] and r["body_md5"]:
            if r["body_md5"] in seen_hashes:
                dedup_hidden += 1
                continue
            seen_hashes.add(r["body_md5"])
        out.append(r)
    return out, dedup_hidden


@bp.route("/<int:aid>/results.json")
def results_json(aid: int):
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    try:
        since = int(request.args.get("since", "-1"))
    except ValueError:
        since = -1
    results = g.project.list_intruder_results(aid, sort="seq", desc=False)
    new_rows = [r for r in results if r["seq"] > since]
    runner = get_runner(aid)
    return jsonify({
        "attack_id": aid,
        "status": attack["status"],
        "live": bool(runner and runner.is_running()),
        "count": len(results),
        "total": runner.total_jobs if runner else None,
        "stop_reason": runner.stop_reason if runner else "",
        "since": since,
        "rows": new_rows,
    })


_EXPORT_COLUMNS = [
    "seq", "status", "len_resp", "duration_ms", "matched",
    "grep_hits", "body_md5", "payloads", "history_id",
]


def _safe_filename(name: str) -> str:
    """Return a filesystem-safe slug suitable for Content-Disposition."""
    slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "attack").strip()).strip("_")
    return slug or "attack"


def _row_for_export(r: dict) -> dict:
    return {
        "seq": r["seq"],
        "status": r["status"],
        "len_resp": r["len_resp"],
        "duration_ms": r["duration_ms"],
        "matched": 1 if r["matched"] else 0,
        "grep_hits": r["grep_hits"],
        "body_md5": r["body_md5"],
        "payloads": "|".join(str(p) for p in r["payloads"]),
        "history_id": r["history_id"] if r["history_id"] is not None else "",
    }


def _fetch_filtered_results(aid: int):
    """Return ``(attack, filtered_rows, all_rows, filters)`` honouring query args."""
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    sort = request.args.get("sort", "seq")
    desc = request.args.get("desc") == "1"
    filters = _parse_filters(request.args)
    all_rows = g.project.list_intruder_results(aid, sort=sort, desc=desc)
    rows, _hidden = _apply_filters(all_rows, filters)
    return attack, rows, all_rows, filters


@bp.route("/<int:aid>/export.csv")
def export_csv(aid: int):
    attack, rows, _all, _filters = _fetch_filtered_results(aid)
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow(_row_for_export(r))
    fname = f"intruder-{aid}-{_safe_filename(attack['name'])}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@bp.route("/<int:aid>/export.json")
def export_json(aid: int):
    attack, rows, all_rows, filters = _fetch_filtered_results(aid)
    payload = {
        "attack": {
            "id": attack["id"],
            "name": attack["name"],
            "attack_type": attack["attack_type"],
            "engine": attack["engine"],
            "status": attack["status"],
        },
        "exported_at": datetime.now(UTC).isoformat(),
        "total": len(all_rows),
        "exported": len(rows),
        "filters": filters,
        "rows": [_row_for_export(r) for r in rows],
    }
    fname = f"intruder-{aid}-{_safe_filename(attack['name'])}.json"
    return Response(
        json.dumps(payload, indent=2),
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@bp.route("/<int:aid>/start", methods=["POST"])
def start(aid: int):
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    existing = get_runner(aid)
    if existing and existing.is_running():
        flash("Attack already running.", "warn")
    else:
        runner = AttackRunner(g.project, aid)
        register(runner)
        runner.start()
        flash("Attack started.", "ok")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/pause", methods=["POST"])
def pause(aid: int):
    r = get_runner(aid)
    if r and r.is_running() and not r.is_paused():
        r.pause()
        flash("Attack paused. In-flight requests will finish; no new requests will start.", "ok")
    else:
        flash("Attack is not running.", "warn")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/resume", methods=["POST"])
def resume(aid: int):
    r = get_runner(aid)
    if r and r.is_paused():
        r.resume()
        flash("Attack resumed.", "ok")
    else:
        flash("Attack is not paused.", "warn")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/cancel", methods=["POST"])
def cancel(aid: int):
    r = get_runner(aid)
    if r:
        r.cancel()
        flash("Attack cancelled.", "ok")
    else:
        flash("Attack not running.", "warn")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/delete", methods=["POST"])
def delete(aid: int):
    g.project.delete_intruder(aid)
    flash("Attack deleted.", "ok")
    return redirect(url_for("intruder.index"))
