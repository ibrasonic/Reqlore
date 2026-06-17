"""DOM Hunter - DOM XSS source/sink tracer (server-side).

Three surfaces:
- /dom-hunter/                  human UI: findings list, detail, messages, settings
- /_dom_hunter/report           bridge: extension POSTs findings/messages here
- /_dom_hunter/config           bridge: extension GETs canary + scope + token
"""
from __future__ import annotations

import json

from flask import (
    Blueprint, abort, current_app, flash, g, jsonify, redirect,
    render_template, request, url_for,
)

from ... import dom_hunter as S

bp = Blueprint("dom_hunter", __name__)


# ---------------------------------------------------------------------------
# bridge auth
# ---------------------------------------------------------------------------

def _check_token() -> None:
    """Validate the X-DOMHunter-Token header for bridge requests. 401 on fail.

    Accepts the project's CURRENT token, or the immediately-previous
    token within ``TOKEN_ROTATION_GRACE_SECONDS`` of a rotation, so a
    running extension can self-heal after the user clicks "Rotate
    bridge token" without needing a browser relaunch.
    """
    got = request.headers.get("X-DOMHunter-Token", "")
    if not S.is_valid_token(g.project, got):
        abort(401, description="Bad or missing DOM Hunter token.")


def _ct_equal(a: str, b: str) -> bool:
    """Constant-time string compare."""
    import secrets as _s
    return _s.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _truncate(s: str, n: int = 4096) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "... [truncated]"


# ---------------------------------------------------------------------------
# human UI
# ---------------------------------------------------------------------------

@bp.route("/", methods=["GET"])
def index():
    q = (request.args.get("q", "") or "").strip()
    min_sev = (request.args.get("sev", "info") or "info").lower()
    if min_sev not in S.SEVERITIES:
        min_sev = "info"
    rows = g.project.list_dom_hunter_findings(limit=200, min_severity=min_sev, q=q or None)
    return render_template(
        "dom_hunter/index.html",
        findings=rows, q=q, min_sev=min_sev, severities=S.SEVERITIES,
        sink_index=S.SINK_INDEX, source_index=S.SOURCE_INDEX,
        enabled=S.is_enabled(g.project),
        canary=S.get_or_make_canary(g.project),
        token=S.get_or_make_token(g.project),
        scope=S.get_scope(g.project),
        dom_hunter_messages_count=g.project.dom_hunter_messages_count(),
    )


@bp.route("/finding/<int:fid>", methods=["GET"])
def detail(fid: int):
    row = g.project.get_dom_hunter_finding(fid)
    if not row:
        abort(404)
    raw_source = row["source"] or ""
    source_ids = [p.strip() for p in raw_source.split(",") if p.strip()]
    source_metas = [
        S.SOURCE_INDEX[s] for s in source_ids if s in S.SOURCE_INDEX
    ]
    return render_template(
        "dom_hunter/detail.html",
        f=row,
        sink_meta=S.SINK_INDEX.get(row["sink"]),
        source_metas=source_metas,
    )


@bp.route("/messages", methods=["GET"])
def messages():
    origin = (request.args.get("origin", "") or "").strip()
    only = request.args.get("only_canary", "") == "1"
    rows = g.project.list_dom_hunter_messages(
        limit=200, origin=origin or None, only_canary=only,
    )
    origins = sorted({r["origin"] for r in g.project.list_dom_hunter_messages(limit=2000)})
    return render_template(
        "dom_hunter/messages.html",
        messages=rows, origin=origin, only_canary=only, origins=origins,
    )


@bp.route("/clear-findings", methods=["POST"])
def clear_findings():
    n = g.project.clear_dom_hunter_findings()
    flash(f"Cleared {n} DOM Hunter findings.", "ok")
    return redirect(url_for(".index"))


@bp.route("/clear-messages", methods=["POST"])
def clear_messages():
    n = g.project.clear_dom_hunter_messages()
    flash(f"Cleared {n} recorded web messages.", "ok")
    return redirect(url_for(".messages"))


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "save":
            enabled = request.form.get("enabled") == "1"
            S.set_enabled(g.project, enabled)
            scope_raw = request.form.get("scope", "")
            hosts = [h for h in (scope_raw or "").replace(",", "\n").splitlines()]
            S.set_scope(g.project, hosts)
            targets = request.form.getlist("auto_inject")
            S.set_auto_inject(g.project, targets)
            flash("DOM Hunter settings saved. Reload the target tab to apply.", "ok")
        elif action == "rotate_canary":
            g.project.set_state(S.CANARY_KEY, "")
            S.get_or_make_canary(g.project)
            flash(
                "Canary rotated. Reload any open target tabs to pick"
                " up the new value; existing findings remain.",
                "ok",
            )
        elif action == "rotate_token":
            S.rotate_token(g.project)
            flash(
                "Bridge token rotated. The running extension will"
                " pick up the new token within a few seconds via the"
                " bridge config response -- no browser relaunch needed.",
                "ok",
            )
        return redirect(url_for(".settings"))

    return render_template(
        "dom_hunter/settings.html",
        enabled=S.is_enabled(g.project),
        canary=S.get_or_make_canary(g.project),
        token=S.get_or_make_token(g.project),
        scope="\n".join(S.get_scope(g.project)),
        auto_inject=set(S.get_auto_inject(g.project)),
        targets=S.AUTO_INJECT_TARGETS,
    )


# ---------------------------------------------------------------------------
# bridge endpoints (token-auth, no CSRF; see web/__init__.py for exemption)
# ---------------------------------------------------------------------------

@bp.route("/__bridge/config", methods=["GET"], strict_slashes=False)
def bridge_config():
    """Extension polls this at install time and on every page load."""
    _check_token()
    canary = S.get_or_make_canary(g.project)
    return jsonify({
        "enabled": S.is_enabled(g.project),
        "canary": canary,
        # The current bridge token. The extension stores this locally on
        # every successful fetch so a token rotation propagates to the
        # running extension within a few seconds (the request that
        # carried the now-previous token is still accepted under the
        # rotation grace window; the response hands back the NEW one).
        "token": S.get_or_make_token(g.project),
        # Per-source tagged canary variants. The agent uses these to
        # stamp a uniquely-identifiable string into each enabled
        # auto-inject source, so source attribution at sink-fire time
        # is provable by exact substring match (no heuristic co-
        # occurrence guessing across sources).
        "tagged_canaries": S.tagged_canaries(canary),
        "scope": S.get_scope(g.project),
        "auto_inject": S.get_auto_inject(g.project),
        "sinks": [s["id"] for s in S.SINKS],
        "ui_url": request.url_root.rstrip("/") + url_for(".index"),
    })


@bp.route("/__bridge/report", methods=["POST"], strict_slashes=False)
def bridge_report():
    """Extension POSTs JSON {kind, ...fields}."""
    _check_token()
    try:
        body = request.get_json(force=True, silent=False) or {}
    except Exception:
        abort(400, description="Invalid JSON.")
    if not isinstance(body, dict):
        abort(400, description="Expected JSON object.")
    kind = (body.get("kind") or "").strip()
    page_url = _truncate(str(body.get("page_url", "")), 2048)
    frame_url = _truncate(str(body.get("frame_url", page_url)), 2048)

    if kind == "finding":
        sink = (body.get("sink") or "").strip()
        if sink not in S.SINK_INDEX:
            sink = "unknown" if sink else ""
            if not sink:
                abort(400, description="Missing sink id.")
        source = (body.get("source") or "unknown").strip() or "unknown"
        # The agent may attribute a sink hit to multiple DOM sources
        # at once (comma-joined in precedence order) when more than
        # one source actually contained the canary that reached the
        # sink. Validate each id independently against SOURCE_INDEX
        # and drop unknowns; if nothing survives, fall back to
        # "unknown".
        parts = [p.strip() for p in source.split(",") if p.strip()]
        parts = [p for p in parts if p in S.SOURCE_INDEX]
        # De-duplicate while preserving precedence order.
        seen_p: set[str] = set()
        deduped = [p for p in parts if not (p in seen_p or seen_p.add(p))]
        source = ",".join(deduped) if deduped else "unknown"
        severity = S.normalise_severity(
            body.get("severity") or S.SINK_INDEX.get(sink, {}).get("severity", "medium")
        )
        canary_seen = bool(body.get("canary_seen", False))
        value = _truncate(str(body.get("value", "")), 4096)
        stack = _truncate(str(body.get("stack", "")), 8192)
        key = S.dedupe_key(
            sink=sink, source=source, page_url=page_url,
            stack=stack, canary_seen=canary_seen,
        )
        fid = g.project.add_dom_hunter_finding(
            page_url=page_url, frame_url=frame_url, sink=sink, source=source,
            severity=severity, canary_seen=canary_seen, value=value,
            stack=stack, dedupe_key=key,
        )
        return jsonify({"ok": True, "id": fid})

    if kind == "message":
        origin = _truncate(str(body.get("origin", "")), 256)
        data = body.get("data", "")
        if not isinstance(data, str):
            try:
                data = json.dumps(data)
            except Exception:
                data = str(data)
        data = _truncate(data, 4096)
        has_canary = bool(body.get("has_canary", False))
        handler_stack = _truncate(str(body.get("handler_stack", "")), 4096)
        mid = g.project.add_dom_hunter_message(
            page_url=page_url, origin=origin, data=data,
            has_canary=has_canary, handler_stack=handler_stack,
        )
        return jsonify({"ok": True, "id": mid})

    abort(400, description=f"Unknown kind: {kind!r}")


@bp.route("/__bridge/findings.json", methods=["GET"], strict_slashes=False)
def bridge_findings_json():
    """Read-only mirror so the extension sidebar can show counts."""
    _check_token()
    limit = min(int(request.args.get("limit", 50) or 50), 200)
    rows = g.project.list_dom_hunter_findings(limit=limit)
    return jsonify({"findings": rows,
                    "total": g.project.dom_hunter_findings_count()})
