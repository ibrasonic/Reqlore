"""Proxy control panel + intercept queue."""
from __future__ import annotations

import json
import re
from pathlib import Path

from flask import (
    Blueprint, abort, flash, g, jsonify, redirect, render_template, request,
    url_for, send_file,
)

from ...proxy.rules import (
    DEFAULT_NOISE_HOST_REGEX, DEFAULT_NOISE_PATH_REGEX, SUPPORTED_METHODS,
    InterceptConfig,
)

bp = Blueprint("proxy", __name__)


# ---------------------------------------------------------------------------
# Send-to dispatch
# ---------------------------------------------------------------------------
#
# Each held request can be copied into one of the other Reqlore tools
# (Repeater, Intruder, Comparer, PoC, JWT, Decoder). The flow itself
# stays held — "Send to" never decides forward/drop; the Action menu
# is deliberately non-destructive.
#
# Mechanism: we materialise the held bytes into the `http_history` table
# as an `intercept-snapshot` row, then redirect to the target tool with
# the `?from_history=<hid>` (or tool-specific) query param. Every target
# already knows how to hydrate itself from a history row.

# Targets the "Send to" menu can dispatch to. Order is the order shown
# in the UI. Each entry also carries a single-letter `accesskey` so the
# button can be activated from anywhere on the page via the browser's
# native access-key modifier (Alt on Chrome/Edge, Alt+Shift on Firefox,
# Ctrl+Alt on macOS). Letters were chosen to be mnemonic, unique across
# the page, and to avoid Alt+D (which focuses the browser address bar).
_SEND_TARGETS: list[tuple[str, str, str]] = [
    # (slug, label, accesskey)
    ("repeater", "Repeater",          "r"),
    ("intruder", "Intruder",          "i"),
    ("comparer", "Comparer (side A)", "m"),
    ("poc",      "PoC builder",       "b"),
    ("jwt",      "JWT workbench",     "j"),
    ("decoder",  "Decoder",           "o"),
    ("auth-matrix", "Auth Matrix",    "x"),
]


def _parse_raw_request(raw: bytes) -> tuple[str, str, str, list[tuple[str, str]], bytes]:
    """Best-effort parse of a raw HTTP request blob.
    Returns (method, path, host, headers, body). Never raises — falls
    back to safe defaults if the blob is mangled.
    """
    sep = raw.find(b"\r\n\r\n")
    head = raw[:sep] if sep >= 0 else raw
    body = raw[sep + 4:] if sep >= 0 else b""
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    rl = lines[0].split(" ", 2) if lines else []
    method = rl[0] if rl else "GET"
    path = rl[1] if len(rl) > 1 else "/"
    host = ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            headers.append((k, v))
            if k.lower() == "host":
                host = v
    return method, path, host, headers, body


def _bearer_token(headers: list[tuple[str, str]]) -> str:
    """Return the JWT-looking string from any Authorization: Bearer
    header, or '' if none / not JWT-shaped."""
    for k, v in headers:
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            tok = v.split(" ", 1)[1].strip()
            if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", tok):
                return tok
    return ""


def _snapshot_intercept_to_history(item) -> int:
    """Copy a held intercept's raw bytes into `http_history` so the
    other tools (which all key off a history id) can hydrate from it.
    Engine is tagged `intercept-snapshot` for traceability.
    """
    raw = item.req_blob
    method, path, host, _, _ = _parse_raw_request(raw)
    url = f"http://{host}{path}" if host else path
    return g.project.add_history(
        host=host, method=method, url=url, status=0, duration_ms=0,
        engine="intercept-snapshot",
        raw_req=raw, raw_resp=b"",
        flags="", tags=f"intercept:{item.id}",
    )


def _plugin_apps_available() -> bool:
    """``True`` if at least one enabled plugin app is registered.

    Lazy import: the plugins package pulls in optional engine imports
    and we don't want to load it on every proxy request when the
    operator never opens an intercept.
    """
    try:
        from ...plugins import get_registry
        return bool(get_registry().active_plugin_apps())
    except Exception:
        return False


def _underline_first(text: str, ch: str) -> str:
    """Wrap the first case-insensitive occurrence of ``ch`` in ``text``
    in <u>…</u>. Used to visually mark the access-key letter in a
    button label, matching how desktop menus show their mnemonics.
    Returns Markup-safe HTML; falls back to plain text if no match.
    """
    i = text.lower().find(ch.lower())
    if i < 0:
        return text
    return f"{text[:i]}<u>{text[i]}</u>{text[i + 1:]}"


def _available_targets(item) -> list[dict]:
    """Build the menu list for an intercept-detail page.
    Filters out targets that wouldn't have anything useful to do (e.g.
    JWT only appears when an Authorization: Bearer header is present,
    Decoder only when there's a body to decode).
    """
    raw = item.req_blob
    _, _, _, headers, body = _parse_raw_request(raw)
    bearer = _bearer_token(headers)
    out: list[dict] = []
    for slug, label, key in _SEND_TARGETS:
        if slug == "jwt" and not bearer:
            continue
        if slug == "decoder" and not body:
            continue
        out.append({
            "slug": slug,
            "label": label,
            "key": key,
            "html": _underline_first(f"Send to {label}", key),
        })
    return out


def _send_redirect(item, slug: str):
    """Dispatch a held item to a tool. Materialises a history snapshot
    first (so the tool gets a stable hid) and then redirects.
    Returns a Flask response. The held flow is left untouched.
    """
    raw = item.req_blob
    _, _, _, headers, _ = _parse_raw_request(raw)
    hid = _snapshot_intercept_to_history(item)
    if slug == "repeater":
        target = url_for("repeater.index", from_history=hid)
    elif slug == "intruder":
        target = url_for("intruder.new", from_history=hid)
    elif slug == "comparer":
        target = url_for("comparer.index", from_a=hid)
    elif slug == "poc":
        target = url_for("poc.index", from_history=hid)
    elif slug == "jwt":
        target = url_for("jwt.index", token=_bearer_token(headers))
    elif slug == "decoder":
        # Decoder operates on text; send the body decoded best-effort.
        _, _, _, _, body = _parse_raw_request(raw)
        target = url_for("decoder.index",
                         text=body.decode("utf-8", errors="replace"))
    elif slug == "plugin-app":
        target = url_for("plugins.send_to_chooser", from_history=hid)
    elif slug == "auth-matrix":
        target = url_for("auth_matrix.from_history", hid=hid)
    else:
        abort(404, description=f"Unknown send target: {slug!r}")
    label = next((t[1] for t in _SEND_TARGETS if t[0] == slug), slug)
    if slug == "plugin-app":
        label = "plugin app chooser"
    flash(f"Sent intercept #{item.id} to {label} (history #{hid}). "
          f"Flow is still held \u2014 Forward or Drop when ready.", "ok")
    return redirect(target)


def _parse_queue_filters() -> dict:
    """Parse the held-queue filter querystring into a dict shared by the
    index view and the live-refresh count endpoint."""
    f_methods = {m.upper() for m in request.args.getlist("method") if m}
    f_kinds = {k.lower() for k in request.args.getlist("kind") if k}
    f_host_raw = request.args.get("host", "").strip()
    f_host_mode = request.args.get("host_mode", "contains").strip().lower()
    if f_host_mode not in ("exact", "contains"):
        f_host_mode = "contains"
    f_q_raw = request.args.get("q", "").strip()
    f_q_regex = request.args.get("q_re") == "1"
    f_q_re = None
    if f_q_raw and f_q_regex:
        try:
            f_q_re = re.compile(f_q_raw, re.IGNORECASE)
        except re.error:
            # Bad regex falls back to substring search rather than
            # 400-ing \u2014 the URL is the user's UI, degrade gracefully.
            f_q_re = None
            f_q_regex = False
    return {
        "methods": f_methods,
        "kinds": f_kinds,
        "host_raw": f_host_raw,
        "host_mode": f_host_mode,
        "q_raw": f_q_raw,
        "q_regex": f_q_regex,
        "q_re": f_q_re,
    }


def _filter_pending_for_count(pending: list, f: dict) -> list[dict]:
    """Lean enrichment + filtering used by ``/intercept/count``.

    Returns a list of ``{"id": int, "kind": str}`` dicts (only the
    fields the count endpoint actually inspects) so we skip the more
    expensive ``send_targets`` lookup the table view does.
    """
    out: list[dict] = []
    for it in pending:
        method, path, host, _hdrs, _body = _parse_raw_request(it.req_blob)
        url = f"{host}{path}" if host else (path or "/")
        if f["methods"] and method.upper() not in f["methods"]:
            continue
        if f["kinds"] and it.kind.lower() not in f["kinds"]:
            continue
        if f["host_raw"]:
            hl = (host or "").lower()
            needle = f["host_raw"].lower()
            if f["host_mode"] == "exact":
                if hl != needle:
                    continue
            else:
                if needle not in hl:
                    continue
        if f["q_raw"]:
            if f["q_re"] is not None:
                if not f["q_re"].search(url):
                    continue
            else:
                if f["q_raw"].lower() not in url.lower():
                    continue
        out.append({"id": it.id, "kind": it.kind})
    return out


@bp.route("/")
def index():
    items = g.project.list_intercept()
    # Filter to only pending (decision IS NULL) for the queue view
    pending = [i for i in items if g.project.get_intercept_decision(i.id)[0] is None]

    # ------------------------------------------------------------------
    # Per-column filtering, matching the History page's UX so the
    # operator can narrow the queue when intercept holds dozens of
    # requests during real browsing. Column-header click-to-filter is
    # rendered by the shared hist_th_filter macro.
    # ------------------------------------------------------------------
    filters = _parse_queue_filters()
    f_methods = filters["methods"]
    f_kinds = filters["kinds"]
    f_host_raw = filters["host_raw"]
    f_host_mode = filters["host_mode"]
    f_q_raw = filters["q_raw"]
    f_q_regex = filters["q_regex"]
    f_q_re = filters["q_re"]

    enriched: list[dict] = []
    for it in pending:
        method, path, host, _hdrs, _body = _parse_raw_request(it.req_blob)
        url = f"{host}{path}" if host else (path or "/")
        enriched.append({
            "id": it.id,
            "kind": it.kind,
            "method": method,
            "host": host,
            "path": path,
            "url": url,
            "hold_reason": it.hold_reason,
            "created_at": it.created_at,
            "parent_intercept_id": it.parent_intercept_id,
            "send_targets": _available_targets(it),
        })

    def _keep(row: dict) -> bool:
        if f_methods and row["method"].upper() not in f_methods:
            return False
        if f_kinds and row["kind"].lower() not in f_kinds:
            return False
        if f_host_raw:
            hl = (row["host"] or "").lower()
            needle = f_host_raw.lower()
            if f_host_mode == "exact":
                if hl != needle:
                    return False
            else:
                if needle not in hl:
                    return False
        if f_q_raw:
            url = row["url"] or ""
            if f_q_re is not None:
                if not f_q_re.search(url):
                    return False
            else:
                if f_q_raw.lower() not in url.lower():
                    return False
        return True

    filtered = [r for r in enriched if _keep(r)]
    any_filter = bool(f_methods or f_kinds or f_host_raw or f_q_raw)
    # Highest pending-and-matching id, used by the live-refresh widget's
    # `data-since` cursor so the next poll only counts arrivals newer
    # than what the user already has on screen.
    max_id = max((r["id"] for r in filtered), default=0)

    # `get_intercept_config` is missing on test stubs and older injected
    # proxies; fall back to defaults so the panel still renders.
    cfg = InterceptConfig()
    if g.proxy is not None:
        getter = getattr(g.proxy, "get_intercept_config", None)
        if callable(getter):
            cfg = getter()
    return render_template("proxy/index.html",
                           items=filtered,
                           total_items=len(enriched),
                           any_filter=any_filter,
                           max_id=max_id,
                           filters={
                               "methods": sorted(f_methods),
                               "kinds": sorted(f_kinds),
                               "host": f_host_raw or None,
                               "host_mode": f_host_mode,
                               "q": f_q_raw or None,
                               "q_regex": f_q_regex,
                           },
                           intercept_cfg=cfg,
                           supported_methods=SUPPORTED_METHODS)


def _next_pending_id() -> int | None:
    """Lowest-id intercept that has not yet been decided, or ``None``.

    Used by the auto-advance flow after a Forward/Drop decision so the
    operator lands on the next held request directly instead of going
    back to the queue page and clicking the next row.
    """
    for it in g.project.list_intercept():
        if g.project.get_intercept_decision(it.id)[0] is None:
            return it.id
    return None


def _after_decision_redirect():
    """Where to send the user after they Forward / Drop an intercept.

    If another request is currently held, jump straight to its detail
    page (one round-trip per decision instead of the old two). When the
    queue is empty fall back to ``/proxy/`` so the operator sees the
    "no intercepts held" landing state.
    """
    nxt = _next_pending_id()
    if nxt is None:
        return redirect(url_for(".index"))
    return redirect(url_for(".show_intercept", iid=nxt))


@bp.route("/intercept/next")
def next_intercept():
    """Go to the oldest still-pending intercept, or back to the queue.

    Bookmarkable shortcut for "open whatever is held right now". When
    nothing is pending it just renders the queue page.
    """
    return _after_decision_redirect()


@bp.route("/intercept/count")
def intercept_count():
    """Live-refresh poll endpoint.

    Honours the same per-column queue filters as the index view
    (``method`` / ``kind`` / ``host`` / ``host_mode`` / ``q`` / ``q_re``)
    so the count reflects what the operator is actually looking at — a
    filter to ``kind=response`` won't surprise-reload the page when an
    unrelated request-side hold arrives.

    ``since`` (default ``0``) is the highest intercept id the client
    already has on screen; ``new`` counts only matching pending items
    with ``id > since`` and is what the JS uses to decide whether to
    paint the "N new — Refresh now" affordance / schedule an opt-in
    auto-reload.

    Response shape::

        {"count":  <total matching pending now>,
         "new":    <matching pending with id > since>,
         "max_id": <highest matching pending id, 0 if empty>,
         "since":  <echoed input>}

    ``count`` is retained for backward compatibility with older callers
    that only need the queue size.
    """
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        since = 0
    items = g.project.list_intercept()
    pending = [i for i in items
               if g.project.get_intercept_decision(i.id)[0] is None]
    enriched = _filter_pending_for_count(pending, _parse_queue_filters())
    new_count = sum(1 for r in enriched if r["id"] > since)
    max_id = max((r["id"] for r in enriched), default=0)
    return jsonify({
        "count": len(enriched),
        "new": new_count,
        "max_id": max_id,
        "since": since,
    })


@bp.route("/start", methods=["POST"])
def start():
    if not g.proxy:
        abort(503, description="Proxy controller not configured.")
    g.proxy.start()
    return redirect(url_for(".index"))


@bp.route("/stop", methods=["POST"])
def stop():
    if not g.proxy:
        abort(503, description="Proxy controller not configured.")
    g.proxy.stop()
    return redirect(url_for(".index"))


@bp.route("/intercept/toggle", methods=["POST"])
def toggle_intercept():
    """Global intercept on/off. Persists across restarts.
    When the form was submitted from the checkbox (hidden `from=checkbox`),
    the absence of the `on` field means unchecked → OFF. Otherwise
    (legacy / external callers), simply flip the current state.
    """
    if not g.proxy:
        abort(503, description="Proxy controller not configured.")
    if request.form.get("from") == "checkbox":
        on = request.form.get("on") == "1"
    else:
        on = g.project.get_state("intercept_on", "0") != "1"
    g.proxy.set_intercept(on)
    g.project.set_state("intercept_on", "1" if on else "0")
    flash(f"Intercept {'ON' if on else 'OFF'}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/intercept/config", methods=["POST"])
def set_intercept_config():
    """Update the filter that decides which requests get held when
    intercept is ON. Methods come in as repeated form fields; the
    regexes are plain strings; the noise checkbox is a single bool.
    Stays effective immediately and persists across restarts.
    """
    if not g.proxy:
        abort(503, description="Proxy controller not configured.")
    methods = [m for m in request.form.getlist("method")
               if m in SUPPORTED_METHODS]
    host_regex = request.form.get("host_regex", "").strip()
    path_regex = request.form.get("path_regex", "").strip()
    exclude_host_regex = (request.form.get(
        "exclude_host_regex", "").strip() or DEFAULT_NOISE_HOST_REGEX)
    exclude_path_regex = (request.form.get(
        "exclude_path_regex", "").strip() or DEFAULT_NOISE_PATH_REGEX)
    restrict_to_scope = request.form.get("restrict_to_scope") == "1"
    # L-12: validate every operator-supplied regex at save time.
    # Falling through to the runtime would only suppress the bad
    # pattern silently (safe_search returns None on regex.error), so
    # the user would never know their filter was inert.
    from ... import _safe_regex
    for label, pat in (("host_regex", host_regex),
                        ("path_regex", path_regex),
                        ("exclude_host_regex", exclude_host_regex),
                        ("exclude_path_regex", exclude_path_regex)):
        if pat and not _safe_regex.is_valid_pattern(pat):
            flash(f"{label} is not a valid regular expression.", "err")
            return redirect(url_for(".index"))
    # M-14: warn on un-anchored host filter (non-blocking).
    if host_regex and not (host_regex.startswith("^") or "$" in host_regex):
        flash(
            "Heads up: host filter is not anchored. Add ^ at the start "
            "and $ at the end to avoid matching attacker-controlled "
            "subdomains like evil-example.com.attacker.tld.",
            "warn",
        )
    cfg = InterceptConfig(
        methods=methods,
        host_regex=host_regex,
        path_regex=path_regex,
        exclude_host_regex=exclude_host_regex,
        exclude_path_regex=exclude_path_regex,
        restrict_to_scope=restrict_to_scope,
    )
    g.proxy.set_intercept_config(cfg)
    g.project.set_state("intercept_config", json.dumps(cfg.to_dict()))
    flash("Intercept filter updated.", "ok")
    return redirect(url_for(".index"))


@bp.route("/intercept/<int:iid>")
def show_intercept(iid: int):
    item = g.project.get_intercept(iid)
    if item is None:
        abort(404)
    body_text = _safe_text(item.req_blob)
    # Server-side find — the editable textarea cannot be searched with
    # browser Ctrl+F, so this is the only AAA-clean way to point a
    # screen-reader user at a token inside a long held request.
    from ...a11y import build_find_context
    find_body = build_find_context(
        body_text, prefix="body",
        q=request.args.get("body_find", ""),
        regex=request.args.get("body_re") == "1",
        region_label="held request",
        action=url_for("proxy.show_intercept", iid=iid),
    )
    return render_template("proxy/intercept_detail.html", item=item,
                           body_text=body_text,
                           find_body=find_body,
                           send_targets=_available_targets(item),
                           plugin_apps_available=_plugin_apps_available())


@bp.route("/intercept/<int:iid>/drop", methods=["POST"])
def drop_intercept(iid: int):
    g.project.decide_intercept(iid, "drop")
    flash("Intercept dropped.", "ok")
    return _after_decision_redirect()


@bp.route("/intercept/<int:iid>/forward", methods=["POST"])
def forward_intercept(iid: int):
    g.project.decide_intercept(iid, "forward")
    flash("Intercept forwarded.", "ok")
    return _after_decision_redirect()


@bp.route("/intercept/forward_all", methods=["POST"])
def forward_all():
    """Forward every currently-pending intercept as-is. Handy when the
    queue piled up while you were away, or you've finished testing one
    flow and just want everything else to fly through.
    """
    n = 0
    for it in g.project.list_intercept():
        decision, _ = g.project.get_intercept_decision(it.id)
        if decision is None:
            g.project.decide_intercept(it.id, "forward")
            n += 1
    flash(f"Forwarded {n} held item{'s' if n != 1 else ''}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/intercept/drop_all", methods=["POST"])
def drop_all():
    """Drop every currently-pending intercept. Use when the queue has
    irrelevant traffic you don't want to deal with one at a time.
    """
    n = 0
    for it in g.project.list_intercept():
        decision, _ = g.project.get_intercept_decision(it.id)
        if decision is None:
            g.project.decide_intercept(it.id, "drop")
            n += 1
    flash(f"Dropped {n} held item{'s' if n != 1 else ''}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/intercept/<int:iid>/send/<slug>", methods=["POST"])
def send_to(iid: int, slug: str):
    """Copy a held request into the named tool and redirect there.
    The intercepted flow stays in the queue — the operator still has
    to Forward or Drop it explicitly. The Action menu is non-destructive.
    """
    item = g.project.get_intercept(iid)
    if item is None:
        abort(404)
    return _send_redirect(item, slug)


@bp.route("/intercept/send_all/repeater", methods=["POST"])
def send_all_to_repeater():
    """Bulk-copy every pending held request into history snapshots so
    they all become available in Repeater for replay. Flows stay held.
    """
    last_hid = 0
    n = 0
    for it in g.project.list_intercept():
        decision, _ = g.project.get_intercept_decision(it.id)
        if decision is None:
            last_hid = _snapshot_intercept_to_history(it)
            n += 1
    if n == 0:
        flash("No pending intercepts to send.", "warn")
        return redirect(url_for(".index"))
    flash(f"Sent {n} held item{'s' if n != 1 else ''} to Repeater "
          f"(latest history #{last_hid}). Flows are still held.", "ok")
    # Land the operator in Repeater on the most recent snapshot so they
    # can start replaying immediately; History view has the rest.
    return redirect(url_for("repeater.index", from_history=last_hid))


@bp.route("/intercept/<int:iid>/forward_edited", methods=["POST"])
def forward_edited(iid: int):
    raw = request.form.get("raw", "")
    g.project.decide_intercept(iid, "forward_edited", raw.encode("utf-8", errors="replace"))
    flash("Edited intercept forwarded.", "ok")
    return _after_decision_redirect()


@bp.route("/ca")
def ca_download():
    cert = Path(g.settings.ca_dir) / "reqlore-ca.pem"
    if not cert.exists():
        abort(404, description="No CA generated yet. Start the proxy once.")
    return send_file(cert, mimetype="application/x-pem-file",
                     as_attachment=True, download_name="reqlore-ca.pem")


def _safe_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")
