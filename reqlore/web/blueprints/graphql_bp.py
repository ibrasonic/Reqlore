"""GraphQL workbench: introspect, browse schema, run queries."""
from __future__ import annotations

import json

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ...graphql import introspect, parse_schema, run_query
from .._prg import PRGCache

bp = Blueprint("graphql", __name__)

_cache = PRGCache()


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        headers_text = request.form.get("headers", "")
        query_text = request.form.get("query", "")
        vars_text = request.form.get("vars", "")
        action = request.form.get("action", "")
        parsed_headers = _parse_headers(headers_text)
        schema_types = None
        raw_response = None
        raw_introspection = None

        if url:
            if action == "introspect":
                raw_introspection = introspect(url, headers=parsed_headers)
                if "error" in raw_introspection:
                    flash(f"Introspection failed: {raw_introspection['error']}", "err")
                else:
                    try:
                        schema_types = parse_schema(raw_introspection)
                        flash(f"Schema loaded: {len(schema_types)} types.", "ok")
                    except Exception as exc:
                        flash(f"Could not parse schema: {exc}", "err")
            elif action == "run":
                variables = None
                if vars_text.strip():
                    try:
                        variables = json.loads(vars_text)
                    except json.JSONDecodeError as exc:
                        flash(f"Variables JSON is invalid: {exc}", "err")
                        variables = None
                raw_response = run_query(url, query_text, variables=variables,
                                          headers=parsed_headers)

        token = _cache.put({
            "url": url, "headers_text": headers_text,
            "query_text": query_text, "vars_text": vars_text,
            "schema_types": schema_types,
            "raw_response": (json.dumps(raw_response, indent=2)
                              if raw_response else ""),
            "raw_introspection": (json.dumps(raw_introspection, indent=2)
                                   if raw_introspection else ""),
        })
        return redirect(url_for(".index", t=token))

    stashed = _cache.get(request.args.get("t")) or {}
    return render_template(
        "graphql/index.html",
        url=stashed.get("url") or request.args.get("url", "").strip(),
        headers_text=stashed.get("headers_text", ""),
        query_text=stashed.get("query_text", ""),
        vars_text=stashed.get("vars_text", ""),
        schema_types=stashed.get("schema_types"),
        raw_response=stashed.get("raw_response", ""),
        raw_introspection=stashed.get("raw_introspection", ""),
    )


def _parse_headers(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out
