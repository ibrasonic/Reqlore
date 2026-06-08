"""GraphQL workbench: introspect, browse schema, run queries."""
from __future__ import annotations

import json

from flask import Blueprint, flash, g, render_template, request

from ...graphql import introspect, parse_schema, run_query

bp = Blueprint("graphql", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    url = (request.form.get("url") or request.args.get("url") or "").strip()
    headers_text = request.form.get("headers", "")
    query_text = request.form.get("query", "")
    vars_text = request.form.get("vars", "")
    action = request.form.get("action", "")
    schema_types = None
    raw_response = None
    raw_introspection = None

    parsed_headers = _parse_headers(headers_text)

    if request.method == "POST" and url:
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

    return render_template(
        "graphql/index.html",
        url=url, headers_text=headers_text, query_text=query_text,
        vars_text=vars_text, schema_types=schema_types,
        raw_response=json.dumps(raw_response, indent=2) if raw_response else "",
        raw_introspection=(json.dumps(raw_introspection, indent=2)
                            if raw_introspection else ""),
    )


def _parse_headers(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out
