"""GraphQL helpers: introspection, schema flattening, query templating."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .engines import Request
from .engines import httpx_engine

INTROSPECTION_QUERY = """\
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description type { kind name ofType { kind name } } defaultValue }
        type { kind name ofType { kind name ofType { kind name } } }
        isDeprecated deprecationReason
      }
      inputFields {
        name description type { kind name ofType { kind name } } defaultValue
      }
      enumValues(includeDeprecated: true) { name description }
    }
  }
}
"""


@dataclass
class SchemaField:
    name: str
    description: str = ""
    args: list[dict] = field(default_factory=list)
    type_str: str = ""
    deprecated: bool = False


@dataclass
class SchemaType:
    kind: str
    name: str
    description: str = ""
    fields: list[SchemaField] = field(default_factory=list)


def _type_to_str(t: dict) -> str:
    """Render a (possibly nested) GraphQL type reference as 'X!' / '[X!]!'."""
    if not t:
        return "?"
    kind = t.get("kind")
    name = t.get("name")
    of = t.get("ofType")
    if kind == "NON_NULL":
        return f"{_type_to_str(of)}!"
    if kind == "LIST":
        return f"[{_type_to_str(of)}]"
    return name or "?"


def parse_schema(introspection_json: dict) -> list[SchemaType]:
    """Flatten introspection JSON into a list of SchemaType for templating."""
    data = introspection_json.get("data") or introspection_json
    schema = data.get("__schema") or {}
    out: list[SchemaType] = []
    for t in schema.get("types") or []:
        if (t.get("name") or "").startswith("__"):
            continue  # skip introspection internals
        fields: list[SchemaField] = []
        for f in t.get("fields") or []:
            args = []
            for a in f.get("args") or []:
                args.append({
                    "name": a.get("name", ""),
                    "type": _type_to_str(a.get("type")),
                    "default": a.get("defaultValue"),
                })
            fields.append(SchemaField(
                name=f.get("name", ""),
                description=f.get("description") or "",
                args=args,
                type_str=_type_to_str(f.get("type")),
                deprecated=bool(f.get("isDeprecated")),
            ))
        out.append(SchemaType(
            kind=t.get("kind", ""), name=t.get("name", ""),
            description=t.get("description") or "", fields=fields,
        ))
    out.sort(key=lambda x: (x.kind != "OBJECT", x.name))
    return out


def introspect(url: str, *, headers: list[tuple[str, str]] | None = None,
                timeout: float = 15.0) -> dict:
    """Send the introspection query. Returns the parsed JSON response."""
    body = json.dumps({"query": INTROSPECTION_QUERY}).encode()
    h = list(headers or [])
    h = [(k, v) for k, v in h if k.lower() != "content-type"]
    h.append(("Content-Type", "application/json"))
    h.append(("Accept", "application/json"))
    req = Request(method="POST", url=url, headers=h, body=body)
    resp = httpx_engine.send(req, timeout=timeout)
    if resp.error:
        return {"error": resp.error, "status": resp.status}
    try:
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError) as exc:
        return {"error": f"non-JSON response: {exc}",
                "status": resp.status,
                "body_preview": resp.body[:400].decode("latin-1", errors="replace")}


def run_query(url: str, query: str, *,
               variables: dict[str, Any] | None = None,
               headers: list[tuple[str, str]] | None = None,
               timeout: float = 15.0) -> dict:
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    body = json.dumps(payload).encode()
    h = list(headers or [])
    h = [(k, v) for k, v in h if k.lower() != "content-type"]
    h.append(("Content-Type", "application/json"))
    h.append(("Accept", "application/json"))
    req = Request(method="POST", url=url, headers=h, body=body)
    resp = httpx_engine.send(req, timeout=timeout)
    if resp.error:
        return {"_error": resp.error, "_status": resp.status}
    try:
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError) as exc:
        return {"_error": f"non-JSON response: {exc}",
                "_status": resp.status,
                "_preview": resp.body[:400].decode("latin-1", errors="replace")}
