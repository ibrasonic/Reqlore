"""Example: add a 'PHP curl' renderer alongside the built-in copy-as menu.

Only consumed by hosts that look up ``copy_as()`` (UI in Phase 6+) — the
plugin loader will not crash if the host doesn't yet wire this up.
"""
from reqlore.plugins_sdk import CopyAsHandler, make_info

PLUGIN_INFO = make_info(
    name="copy-as-php",
    version="1.0",
    description="Adds a PHP curl renderer to the copy-as menu.",
)


def _render_php(raw_req: bytes) -> str:
    """Turn raw HTTP/1.1 bytes into a tiny PHP curl snippet."""
    head, _, body = raw_req.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    if not lines:
        return "// empty request"
    request_line = lines[0]
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    parts = request_line.split(" ", 2)
    method = parts[0] if parts else "GET"
    url = parts[1] if len(parts) > 1 else "/"
    php_headers = ",\n    ".join(f"'{k}: {v}'" for k, v in headers)
    body_literal = body.decode("latin-1").replace("'", "\\'")
    return (
        "<?php\n"
        "$ch = curl_init();\n"
        f"curl_setopt($ch, CURLOPT_URL, '{url}');\n"
        f"curl_setopt($ch, CURLOPT_CUSTOMREQUEST, '{method}');\n"
        "curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n"
        f"curl_setopt($ch, CURLOPT_HTTPHEADER, [\n    {php_headers}\n]);\n"
        + (f"curl_setopt($ch, CURLOPT_POSTFIELDS, '{body_literal}');\n" if body else "")
        + "$response = curl_exec($ch);\n"
        "curl_close($ch);\n"
    )


def copy_as():
    return [CopyAsHandler(name="PHP curl", render=_render_php)]
