"""
Echo Plugin App — minimal `PLUGIN_APP` example.

Drop into `~/.reqlore/plugins/echo_app.py`, click **Reload plugins**,
then open `/plugins/app/echo-app/`.

Demonstrates:
  - `sdk.make_info` + `sdk.make_app`
  - every settings-field type (`StrField`, `SelectField`,
    `IntField`, `BoolField`, `TextField`)
  - `PLUGIN_APP.runner` decorator
  - PluginContext: `settings`, `scope`, `seed_request`,
    `log`, `progress`, `sleep`, `check_stop`, `add_result`,
    `record_finding`, `send`

See docs/PLUGINS.md for the full reference.
"""

from reqlore import plugins_sdk as sdk

PLUGIN_INFO = sdk.make_info(
    name="echo-app",
    version="0.1",
    description="Send one request per URL and record the response status.",
    author="reqlore-examples",
)

PLUGIN_APP = sdk.make_app(
    slug="echo-app",
    name="Echo App",
    description="Tiny Plugin App template — one request per URL.",
    fields=[
        sdk.TextField(
            "urls",
            rows=6,
            required=True,
            label="Target URLs",
            placeholder="https://app.example.com/\nhttps://app.example.com/health",
            help="One absolute URL per line.",
        ),
        sdk.SelectField(
            "method",
            choices=["GET", "HEAD", "OPTIONS"],
            default="GET",
            label="HTTP method",
        ),
        sdk.IntField(
            "delay_ms",
            default=0,
            min=0,
            max=10_000,
            label="Delay between requests (ms)",
            help="Use a non-zero value to be polite to fragile targets.",
        ),
        sdk.BoolField(
            "follow_redirects",
            default=True,
            label="Follow redirects",
        ),
        sdk.StrField(
            "header_auth",
            label="Authorization header (optional)",
            placeholder="Bearer eyJ...",
        ),
    ],
    columns=["url", "status", "length", "note"],
    timeout_s=120,
    tags=["example", "recon"],
    category="example",
)


@PLUGIN_APP.runner
def run(ctx):  # noqa: D401
    urls = [u.strip() for u in ctx.settings["urls"].splitlines() if u.strip()]
    method = ctx.settings["method"]
    delay = float(ctx.settings["delay_ms"]) / 1000.0
    follow = ctx.settings["follow_redirects"]
    auth = ctx.settings.get("header_auth") or ""

    # Pre-fill from Send-to-plugin if the form's `urls` was left empty.
    seed = ctx.seed_request
    if seed is not None and not urls:
        urls = [seed.url]
        ctx.log(f"seeded from history#{seed.history_id} {seed.method} {seed.url}")

    if not urls:
        ctx.log("no URLs to send — aborting", "error")
        return

    headers = [("Authorization", auth)] if auth else []

    total = len(urls)
    ctx.progress(0, total, "starting")

    for i, url in enumerate(urls, start=1):
        ctx.check_stop()

        if not ctx.scope.empty and not ctx.scope.is_url_in_scope(url):
            ctx.add_result({"url": url, "status": "-", "length": 0,
                            "note": "out of scope"})
            ctx.log(f"skip out-of-scope {url}", "warn")
            ctx.progress(i, total, f"{i}/{total}")
            continue

        ctx.log(f"sending {method} {url}", "info")
        resp = ctx.send(
            method, url,
            headers=headers,
            engine="httpx",
            timeout=15.0,
            follow_redirects=follow,
        )

        body_len = len(resp.body or b"")
        note = resp.error or ""
        ctx.add_result({
            "url": url,
            "status": resp.status,
            "length": body_len,
            "note": note,
        })

        # Example finding: surface 5xx as info-severity for triage.
        if 500 <= resp.status < 600:
            ctx.record_finding(
                title="Echo App: server error",
                severity="info",
                host=(url.split("/")[2] if "://" in url else ""),
                url=url,
                evidence=f"HTTP {resp.status} from a single {method}",
                description=(
                    "The target returned a 5xx response to a single "
                    "well-formed request. May indicate an unhandled "
                    "exception path worth investigating."
                ),
                confidence="tentative",
            )

        ctx.progress(i, total, f"{i}/{total}")
        if delay > 0 and i < total:
            if not ctx.sleep(delay):
                return  # stopped by the operator

    ctx.log(f"done: {total} URL(s) sent", "info")
