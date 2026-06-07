"""Example: add an extra passive rule that flags missing 'Server-Timing'."""
from weblore.plugins_sdk import make_info, make_passive_rule
from weblore.scanner.findings import Finding

PLUGIN_INFO = make_info(
    name="extra-headers",
    version="1.0",
    description="Adds a passive rule for the Server-Timing header.",
    author="Weblore examples",
)


@make_passive_rule("missing-server-timing", severity="info")
def _server_timing(ctx):
    for k, _ in ctx.resp_headers:
        if k.lower() == "server-timing":
            return
    yield Finding(
        severity="info",
        title="No Server-Timing header",
        host=ctx.host,
        url=ctx.url,
        description=("The response does not advertise Server-Timing metrics. "
                      "This is informational; some teams require it as a "
                      "performance/observability baseline."),
    )


def scanner_rules():
    return [_server_timing]
