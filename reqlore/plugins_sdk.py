"""Plugin authoring SDK — typed builders used by example plugins.

A plugin file is a plain ``.py`` module. To register code you only need
to expose a module-level ``PLUGIN_INFO`` dict and optionally one or more
of these entry points:

* ``scanner_rules() -> list[callable]`` — passive rules
* ``register(app)``                     — Flask hook / blueprint
* ``copy_as() -> list[CopyAsHandler]``  — extra "copy-as" renderers

This module provides:

* :func:`make_info`                  build a valid ``PLUGIN_INFO`` dict
* :func:`make_passive_rule`          decorator/wrapper for a rule fn
* :class:`CopyAsHandler`             dataclass for new copy-as helpers
* :func:`assert_compatible`          static check used at load time
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .scanner.findings import Finding, Severity   # noqa: F401 - re-export for SDK users
from .scanner.passive import RuleContext           # noqa: F401 - re-export


SDK_VERSION = "1.0"


def make_info(*, name: str, version: str = "0.1",
              description: str = "",
              author: str = "",
              homepage: str = "",
              min_reqlore: str = "0.1") -> dict[str, Any]:
    """Build a well-formed ``PLUGIN_INFO`` dict."""
    return {
        "name": name,
        "version": version,
        "description": description,
        "author": author,
        "homepage": homepage,
        "min_reqlore": min_reqlore,
        "sdk_version": SDK_VERSION,
    }


def make_passive_rule(name: str, *, severity: str = "info") -> Callable:
    """Decorator: tag a ``(ctx) -> Iterable[Finding]`` function with a name.

    Example::

        @make_passive_rule("missing-server-timing", severity="info")
        def rule(ctx):
            if not ctx.resp.header("server-timing"):
                yield Finding(severity="info",
                              title="No Server-Timing header",
                              host=ctx.host, url=ctx.url)
    """
    def deco(fn: Callable) -> Callable:
        fn.reqlore_rule_name = name              # type: ignore[attr-defined]
        fn.reqlore_rule_severity = severity      # type: ignore[attr-defined]
        return fn
    return deco


@dataclass
class CopyAsHandler:
    name: str                            # menu label (e.g. "PHP curl")
    render: Callable[[bytes], str]       # bytes (raw req) -> printable text


def assert_compatible(info: dict[str, Any]) -> None:
    """Validate a ``PLUGIN_INFO`` dict. Raise ``ValueError`` on mismatch."""
    if not isinstance(info, dict):
        raise ValueError("PLUGIN_INFO must be a dict")
    if "name" not in info or not str(info["name"]).strip():
        raise ValueError("PLUGIN_INFO['name'] is required")
    sdk = str(info.get("sdk_version", SDK_VERSION))
    major = sdk.split(".")[0]
    if major != SDK_VERSION.split(".")[0]:
        raise ValueError(
            f"plugin built against SDK {sdk}, host SDK is {SDK_VERSION}")
