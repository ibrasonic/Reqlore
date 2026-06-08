"""Opt-in update check.

Off by default. When the user enables it in /settings we fetch a single JSON
manifest URL once per UI session and compare ``latest_version`` against
:py:data:`reqlore.__version__`. No telemetry, no automatic downloads, and the
request is made through the standard library ``urllib`` with a 4-second
timeout so it never blocks startup.

Manifest format::

    {"latest_version": "0.2.0", "released": "2026-07-01",
     "url": "https://example.org/reqlore/0.2.0/"}
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

from . import __version__

DEFAULT_MANIFEST_URL = "https://reqlore.invalid/manifest.json"
USER_AGENT = f"reqlore/{__version__} (+update-check)"


@dataclass
class UpdateInfo:
    enabled: bool
    current_version: str
    latest_version: str | None = None
    released: str | None = None
    url: str | None = None
    update_available: bool = False
    error: str | None = None


def _parse_version(s: str) -> tuple[int, ...]:
    out = []
    for part in (s or "").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def check(manifest_url: str = DEFAULT_MANIFEST_URL, *,
          timeout_s: float = 4.0) -> UpdateInfo:
    """Fetch the manifest and return an :class:`UpdateInfo`. Never raises."""
    info = UpdateInfo(enabled=True, current_version=__version__)
    try:
        req = urllib.request.Request(manifest_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            raw = resp.read(64_000)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        info.latest_version = data.get("latest_version")
        info.released = data.get("released")
        info.url = data.get("url")
        if info.latest_version:
            info.update_available = (_parse_version(info.latest_version)
                                      > _parse_version(__version__))
    except Exception as exc:
        info.error = f"{type(exc).__name__}: {exc}"
    return info
