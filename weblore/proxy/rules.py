"""Intercept rules engine. Pure data; no I/O."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# Default exclude regex: Firefox / Mozilla background traffic (telemetry,
# safe-browsing, push, addon updates, captive-portal probes, etc.) plus
# the common asset extensions a normal HTML page pulls in. Without this,
# turning intercept ON during a Firefox session buries the operator under
# hundreds of held requests that have nothing to do with the target.
DEFAULT_NOISE_HOST_REGEX = (
    r"(^|\.)("
    r"mozilla\.(com|net|org)"
    r"|mozilla\.cloudflare-dns\.com"
    r"|firefox\.com"
    r"|services\.mozilla\.com"
    r"|telemetry\.mozilla\.org"
    r"|tracking-protection\.cdn\.mozilla\.net"
    r"|push\.services\.mozilla\.com"
    r"|content-signature-2\.cdn\.mozilla\.net"
    r"|safebrowsing\.googleapis\.com"
    r"|detectportal\.firefox\.com"
    r")$"
)

DEFAULT_NOISE_PATH_REGEX = (
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|eot|"
    r"mp3|mp4|webm|ogg|wasm)(?:\?.*)?$"
)


@dataclass
class Rule:
    enabled: bool = True
    host_regex: str | None = None
    method_in: list[str] | None = None
    path_regex: str | None = None
    # When set, requests whose host matches this pattern are NEVER held,
    # even if every other field matches. Useful for blanket-excluding
    # Firefox/Mozilla background traffic.
    exclude_host_regex: str | None = None
    # When set, requests whose path matches this pattern are NEVER held.
    # Useful for blanket-excluding asset files (.css/.js/.png/...).
    exclude_path_regex: str | None = None
    status_in: list[int] | None = None
    content_type_regex: str | None = None

    def matches_request(self, host: str, method: str, path: str = "") -> bool:
        if not self.enabled:
            return False
        if self.exclude_host_regex and re.search(
                self.exclude_host_regex, host or ""):
            return False
        if self.exclude_path_regex and re.search(
                self.exclude_path_regex, path or ""):
            return False
        if self.host_regex and not re.search(self.host_regex, host or ""):
            return False
        if self.method_in and method.upper() not in (
                m.upper() for m in self.method_in):
            return False
        if self.path_regex and not re.search(self.path_regex, path or ""):
            return False
        return True

    def matches_response(self, status: int, content_type: str) -> bool:
        if not self.enabled:
            return False
        # A rule with no response criteria is request-only — never hold
        # the response. Without this guard, a plain "hold POSTs" rule
        # would also hold every single response that flows through,
        # including the Weblore UI's own redirects, which loops forever.
        if self.status_in is None and not self.content_type_regex:
            return False
        if self.status_in is not None and status not in self.status_in:
            return False
        if self.content_type_regex and not re.search(
                self.content_type_regex, content_type or ""):
            return False
        return True


def should_hold_request(rules: Iterable[Rule], host: str, method: str,
                        path: str = "") -> bool:
    return any(r.matches_request(host, method, path) for r in rules)


def should_hold_response(rules: Iterable[Rule], status: int,
                         content_type: str) -> bool:
    return any(r.matches_response(status, content_type) for r in rules)


# ---------------------------------------------------------------------------
# Intercept configuration (persisted as JSON in project_state)
# ---------------------------------------------------------------------------

# All HTTP methods exposed in the UI's checkbox list. Order matters: this
# is the order they render in.
SUPPORTED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE",
                     "HEAD", "OPTIONS")


@dataclass
class InterceptConfig:
    """User-tunable filter for the Burp-style intercept toggle.

    Sensible defaults: hold POST/PUT/PATCH/DELETE only (state-changing
    requests), on any host. Browser background traffic (Mozilla /
    Firefox telemetry, safe-browsing, push) and static asset extensions
    are *always* excluded — the operator can't turn that off from the
    UI because there's no realistic pentest reason to drown the queue
    in CSS/JS/image requests.
    """
    methods: list[str] = field(
        default_factory=lambda: ["POST", "PUT", "PATCH", "DELETE"])
    host_regex: str = ""
    path_regex: str = ""
    exclude_host_regex: str = DEFAULT_NOISE_HOST_REGEX
    exclude_path_regex: str = DEFAULT_NOISE_PATH_REGEX

    def to_rule(self) -> Rule:
        return Rule(
            enabled=True,
            host_regex=self.host_regex or None,
            method_in=list(self.methods) if self.methods else None,
            path_regex=self.path_regex or None,
            exclude_host_regex=self.exclude_host_regex or None,
            exclude_path_regex=self.exclude_path_regex or None,
        )

    def to_dict(self) -> dict:
        return {
            "methods": list(self.methods),
            "host_regex": self.host_regex,
            "path_regex": self.path_regex,
            "exclude_host_regex": self.exclude_host_regex,
            "exclude_path_regex": self.exclude_path_regex,
        }

    @classmethod
    def from_dict(cls, d: dict | None) -> "InterceptConfig":
        if not d:
            return cls()
        methods = d.get("methods") or []
        if not isinstance(methods, list):
            methods = []
        return cls(
            methods=[str(m).upper() for m in methods
                     if isinstance(m, str) and m.upper() in SUPPORTED_METHODS],
            host_regex=str(d.get("host_regex", "") or ""),
            path_regex=str(d.get("path_regex", "") or ""),
            exclude_host_regex=str(
                d.get("exclude_host_regex", DEFAULT_NOISE_HOST_REGEX) or ""),
            exclude_path_regex=str(
                d.get("exclude_path_regex", DEFAULT_NOISE_PATH_REGEX) or ""),
        )
