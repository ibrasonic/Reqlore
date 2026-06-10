"""Optional-dependency availability flags.

Reqlore keeps several capabilities behind opt-in ``[project.optional-dependencies]``
extras so the default install stays small. Modules that depend on those extras
import the matching flag from here and skip work gracefully when ``False``.

The probes are import-time and cached at module load — nothing in here is
expected to change between processes.
"""
from __future__ import annotations

try:
    import playwright  # noqa: F401
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import dns.resolver  # noqa: F401
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


__all__ = ["PLAYWRIGHT_AVAILABLE", "DNS_AVAILABLE"]
