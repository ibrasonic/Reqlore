"""Phase 3 (Burp-parity) \u2014 response fingerprinting for WAFs and framework
error pages.

Two purposes:

* **WAF block-page detection** \u2014 if a finding's response looks like
  Cloudflare/AWS WAF/Akamai/F5/Imperva/Sucuri returning a generic block
  page, the finding's confidence is demoted to ``"tentative"`` and the
  tag ``behind_waf:<vendor>`` is attached. The finding is **never
  silently dropped** \u2014 demotion only \u2014 because a real-world target
  fronted by a WAF can still be vulnerable; the WAF just makes the
  evidence noisier.
* **Framework error-page detection** \u2014 Flask debugger, Django DEBUG,
  Rails error, IIS yellow-screen, PHP warning/notice. These pages
  almost always reflect attacker input verbatim, so XSS / reflection
  rules light up on every probe. We tag (``error_page:<framework>``)
  and demote so the finding is recorded but doesn't crowd the high
  -severity list.

The detector is intentionally conservative: every regex matches a
fragment that the framework / vendor itself prints, not a string an
attacker could control. False negatives are preferred over false
positives.

Functions exported:

* :func:`fingerprint_response` \u2014 the public entry point. Returns a list
  of tag strings.
* :func:`apply_fingerprint` \u2014 helper that maps tag list \u2192 (confidence,
  joined_tags_string) for use by ``record_finding``.
"""
from __future__ import annotations

import re
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# Vendor / framework signatures.
# Each entry: (tag, list of compiled regexes against the response body OR
# the response headers; we OR the matches together).
# ---------------------------------------------------------------------------

# Body signatures \u2014 case-insensitive matches against the response body
# (decoded as latin-1 / utf-8). Each tuple is (tag, regex).
_BODY_SIGNATURES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    # ----- WAFs -----
    ("behind_waf:cloudflare", re.compile(
        rb"(Attention\s+Required!\s*\|\s*Cloudflare|cf-error-details|"
        rb"<title>Just a moment\.\.\.</title>|Cloudflare\s+Ray\s+ID)",
        re.IGNORECASE,
    )),
    ("behind_waf:aws", re.compile(
        rb"(AWS\s+WAF|<title>403\s+Forbidden</title>.{0,200}"
        rb"Request\s+blocked)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("behind_waf:akamai", re.compile(
        rb"(akamai\s+reference\s+(number|id)|Reference\s+&#?\d|"
        rb"AkamaiGHost)",
        re.IGNORECASE,
    )),
    ("behind_waf:f5", re.compile(
        rb"(The\s+requested\s+URL\s+was\s+rejected|"
        rb"Please\s+consult\s+with\s+your\s+administrator|"
        rb"Support\s+ID:\s*\d{10,})",
        re.IGNORECASE,
    )),
    ("behind_waf:imperva", re.compile(
        rb"(Incapsula\s+incident\s+ID|_Incapsula_Resource|"
        rb"Powered\s+by\s+Incapsula)",
        re.IGNORECASE,
    )),
    ("behind_waf:sucuri", re.compile(
        rb"(Sucuri\s+WebSite\s+Firewall|Access\s+Denied\s+-\s+Sucuri)",
        re.IGNORECASE,
    )),
    # ----- framework error / debug pages -----
    ("error_page:flask_debug", re.compile(
        rb"(Werkzeug\s+Debugger|The\s+debugger\s+caught\s+an\s+exception|"
        rb"<title>.{0,80}Werkzeug</title>)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("error_page:django_debug", re.compile(
        rb"(You're\s+seeing\s+this\s+error\s+because|"
        rb"<title>.{0,120}at\s+/.{0,80}</title>.{0,500}django|"
        rb"DEBUG\s*=\s*True)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("error_page:rails", re.compile(
        rb"(Action\s+Controller:\s+Exception\s+caught|"
        rb"<title>Action\s+Controller:|"
        rb"<h1>.{0,40}Routing\s+Error)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("error_page:iis", re.compile(
        rb"(Server\s+Error\s+in\s+'.{0,40}'\s+Application|"
        rb"<title>Runtime\s+Error</title>|"
        rb"yellow-screen-of-death|<b>\s*Compilation\s+Error</b>)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("error_page:php", re.compile(
        rb"(<b>\s*(Notice|Warning|Fatal\s+error|Parse\s+error)\s*</b>:|"
        rb"PHP\s+(Notice|Warning|Fatal\s+error|Parse\s+error):)",
        re.IGNORECASE,
    )),
)

# Header signatures \u2014 match against a single decoded "Name: value" line
# (case-insensitive). Header matches alone are enough to tag a vendor
# because servers rarely set these by accident.
_HEADER_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("behind_waf:cloudflare", re.compile(
        r"^(server\s*:\s*cloudflare|cf-ray\s*:|cf-cache-status\s*:)",
        re.IGNORECASE,
    )),
    ("behind_waf:aws", re.compile(
        r"^(x-amzn-requestid\s*:|x-amz-cf-id\s*:|x-amzn-errortype\s*:)",
        re.IGNORECASE,
    )),
    ("behind_waf:akamai", re.compile(
        r"^(server\s*:\s*akamaighost|x-akamai-|akamai-)",
        re.IGNORECASE,
    )),
    ("behind_waf:f5", re.compile(
        r"^(x-wa-info\s*:|server\s*:\s*bigip|x-cnection\s*:)",
        re.IGNORECASE,
    )),
    ("behind_waf:imperva", re.compile(
        r"^(x-iinfo\s*:|x-cdn\s*:\s*imperva)",
        re.IGNORECASE,
    )),
    ("behind_waf:sucuri", re.compile(
        r"^(x-sucuri-id\s*:|x-sucuri-cache\s*:|server\s*:\s*sucuri)",
        re.IGNORECASE,
    )),
)

# Status codes that strongly correlate with WAF blocking (used only as
# a secondary signal: status alone is never enough to tag).
_WAF_BLOCK_STATUS = frozenset({403, 406, 429, 451, 501, 503})

# Cap how much of the body we scan \u2014 these regexes are simple but the
# body can be megabytes and we are called on the hot path.
_MAX_BODY_BYTES = 64 * 1024


def fingerprint_response(body: bytes | None,
                          headers: Sequence[tuple[str, str]] | None = None,
                          *, status: int | None = None,
                          ) -> list[str]:
    """Return a sorted, de-duplicated list of fingerprint tags for the
    response described by ``body`` / ``headers``.

    Both arguments are optional so a caller that only has the response
    blob (or only headers) can still get a useful answer.

    Returns ``[]`` when nothing matches. Defensive: any failure inside
    a single regex is swallowed so one bad pattern can never break the
    bus layer.
    """
    tags: set[str] = set()
    if body:
        sample = body[:_MAX_BODY_BYTES]
        for tag, pat in _BODY_SIGNATURES:
            try:
                if pat.search(sample):
                    tags.add(tag)
            except (TypeError, re.error):
                continue
    if headers:
        # Materialise as decoded "name: value" lines so each pattern
        # can match a single line.
        for name, value in headers:
            try:
                line = f"{name}: {value}"
            except (TypeError, ValueError):
                continue
            for tag, pat in _HEADER_SIGNATURES:
                try:
                    if pat.search(line):
                        tags.add(tag)
                except (TypeError, re.error):
                    continue
    # Secondary signal: a generic 4xx/5xx status combined with a tiny
    # body containing only a vendor name in the title is otherwise
    # easy to miss. Already handled by the body regexes; the status is
    # left here for callers that want to inspect it themselves.
    _ = status
    return sorted(tags)


def apply_fingerprint(tags: Iterable[str],
                       *, base_confidence: str = "firm",
                       ) -> tuple[str, str]:
    """Map a list of fingerprint tags to the (confidence, joined-tags)
    pair that ``record_finding`` / ``add_finding`` expect.

    Rule: any ``behind_waf:*`` or ``error_page:*`` tag demotes the
    finding to ``"tentative"``. The strongest demotion wins; a
    finding already at ``"tentative"`` cannot be promoted by this
    function.
    """
    tag_list = [t for t in tags if t]
    joined = ",".join(sorted(set(tag_list)))
    demote = any(
        t.startswith("behind_waf:") or t.startswith("error_page:")
        for t in tag_list
    )
    if demote:
        return "tentative", joined
    return base_confidence, joined


__all__ = [
    "fingerprint_response",
    "apply_fingerprint",
]
