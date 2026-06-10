"""SAML message decoder + simple inspector.

Handles the two transports defined by SAML 2.0:
    * **HTTP-Redirect** binding — base64 + raw DEFLATE (no zlib header)
    * **HTTP-POST** binding — plain base64

Inspector flags common issues found at audit time:
    * Signature element missing / unsigned assertion
    * Empty / missing ``NotOnOrAfter`` (replay window)
    * ``AudienceRestriction`` missing
    * Use of weak digest algorithms (SHA-1)
    * Algorithm in the ``ds:SignatureMethod`` that matches well-known weak values
"""
from __future__ import annotations

import base64
import re
import zlib
from dataclasses import dataclass, field

import xml.etree.ElementTree as ET


@dataclass
class SAMLFinding:
    severity: str   # 'info' | 'low' | 'medium' | 'high'
    title: str
    detail: str = ""


@dataclass
class SAMLInspection:
    xml: str = ""
    pretty: str = ""
    binding: str = ""              # 'http-redirect' | 'http-post' | 'raw'
    issuer: str = ""
    destination: str = ""
    id: str = ""
    not_on_or_after: str = ""
    audience: str = ""
    findings: list[SAMLFinding] = field(default_factory=list)
    error: str = ""


def decode(blob: str) -> tuple[str, str]:
    """Try every binding combination; return ``(xml, binding)``.

    Raises ``ValueError`` if none of them produce valid XML.
    """
    s = (blob or "").strip()
    if not s:
        raise ValueError("empty input")
    # Already raw XML?
    if s.lstrip().startswith("<"):
        return s, "raw"
    # The form may pass urlencoded base64 — undo + safely.
    s = s.replace(" ", "+")
    raw = _safe_b64(s)
    if raw is None:
        raise ValueError("input is not valid base64")
    # Try HTTP-POST first (most common in browsers): plain base64 = XML.
    try:
        text = raw.decode("utf-8")
        if "<" in text and ">" in text:
            return text, "http-post"
    except UnicodeDecodeError:
        pass
    # Try HTTP-Redirect: DEFLATE without zlib header.
    try:
        dec = zlib.decompress(raw, -zlib.MAX_WBITS)
        return dec.decode("utf-8"), "http-redirect"
    except (zlib.error, UnicodeDecodeError) as exc:
        raise ValueError(f"could not decode as POST or Redirect SAML: {exc}")


def _safe_b64(s: str) -> bytes | None:
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad, validate=False)
    except Exception:
        return None


def inspect(blob: str) -> SAMLInspection:
    try:
        xml, binding = decode(blob)
    except ValueError as exc:
        return SAMLInspection(error=str(exc))
    insp = SAMLInspection(xml=xml, binding=binding)
    insp.pretty = _pretty(xml)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        insp.error = f"XML parse error: {exc}"
        return insp
    insp.issuer = _ltext(root, "Issuer")
    insp.destination = root.attrib.get("Destination", "")
    insp.id = root.attrib.get("ID", "")
    cond = _lfind(root, "Conditions")
    if cond is not None:
        insp.not_on_or_after = cond.attrib.get("NotOnOrAfter", "")
        ar = _lfind(cond, "AudienceRestriction")
        if ar is not None:
            insp.audience = _ltext(ar, "Audience")
    insp.findings.extend(_audit(root, xml))
    return insp


def _ltext(root, local_name: str) -> str:
    for el in root.iter():
        if _local(el.tag) == local_name and el.text:
            return el.text.strip()
    return ""


def _lfind(root, local_name):
    for el in root.iter():
        if _local(el.tag) == local_name:
            return el
    return None


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _pretty(xml: str) -> str:
    # Naive pretty-print to avoid pulling in lxml just for this.
    try:
        import xml.dom.minidom as md
        return md.parseString(xml).toprettyxml(indent="  ")
    except Exception:
        return xml


_WEAK_DIGEST_NEEDLES = ("sha1", "ripemd160", "md5")


def _audit(root, xml: str) -> list[SAMLFinding]:
    out: list[SAMLFinding] = []
    # Signature presence
    has_sig = _lfind(root, "Signature") is not None
    if not has_sig:
        out.append(SAMLFinding(
            severity="high", title="SAML message is not signed",
            detail=("The Signature element is missing. Attackers can craft "
                    "arbitrary assertions and the relying party has no way "
                    "to verify authenticity."),
        ))
    # Weak digest / signature algorithms — match common URI suffixes like
    # "#sha1", "#rsa-sha1", "#hmac-sha1", "#md5".
    low = xml.lower()
    for weak in _WEAK_DIGEST_NEEDLES:
        if (f"#{weak}" in low
                or f"-{weak}\"" in low
                or f"-{weak}'" in low):
            out.append(SAMLFinding(
                severity="medium",
                title=f"Weak cryptographic algorithm: {weak.upper()}",
                detail=("The message references a SHA-1 / MD5 / RIPEMD-160 "
                        "algorithm URI. Modern IdPs should use SHA-256 or "
                        "stronger for both DigestMethod and SignatureMethod."),
            ))
            break
    # Conditions / replay window
    cond = _lfind(root, "Conditions")
    if cond is None or not cond.attrib.get("NotOnOrAfter"):
        out.append(SAMLFinding(
            severity="medium", title="No expiry (NotOnOrAfter) on assertion",
            detail=("Without a NotOnOrAfter timestamp the assertion is "
                    "indefinitely replayable."),
        ))
    # AudienceRestriction
    if cond is None or _lfind(cond, "AudienceRestriction") is None:
        out.append(SAMLFinding(
            severity="medium", title="No AudienceRestriction",
            detail=("The assertion does not bind itself to a specific "
                    "Service Provider, so it can be replayed against other "
                    "SPs that share the IdP."),
        ))
    # XML comment-injection heuristic on NameID
    if re.search(r"<!--.*?-->", xml, flags=re.S):
        out.append(SAMLFinding(
            severity="low", title="XML comments in payload",
            detail=("Comments can be used to confuse XML canonicalisation in "
                    "some parsers (CVE-2018-0489 family). Confirm the "
                    "consumer rejects or strips comments before trust "
                    "decisions."),
        ))
    return out


_SAML_RULE_IDS = {
    "SAML message is not signed":            ("saml:unsigned",        "CWE-345"),
    "No expiry (NotOnOrAfter) on assertion": ("saml:no-expiry",       "CWE-294"),
    "No AudienceRestriction":                ("saml:no-audience",     "CWE-346"),
    "XML comments in payload":               ("saml:xml-comments",    "CWE-91"),
}


def _saml_rule_for(title: str) -> tuple[str, str]:
    if title in _SAML_RULE_IDS:
        return _SAML_RULE_IDS[title]
    if title.startswith("Weak cryptographic algorithm"):
        return ("saml:weak-algo", "CWE-327")
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "issue"
    return (f"saml:{slug}", "")


def record_saml_findings(project, inspection: SAMLInspection, *,
                          host: str = "", url: str = "") -> list[int]:
    """Promote every :class:`SAMLFinding` on ``inspection`` into the unified
    findings ledger. Returns the list of finding ids that were created (or
    deduped to an existing row). Suppressed findings yield no id."""
    from .findings_bus import record_finding
    out: list[int] = []
    for f in inspection.findings:
        rule_id, cwe = _saml_rule_for(f.title)
        fid = record_finding(
            project, source="saml", rule_id=rule_id,
            severity=f.severity, title=f.title,
            description=f.detail, cwe=cwe,
            host=host, url=url,
            evidence=f.detail[:200],
        )
        if fid is not None:
            out.append(fid)
    return out
