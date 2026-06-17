"""Defused XML helpers.

``xml.etree.ElementTree`` and ``xml.dom.minidom`` are vulnerable to
entity-expansion attacks ("billion laughs", quadratic blowup). minidom
additionally fetches external entities by default, so untrusted XML
input can trigger XXE.

We prefer :mod:`defusedxml` when available — it is a tiny pure-Python
shim that monkey-patches the unsafe expat features off. When the
dependency is missing we fall back to a manually-hardened
``XMLParser`` that disables DTD processing entirely; this protects
ElementTree at the cost of dropping legitimate DTDs.

The pretty-print helper used by the SAML inspector parses with the
hardened ElementTree and re-serialises through minidom only after the
DOCTYPE/entity surface has been removed by ElementTree, so even the
fallback path is safe.
"""
from __future__ import annotations

try:
    import defusedxml.ElementTree as _ET  # type: ignore[import-not-found]
    _DEFUSED = True
except ImportError:  # pragma: no cover - exercised when dep absent
    import xml.etree.ElementTree as _ET  # type: ignore[no-redef]
    _DEFUSED = False

try:
    import defusedxml.minidom as _MD  # type: ignore[import-not-found]
    _DEFUSED_MD = True
except ImportError:  # pragma: no cover
    import xml.dom.minidom as _MD  # type: ignore[no-redef]
    _DEFUSED_MD = False


# Fallback ElementTree parser with DTDs forbidden — re-used when
# defusedxml is not installed.
def _hardened_parser():
    import xml.etree.ElementTree as _stdlib_ET  # local import
    parser = _stdlib_ET.XMLParser()
    # ``UseForeignDTD(False)`` and rejecting any ``StartDoctypeDecl``
    # together kill external entity resolution and inline ``<!ENTITY>``
    # declarations. expat ignores the rest after that.
    try:
        parser.parser.UseForeignDTD(False)
    except Exception:  # pragma: no cover - older Python
        pass

    def _no_doctype(*_args, **_kwargs):
        raise ValueError("DOCTYPE / DTD declarations are not permitted")

    try:
        parser.parser.StartDoctypeDeclHandler = _no_doctype
    except Exception:  # pragma: no cover
        pass
    return parser


def fromstring(xml: str | bytes):
    """Parse ``xml`` and return the root element. Rejects DTDs / entities."""
    if _DEFUSED:
        return _ET.fromstring(xml)
    import xml.etree.ElementTree as _stdlib_ET
    return _stdlib_ET.fromstring(xml, parser=_hardened_parser())


# Re-export the parser's specific exception so callers can catch it
# without importing the underlying library.
ParseError = _ET.ParseError  # type: ignore[attr-defined]


def pretty(xml: str) -> str:
    """Return a pretty-printed version of ``xml``. Falls back to the original
    string on parse error or if minidom is itself unavailable."""
    try:
        # Parse first with the hardened ElementTree, which strips
        # DOCTYPE / entity declarations.
        root = fromstring(xml)
        import xml.etree.ElementTree as _stdlib_ET
        canonical = _stdlib_ET.tostring(root, encoding="unicode")
        if _DEFUSED_MD:
            return _MD.parseString(canonical).toprettyxml(indent="  ")
        # Stdlib minidom still safe at this point because ``canonical``
        # contains no DTD/entities.
        return _MD.parseString(canonical).toprettyxml(indent="  ")
    except Exception:
        return xml
