"""Decoder/Encoder."""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import json
import re
import urllib.parse
import zlib

import jwt as pyjwt
from flask import Blueprint, render_template, request

bp = Blueprint("decoder", __name__)


OPERATIONS = [
    ("url_encode", "URL encode"),
    ("url_decode", "URL decode"),
    ("form_encode", "URL encode (form body, keep & =)"),
    ("form_decode", "URL decode (form body, keep & =)"),
    ("html_encode", "HTML encode"),
    ("html_decode", "HTML decode"),
    ("b64_encode", "Base64 encode"),
    ("b64_decode", "Base64 decode"),
    ("b64url_encode", "Base64 URL-safe encode"),
    ("b64url_decode", "Base64 URL-safe decode"),
    ("hex_encode", "Hex encode"),
    ("hex_decode", "Hex decode"),
    ("gzip_encode", "Gzip compress"),
    ("gzip_decode", "Gzip decompress"),
    ("deflate_encode", "Deflate compress"),
    ("deflate_decode", "Deflate decompress"),
    ("rot13", "ROT13"),
    ("md5", "MD5 hash"),
    ("sha1", "SHA-1 hash"),
    ("sha256", "SHA-256 hash"),
    ("sha512", "SHA-512 hash"),
    ("jwt_decode", "JWT decode (no verify)"),
    ("json_pretty", "JSON pretty-print"),
    ("json_minify", "JSON minify"),
    ("smart_decode", "Smart decode (chain)"),
]


def _encode(op: str, s: str) -> tuple[str, str | None]:
    """Returns (output, error_or_None)."""
    try:
        b = s.encode("utf-8")
        if op == "url_encode":
            return urllib.parse.quote(s, safe=""), None
        if op == "url_decode":
            # `unquote_plus` decodes BOTH `%20` and `+` to space, matching
            # how application/x-www-form-urlencoded bodies are decoded by
            # every browser and HTTP library. Plain `unquote` left `+`
            # literal, so a form body pasted from Repeater would decode
            # incorrectly ("hello+world" stayed "hello+world").
            return urllib.parse.unquote_plus(s), None
        if op == "form_encode":
            return _form_recode(s, encode=True), None
        if op == "form_decode":
            return _form_recode(s, encode=False), None
        if op == "html_encode":
            return html.escape(s, quote=True), None
        if op == "html_decode":
            return html.unescape(s), None
        if op == "b64_encode":
            return base64.b64encode(b).decode("ascii"), None
        if op == "b64_decode":
            return _b64_decode_strict(s, urlsafe=False), None
        if op == "b64url_encode":
            return base64.urlsafe_b64encode(b).decode("ascii").rstrip("="), None
        if op == "b64url_decode":
            return _b64_decode_strict(s, urlsafe=True), None
        if op == "hex_encode":
            return b.hex(), None
        if op == "hex_decode":
            # Be liberal: accept any whitespace, "0x" prefix, and the
            # common ":"/"-" byte separators that hex dumps use.
            cleaned = re.sub(r"[\s:_\-]", "", s)
            if cleaned.lower().startswith("0x"):
                cleaned = cleaned[2:]
            return bytes.fromhex(cleaned).decode("utf-8", errors="replace"), None
        if op == "gzip_encode":
            return base64.b64encode(gzip.compress(b)).decode("ascii"), None
        if op == "gzip_decode":
            return gzip.decompress(_b64_bytes_strict(s)).decode("utf-8", errors="replace"), None
        if op == "deflate_encode":
            return base64.b64encode(zlib.compress(b)).decode("ascii"), None
        if op == "deflate_decode":
            return zlib.decompress(_b64_bytes_strict(s)).decode("utf-8", errors="replace"), None
        if op == "rot13":
            return s.translate(_ROT13), None
        if op in ("md5", "sha1", "sha256", "sha512"):
            return hashlib.new(op, b).hexdigest(), None
        if op == "jwt_decode":
            parts = s.strip().split(".")
            if len(parts) < 2:
                return "", "Not a JWT (need at least 2 dots)."
            header = pyjwt.get_unverified_header(s.strip())
            payload = pyjwt.decode(s.strip(), options={"verify_signature": False})
            return json.dumps({"header": header, "payload": payload}, indent=2), None
        if op == "json_pretty":
            return json.dumps(json.loads(s), indent=2, sort_keys=False), None
        if op == "json_minify":
            return json.dumps(json.loads(s), separators=(",", ":")), None
        if op == "smart_decode":
            return _smart(s), None
        return "", f"Unknown operation: {op}"
    except (binascii.Error, ValueError, UnicodeDecodeError, OSError) as e:
        return "", f"{type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}"


_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _form_recode(s: str, *, encode: bool) -> str:
    # Treat the string as application/x-www-form-urlencoded: split on &
    # then on the first =, transform key and value separately, rejoin
    # with the structural separators intact. Lets an operator decode a
    # body, edit one value, and re-encode without the & and = inside
    # the values getting promoted into new param boundaries.
    op_one = (lambda v: urllib.parse.quote(v, safe="")) if encode else urllib.parse.unquote_plus
    out_pairs = []
    for pair in s.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out_pairs.append(f"{op_one(k)}={op_one(v)}")
        else:
            out_pairs.append(op_one(pair))
    return "&".join(out_pairs)


def _b64_bytes_strict(s: str) -> bytes:
    """Decode a base64 string to bytes with strict validation.
    Strips whitespace then re-pads, but rejects any character outside
    the standard base64 alphabet. Returning raw bytes lets binary
    payloads (gzip/deflate) be decompressed without an intermediate
    UTF-8 round-trip that would have corrupted them.
    """
    cleaned = re.sub(r"\s+", "", s)
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned.encode("ascii"), validate=True)


def _b64_decode_strict(s: str, *, urlsafe: bool) -> str:
    """Decode a base64 (or url-safe base64) string to UTF-8 text.
    Strict: silently accepting garbage made it impossible to tell
    "this isn't base64" from "this base64 decodes to non-text bytes",
    so we validate the alphabet up front. Non-text decoded bytes still
    use replacement chars rather than raising \u2014 the operator can see
    that and switch to gzip/hex/etc. if needed.
    """
    cleaned = re.sub(r"\s+", "", s)
    if urlsafe:
        cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    raw = base64.b64decode(cleaned.encode("ascii"), validate=True)
    return raw.decode("utf-8", errors="replace")


def _smart(s: str) -> str:
    """Try URL → b64 → JWT decode until something looks readable.
    Each candidate output must change the string AND look mostly
    printable AND \u2014 for base64 \u2014 only run when the input shape is
    actually base64-ish (alphabet chars only, length divisible after
    re-padding). The b64 gating matters now that the underlying decoder
    is strict: without a shape check we'd surface its error for every
    arbitrary intermediate string.
    """
    out = s
    for _ in range(5):
        prev = out
        for op in ("url_decode", "b64_decode", "jwt_decode"):
            if op == "b64_decode" and not _looks_b64(out):
                continue
            v, err = _encode(op, out)
            if not err and v and v != out and _printable(v):
                out = v
                break
        if out == prev:
            break
    return out


def _looks_b64(s: str) -> bool:
    """Strict shape gate for smart_decode's b64 pass.
    Must already be a single base64 token: no internal whitespace, only
    standard-alphabet characters, length \u2265 4 and divisible by 4 after
    re-padding. Stricter than the b64_decode op itself (which strips
    surrounding whitespace) because smart_decode runs speculatively on
    arbitrary intermediate strings, and a loose match here would mis-
    decode plain text like 'helloworld' into binary garbage.
    """
    t = s.strip()
    if len(t) < 4:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+=*", t):
        return False
    # After padding to a multiple of 4, length must be reachable from a
    # valid encode. 4n+1 is impossible; 4n+2/4n+3 need 2/1 pad chars.
    return (len(t) + (-len(t) % 4)) % 4 == 0 and len(t) % 4 != 1


def _printable(s: str) -> bool:
    return sum(1 for c in s if c.isprintable() or c in "\r\n\t") / max(len(s), 1) > 0.85


@bp.route("/", methods=["GET", "POST"])
def index():
    op = request.form.get("op", "url_encode") if request.method == "POST" else "url_encode"
    text_in = request.form.get("text_in", "") if request.method == "POST" else ""
    # Pre-fill from GET param when arriving via "Send to Decoder".
    if request.method == "GET":
        text_in = request.args.get("text", "")
    text_out = ""
    error = None
    if request.method == "POST" and text_in:
        text_out, error = _encode(op, text_in)
    return render_template("decoder/index.html",
                           ops=OPERATIONS, op=op,
                           text_in=text_in, text_out=text_out, error=error)
