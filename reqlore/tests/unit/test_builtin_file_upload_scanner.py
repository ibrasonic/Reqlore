"""Tests for the bundled ``file-upload-scanner`` plugin.

Two layers:

1. **Unit**: payload builders + helper functions + case-list generator
   are exercised with assertions on their bytes / structure. Fast,
   network-free, deterministic.
2. **Integration**: the plugin's runner function is invoked through a
   stub :class:`PluginContext` that captures every ``send`` /
   ``record_finding`` / ``add_result`` / ``log`` / ``oast_*`` call.
   Asserts that the runner walks cases, builds correct multipart
   bodies, honours stop / scope / OAST / re-download oracle and
   files findings with the right severities.
3. **Discovery**: the registry default search path (which now includes
   the bundled built-in dir) finds the plugin out-of-the-box.
"""
from __future__ import annotations

# Import the plugin module by file path the same way the registry
# does so it's exercised through the public surface only.
import importlib.util
import io
import struct
import sys
import threading
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from reqlore import plugins_sdk as sdk
from reqlore.plugins import (
    default_plugin_dirs,
    get_registry,
    reset_registry,
)

_PLUGIN_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "builtin_plugins" / "file_upload_scanner.py"
)
_PLUGIN_MODNAME = "_reqlore_test_upload_scanner"


def _load_plugin_module():
    if _PLUGIN_MODNAME in sys.modules:
        return sys.modules[_PLUGIN_MODNAME]
    spec = importlib.util.spec_from_file_location(
        _PLUGIN_MODNAME, _PLUGIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec so dataclasses can resolve cls.__module__
    # via sys.modules during ClassVar inspection.
    sys.modules[_PLUGIN_MODNAME] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def upmod():
    return _load_plugin_module()


# ============================================================ Binary builders


def test_png_blob_has_signature(upmod):
    b = upmod._png_blob()
    assert b.startswith(b"\x89PNG\r\n\x1a\n")
    # IHDR + IDAT + IEND chunks present.
    assert b"IHDR" in b
    assert b"IDAT" in b
    assert b"IEND" in b
    # Round-trip with zlib so a real decoder would accept the IDAT.
    # Find IDAT chunk: 4 bytes length, 4 bytes tag, data, 4 CRC.
    idx = b.index(b"IDAT")
    length = struct.unpack(">I", b[idx - 4:idx])[0]
    data = b[idx + 4: idx + 4 + length]
    # zlib.decompress raises if malformed.
    zlib.decompress(data)


def test_jpeg_blob_starts_with_soi_and_ends_with_eoi(upmod):
    b = upmod._jpeg_blob()
    assert b.startswith(b"\xff\xd8\xff\xe0")
    assert b.endswith(b"\xff\xd9")
    assert b"JFIF" in b


def test_gif_blob_is_gif89a(upmod):
    b = upmod._gif_blob()
    assert b.startswith(b"GIF89a")
    assert b.endswith(b";")


def test_gif_php_polyglot_keeps_gif_magic_and_php(upmod):
    src = "<?php echo 'X'; ?>"
    out = upmod._gif_php_polyglot(src)
    assert out.startswith(b"GIF89a")
    assert b"<?php" in out


def test_png_php_polyglot_keeps_png_signature_and_php(upmod):
    out = upmod._png_php_polyglot("<?php echo 'X'; ?>")
    assert out.startswith(b"\x89PNG")
    assert b"<?php" in out


def test_jpg_php_polyglot_keeps_jpeg_soi_and_php(upmod):
    out = upmod._jpg_php_polyglot("<?php echo 'X'; ?>")
    assert out.startswith(b"\xff\xd8\xff\xe0")
    assert b"<?php" in out


def test_svg_xss_payload_contains_script(upmod):
    b = upmod._svg_xss()
    assert b.startswith(b"<?xml")
    assert b"<script" in b
    assert b"fetch(" in b


def test_svg_xxe_oast_embeds_url(upmod):
    url = "http://oast.example/abc/svg-xxe/"
    b = upmod._svg_xxe_oast(url)
    assert b"<!DOCTYPE" in b
    assert b"ENTITY" in b
    assert url.encode() in b
    assert b"&xxe;" in b


def test_svg_xxe_file_uses_etc_passwd(upmod):
    b = upmod._svg_xxe_file()
    assert b"file:///etc/passwd" in b


def test_svg_ssrf_payload_uses_image_href(upmod):
    url = "http://oast.example/abc/svg-ssrf/"
    b = upmod._svg_ssrf(url)
    assert b"<image" in b
    assert url.encode() in b


def test_xml_xxe_payload_is_well_formed_prologue(upmod):
    url = "http://oast.example/xxe/"
    b = upmod._xml_xxe(url)
    assert b.startswith(b"<?xml")
    assert b"&xxe;" in b


def test_docx_xxe_is_valid_zip_with_doc_xml(upmod):
    url = "http://oast.example/docxxxe/"
    b = upmod._docx_xxe(url)
    bio = io.BytesIO(b)
    with zipfile.ZipFile(bio) as zf:
        names = zf.namelist()
        assert "[Content_Types].xml" in names
        assert "word/document.xml" in names
        doc = zf.read("word/document.xml")
    assert b"ENTITY" in doc
    assert url.encode() in doc


def test_pdf_oast_has_pdf_header_and_openaction(upmod):
    url = "http://oast.example/pdf/"
    b = upmod._pdf_oast(url)
    assert b.startswith(b"%PDF-")
    assert b"/OpenAction" in b
    assert b"/URI" in b
    assert url.encode() in b


def test_zip_slip_contains_traversal_entries(upmod):
    b = upmod._zip_slip()
    with zipfile.ZipFile(io.BytesIO(b)) as zf:
        names = zf.namelist()
    assert any(n.startswith("../") for n in names)
    assert any("\\" in n or n.startswith("..") for n in names)


def test_zip_php_contains_shell_php(upmod):
    b = upmod._zip_php("<?php echo 'pwn'; ?>")
    with zipfile.ZipFile(io.BytesIO(b)) as zf:
        assert "shell.php" in zf.namelist()
        assert b"<?php" in zf.read("shell.php")


def test_imagick_mvg_references_oast(upmod):
    url = "http://oast.example/mvg/"
    b = upmod._imagick_mvg(url)
    assert b.startswith(b"push graphic-context")
    assert url.encode() in b
    assert b"url:" in b


def test_imagick_msl_xml_with_read(upmod):
    url = "http://oast.example/msl/"
    b = upmod._imagick_msl(url)
    assert b.startswith(b"<?xml")
    assert url.encode() in b
    assert b"<read" in b


def test_ghostscript_payload_starts_with_ps(upmod):
    url = "http://oast.example/gs/"
    b = upmod._ghostscript_ssrf(url)
    assert b.startswith(b"%!PS")
    assert url.encode() in b


def test_csv_injection_has_formula_payloads(upmod):
    b = upmod._csv_injection()
    assert b.startswith(b"user,formula")
    for payload in (b"=cmd|", b"@SUM(", b"+1+cmd", b"-2+cmd",
                    b"=HYPERLINK("):
        assert payload in b


def test_html_xss_payload_embeds_url(upmod):
    url = "http://oast.example/html/"
    b = upmod._html_xss(url)
    assert b"<script" in b
    assert b"fetch(" in b
    assert url.encode() in b


# ============================================================ Multipart


def test_multipart_includes_headers_and_body(upmod):
    ct, body = upmod._build_multipart(
        file_field="upload", filename="x.png",
        file_content=b"\x89PNG\r\n", file_content_type="image/png",
        extra_fields=(("k1", "v1"), ("k2", "v2")),
    )
    assert ct.startswith("multipart/form-data; boundary=reqlore")
    boundary = ct.split("boundary=", 1)[1]
    assert (b"--" + boundary.encode()) in body
    # closing boundary
    assert body.rstrip(b"\r\n").endswith(b"--")
    # extra fields rendered
    assert b'name="k1"' in body
    assert b"v1\r\n" in body
    assert b"v2\r\n" in body
    # file part headers + content
    assert b'name="upload"' in body
    assert b'filename="x.png"' in body
    assert b"Content-Type: image/png" in body
    assert b"\x89PNG\r\n" in body


def test_multipart_passes_through_evil_filenames(upmod):
    """Filenames with CRLF / null / quotes are emitted verbatim so the
    server's parser is the one being tested."""
    bad = "evil\r\nX-Injected:1\r\nfoo\x00.png"
    _, body = upmod._build_multipart(
        file_field="f", filename=bad,
        file_content=b"x", file_content_type="application/octet-stream",
    )
    assert b"evil\r\nX-Injected:1\r\nfoo\x00.png" in body


def test_put_body_returns_raw_content(upmod):
    ct, body = upmod._put_body(b"<?php ?>", "application/x-php")
    assert ct == "application/x-php"
    assert body == b"<?php ?>"


# ============================================================ Helpers


@pytest.mark.parametrize("raw,expected", [
    ("simple.png", "simple.png"),
    ("/etc/passwd", "passwd"),
    ("..\\..\\windows\\evil.exe", "evil.exe"),
    ("a/b/c/d.txt", "d.txt"),
    ("shell.php\x00.jpg", "shell.php"),
    ("", ""),
])
def test_extract_basename(upmod, raw, expected):
    assert upmod._extract_basename(raw) == expected


def test_redownload_url_with_basename_slot(upmod):
    url = upmod._redownload_url(
        "https://h.test/u/{basename}", "../../shell.php")
    assert url == "https://h.test/u/shell.php"


def test_redownload_url_with_filename_slot(upmod):
    url = upmod._redownload_url(
        "https://h.test/u/{filename}", "a.png")
    assert url == "https://h.test/u/a.png"


def test_redownload_url_invalid_template_falls_back_to_join(upmod):
    """An invalid template (e.g. unknown slot) should still produce a
    usable URL via naive join rather than crash."""
    url = upmod._redownload_url("https://h.test/u/{unknown}", "a.png")
    # Either it formatted with no substitution OR fell back to join.
    assert url and url.endswith("a.png")


def test_redownload_url_empty_template_returns_none(upmod):
    assert upmod._redownload_url("", "a.png") is None
    assert upmod._redownload_url("   ", "a.png") is None


def test_looks_accepted_status_match(upmod):
    baseline = upmod.Baseline(status=200, body_len=10)

    @dataclass
    class R:
        status: int = 200
        body: bytes = b"ok"
        headers: list = field(default_factory=list)

    assert upmod._looks_accepted(baseline, R(status=200, body=b"a" * 10))
    assert upmod._looks_accepted(baseline, R(status=201, body=b"a" * 10))
    assert not upmod._looks_accepted(baseline, R(status=400, body=b""))
    assert not upmod._looks_accepted(baseline, R(status=0))


def test_looks_accepted_rejects_huge_error_page(upmod):
    baseline = upmod.Baseline(status=200, body_len=200)

    @dataclass
    class R:
        status: int = 200
        body: bytes = b"!" * (200 * 100)
        headers: list = field(default_factory=list)

    assert not upmod._looks_accepted(baseline, R())


# ============================================================ Case generator


def test_build_cases_baseline_always_first(upmod):
    cases = upmod.build_cases({})
    assert cases
    assert cases[0].name == "baseline-png"
    assert cases[0].category == "baseline"


def test_build_cases_php_disabled(upmod):
    settings = {"test_php": False, "test_asp": False, "test_jsp": False,
                "test_perl": False, "test_image_polyglot": False,
                "test_svg": False, "test_xxe": False, "test_pdf": False,
                "test_zip": False, "test_imagick": False,
                "test_csv_injection": False, "test_eicar": False,
                "test_path_traversal": False, "test_shell_metachars": False,
                "test_edge_cases": False, "test_htaccess": False,
                "test_large_file": False}
    cases = upmod.build_cases(settings)
    assert len(cases) == 1  # only baseline
    assert cases[0].name == "baseline-png"


def test_build_cases_php_only_yields_executor_cases(upmod):
    settings = {
        "test_php": True, "test_asp": False, "test_jsp": False,
        "test_perl": False, "test_python": False, "test_cf": False,
        "test_htaccess": False, "test_image_polyglot": False,
        "test_svg": False, "test_xxe": False, "test_pdf": False,
        "test_zip": False, "test_imagick": False,
        "test_csv_injection": False, "test_eicar": False,
        "test_path_traversal": False, "test_shell_metachars": False,
        "test_edge_cases": False, "test_large_file": False,
    }
    cases = upmod.build_cases(settings)
    cats = {c.category for c in cases}
    assert "executor:php" in cats
    # Every PHP case carries an RCE marker for later oracle checks.
    php_cases = [c for c in cases if c.category == "executor:php"]
    assert php_cases and all(c.rce_marker for c in php_cases)
    # Markers are identical per run.
    assert len({c.rce_marker for c in php_cases}) == 1


def test_build_cases_svg_oast_requires_token(upmod):
    settings = {"test_php": False, "test_asp": False, "test_jsp": False,
                "test_perl": False, "test_image_polyglot": False,
                "test_svg": True, "test_xxe": False, "test_pdf": False,
                "test_zip": False, "test_imagick": False,
                "test_csv_injection": False, "test_eicar": False,
                "test_path_traversal": False, "test_shell_metachars": False,
                "test_edge_cases": False, "test_htaccess": False,
                "test_large_file": False, "use_oast": True}
    # No token -> SVG-OAST cases not generated.
    cases = upmod.build_cases(settings)
    names = {c.name for c in cases}
    assert "svg-xss" in names
    assert "svg-xxe-file" in names
    assert "svg-ssrf" not in names  # needs OAST
    # With token -> OAST cases appear and embed the token URL.
    cases = upmod.build_cases(settings, oast_token="tok",  # noqa: S106  # test fixture token, not a real credential
                              oast_base="http://oast.test/tok/")
    ssrf = [c for c in cases if c.name == "svg-ssrf"][0]
    assert b"http://oast.test/tok/svg-ssrf/" in ssrf.content
    assert ssrf.oast_tag == "svg-ssrf"


def test_build_cases_zip_includes_slip(upmod):
    settings = {"test_zip": True, "test_php": False, "test_asp": False,
                "test_jsp": False, "test_perl": False,
                "test_image_polyglot": False, "test_svg": False,
                "test_xxe": False, "test_pdf": False, "test_imagick": False,
                "test_csv_injection": False, "test_eicar": False,
                "test_path_traversal": False, "test_shell_metachars": False,
                "test_edge_cases": False, "test_htaccess": False,
                "test_large_file": False}
    names = {c.name for c in upmod.build_cases(settings)}
    assert "zip-slip" in names
    assert "zip-php" in names


def test_build_cases_path_traversal_filenames_varied(upmod):
    settings = {"test_path_traversal": True, "test_php": False,
                "test_asp": False, "test_jsp": False, "test_perl": False,
                "test_image_polyglot": False, "test_svg": False,
                "test_xxe": False, "test_pdf": False, "test_zip": False,
                "test_imagick": False, "test_csv_injection": False,
                "test_eicar": False, "test_shell_metachars": False,
                "test_edge_cases": False, "test_htaccess": False,
                "test_large_file": False}
    cases = upmod.build_cases(settings)
    trav = [c for c in cases if c.category == "path-traversal"]
    filenames = [c.filename for c in trav]
    assert any(fn.startswith("../") for fn in filenames)
    assert any("\\" in fn for fn in filenames)
    assert any(fn.startswith("/etc/") for fn in filenames)
    assert any(fn.startswith("C:") for fn in filenames)
    assert any(fn.startswith("file:") for fn in filenames)


def test_build_cases_shell_metachar_filenames(upmod):
    settings = {"test_shell_metachars": True, "test_php": False,
                "test_asp": False, "test_jsp": False, "test_perl": False,
                "test_image_polyglot": False, "test_svg": False,
                "test_xxe": False, "test_pdf": False, "test_zip": False,
                "test_imagick": False, "test_csv_injection": False,
                "test_eicar": False, "test_path_traversal": False,
                "test_edge_cases": False, "test_htaccess": False,
                "test_large_file": False}
    cases = upmod.build_cases(settings)
    fnames = [c.filename for c in cases if c.category == "metachar"]
    assert any("$(id)" in f for f in fnames)
    assert any(";id" in f for f in fnames)
    assert any("|id" in f for f in fnames)
    assert any("DROP TABLE" in f for f in fnames)
    assert any("\r\n" in f for f in fnames)
    # Long filename should be present.
    assert any(len(f) > 4000 for f in fnames)


def test_build_cases_large_file_off_by_default(upmod):
    cases = upmod.build_cases({"test_large_file": False})
    assert not any(c.category == "dos" for c in cases)
    cases = upmod.build_cases({"test_large_file": True,
                               "test_php": False, "test_asp": False,
                               "test_jsp": False, "test_perl": False,
                               "test_image_polyglot": False,
                               "test_svg": False, "test_xxe": False,
                               "test_pdf": False, "test_zip": False,
                               "test_imagick": False,
                               "test_csv_injection": False,
                               "test_eicar": False,
                               "test_path_traversal": False,
                               "test_shell_metachars": False,
                               "test_edge_cases": False,
                               "test_htaccess": False})
    big = [c for c in cases if c.category == "dos"]
    assert len(big) == 1
    assert len(big[0].content) == 10 * 1024 * 1024


# ============================================================ Stub Context


@dataclass
class _StubResp:
    status: int = 200
    body: bytes = b"ok"
    headers: list = field(default_factory=list)
    error: str = ""


class StubScope:
    def __init__(self, empty=True, in_scope=True):
        self.empty = empty
        self._in = in_scope

    def is_url_in_scope(self, url):
        return self._in


class StubContext:
    """Minimal :class:`PluginContext` substitute. Records every call."""

    def __init__(self, *, settings: dict, sends_iter=None,
                 scope=None, oast=None, oast_interactions_=None,
                 stop_after: int | None = None,
                 seed_request=None):
        self.settings = dict(settings)
        self.scope = scope or StubScope()
        self.logs: list[tuple[str, str]] = []
        self.progress_calls: list[tuple[int, int, str]] = []
        self.results: list[dict] = []
        self.findings: list[dict] = []
        self.sent: list[tuple[str, str, list, bytes]] = []
        self._sends_iter = sends_iter
        self._stop = threading.Event()
        self._stop_after = stop_after
        self._oast = oast  # (token, base) or None
        self._oast_interactions = list(oast_interactions_ or [])
        self.seed_request = seed_request

    # --- runner-facing API ---
    def log(self, msg, level="info"):
        self.logs.append((level, msg))

    def progress(self, done, total=0, message=""):
        self.progress_calls.append((done, total, message))

    def add_result(self, row):
        self.results.append(dict(row))
        if self._stop_after is not None and len(self.results) >= self._stop_after:
            self._stop.set()

    def record_finding(self, **kw):
        self.findings.append(dict(kw))
        return len(self.findings)

    def stop_requested(self):
        return self._stop.is_set()

    def sleep(self, seconds):
        return not self._stop.is_set()

    def oast_token(self):
        return self._oast

    def oast_interactions(self, token):
        return list(self._oast_interactions)

    def send(self, method, url, *, headers=None, body=b"", **kw):
        self.sent.append((method, url, list(headers or []), bytes(body or b"")))
        if self._sends_iter is None:
            return _StubResp()
        try:
            return next(self._sends_iter)
        except StopIteration:
            return _StubResp()


def _all_off_settings(url="http://target.test/upload", **overrides):
    base = {
        "url": url, "method": "POST", "file_field": "file",
        "extra_fields": "", "headers": "", "cookie": "",
        "download_url_template": "",
        "max_cases": 1000, "delay_ms": 0, "timeout_s": 5,
        "oast_settle_s": 0, "use_oast": False, "verify_tls": False,
        "honor_scope": True,
        "test_php": False, "test_asp": False, "test_jsp": False,
        "test_perl": False, "test_python": False, "test_cf": False,
        "test_htaccess": False, "test_image_polyglot": False,
        "test_svg": False, "test_xxe": False, "test_pdf": False,
        "test_zip": False, "test_imagick": False,
        "test_csv_injection": False, "test_eicar": False,
        "test_path_traversal": False, "test_shell_metachars": False,
        "test_edge_cases": False, "test_large_file": False,
    }
    base.update(overrides)
    return base


def _run_plugin(upmod, ctx):
    upmod.PLUGIN_APP.runner_fn(ctx)


# ============================================================ Runner: basics


def test_run_aborts_on_blank_url(upmod):
    ctx = StubContext(settings=_all_off_settings(url=""))
    _run_plugin(upmod, ctx)
    assert ctx.sent == []
    assert any("url is empty" in m for _, m in ctx.logs)


def test_run_aborts_when_baseline_fails(upmod):
    sends = iter([_StubResp(status=0, error="connection refused")])
    ctx = StubContext(settings=_all_off_settings(), sends_iter=sends)
    _run_plugin(upmod, ctx)
    assert len(ctx.sent) == 1
    assert ctx.findings == []
    assert any("baseline request failed" in m for _, m in ctx.logs)


def test_run_records_baseline_and_walks_cases(upmod):
    settings = _all_off_settings(test_eicar=True, test_csv_injection=True)
    sends = iter([_StubResp(status=200, body=b"ok"),
                  _StubResp(status=200, body=b"ok"),
                  _StubResp(status=200, body=b"ok")])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    # baseline + eicar + csv = 3 sends.
    assert len(ctx.sent) == 3
    assert ctx.results[0]["category"] == "baseline"
    assert any(r["category"] == "antivirus" for r in ctx.results)
    assert any(r["category"] == "csv-injection" for r in ctx.results)
    # progress called.
    assert ctx.progress_calls
    assert ctx.progress_calls[0][1] == 3  # total cases


def test_run_honours_scope(upmod):
    ctx = StubContext(
        settings=_all_off_settings(),
        scope=StubScope(empty=False, in_scope=False),
    )
    _run_plugin(upmod, ctx)
    assert ctx.sent == []
    assert any("out of project scope" in m for _, m in ctx.logs)


def test_run_honor_scope_off_overrides(upmod):
    ctx = StubContext(
        settings=_all_off_settings(honor_scope=False),
        scope=StubScope(empty=False, in_scope=False),
        sends_iter=iter([_StubResp()]),
    )
    _run_plugin(upmod, ctx)
    assert ctx.sent  # baseline sent despite scope


def test_run_truncates_to_max_cases(upmod):
    settings = _all_off_settings(test_php=True, test_image_polyglot=True,
                                 max_cases=3)
    sends = iter([_StubResp() for _ in range(3)])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    assert len(ctx.sent) == 3
    assert any("truncating" in m for _, m in ctx.logs)


def test_run_records_finding_on_server_error(upmod):
    settings = _all_off_settings(test_eicar=True)
    sends = iter([
        _StubResp(status=200, body=b"ok"),
        _StubResp(status=500, body=b"oops" * 50),
    ])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    titles = [f["title"] for f in ctx.findings]
    assert any(t.startswith("Upload triggers 500") for t in titles)
    sev = [f["severity"] for f in ctx.findings
           if f["title"].startswith("Upload triggers 500")]
    assert "medium" in sev


def test_run_stop_requested_breaks_loop(upmod):
    settings = _all_off_settings(test_eicar=True, test_csv_injection=True,
                                 test_path_traversal=True,
                                 test_shell_metachars=True,
                                 test_edge_cases=True)
    # Always return ok, but the stub stops itself after the 2nd result.
    sends = iter([_StubResp() for _ in range(200)])
    ctx = StubContext(settings=settings, sends_iter=sends, stop_after=2)
    _run_plugin(upmod, ctx)
    # First result is baseline; second triggers stop.
    assert any("stop requested" in m for _, m in ctx.logs)
    assert len(ctx.results) <= 5  # well under the actual case count


# ============================================================ Runner: oracle


def test_run_redownload_match_marks_stored(upmod):
    """When the re-downloaded body == upload content, verdict is
    'stored' and a finding is filed."""
    settings = _all_off_settings(
        test_eicar=True,
        download_url_template="http://target.test/files/{basename}",
    )
    # baseline -> 200 ok; eicar upload -> 200 ok; eicar redownload -> body match.
    eicar_bytes = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    sends = iter([
        _StubResp(status=200, body=b"ok"),                   # baseline
        _StubResp(status=200, body=b"ok"),                   # eicar upload
        _StubResp(status=200, body=eicar_bytes),             # eicar redownload
    ])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    eicar_results = [r for r in ctx.results if r["category"] == "antivirus"]
    assert eicar_results and eicar_results[0]["verdict"] == "stored"
    assert any(f["title"] == "Upload accepted: eicar"
               for f in ctx.findings)


def test_run_rce_marker_in_redownload_marks_critical(upmod, monkeypatch):
    """If the redownloaded body contains the RCE marker, the finding
    is marked critical regardless of the case's nominal severity."""
    # Pin secrets.token_hex inside the plugin module so the marker is
    # deterministic for this test (otherwise we can't pre-compute the
    # body the redownload should return).
    monkeypatch.setattr(upmod.secrets, "token_hex",
                        lambda n=8: "deadbeefcafebabe"[:n * 2])
    marker = upmod._RCE_MARKER_PREFIX + "deadbeefcafebabe"
    settings = _all_off_settings(
        test_php=True, max_cases=2,
        download_url_template="http://target.test/files/{basename}",
    )
    sends = iter([
        _StubResp(status=200, body=b"ok"),                          # baseline
        _StubResp(status=200, body=b"ok"),                          # php upload
        _StubResp(status=200,
                  body=f"{marker} Linux server01 5.4 ...".encode()),  # redownload
    ])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    # The PHP case verdict is RCE-confirmed.
    php = [r for r in ctx.results if r["category"] == "executor:php"]
    assert php and php[0]["verdict"] == "RCE-confirmed"
    # A critical finding was filed.
    crit = [f for f in ctx.findings if f["severity"] == "critical"]
    assert crit
    assert any("Remote code execution" in f["title"] for f in crit)


def test_run_extra_fields_and_headers_propagate(upmod):
    settings = _all_off_settings(
        test_eicar=True,
        extra_fields="csrf=abc\nkind=avatar\n# comment\n",
        headers="X-Custom: 1\nAuthorization: Bearer xyz",
        cookie="session=eyJ",
    )
    sends = iter([_StubResp() for _ in range(5)])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    method, url, headers, body = ctx.sent[0]
    # Cookie + custom + Authorization all present.
    keys = [k.lower() for k, _ in headers]
    assert "cookie" in keys
    assert "x-custom" in keys
    assert "authorization" in keys
    # Multipart contains the extra form fields.
    assert b'name="csrf"' in body
    assert b"abc" in body
    assert b'name="kind"' in body


def test_run_put_method_sends_raw_body(upmod):
    settings = _all_off_settings(method="PUT", test_eicar=True)
    sends = iter([_StubResp() for _ in range(3)])
    ctx = StubContext(settings=settings, sends_iter=sends)
    _run_plugin(upmod, ctx)
    method, url, headers, body = ctx.sent[0]
    assert method == "PUT"
    # Body is the file content itself (PNG signature), not multipart.
    assert body.startswith(b"\x89PNG")
    cts = [v for k, v in headers if k.lower() == "content-type"]
    assert cts == ["image/png"]


# ============================================================ Runner: OAST


def test_run_files_oast_finding_for_matched_tag(upmod):
    """When the OAST listener observes a callback whose path carries a
    case tag, a high-severity finding for that case is filed."""
    settings = _all_off_settings(
        test_svg=True, use_oast=True, oast_settle_s=0,
    )
    # baseline + svg-xss + svg-ssrf + svg-xxe-oast + svg-xxe-file
    sends = iter([_StubResp() for _ in range(10)])
    interaction = type("IX", (), {
        "kind": "http", "remote": "10.0.0.5",
        "path": "/tok/svg-ssrf/probe.png",
    })()
    ctx = StubContext(
        settings=settings, sends_iter=sends,
        oast=("tok", "http://oast.test/tok/"),
        oast_interactions_=[interaction],
    )
    _run_plugin(upmod, ctx)
    oast_findings = [f for f in ctx.findings
                     if f["title"].startswith("OAST callback")]
    assert oast_findings
    assert "svg-ssrf" in oast_findings[0]["title"]
    assert oast_findings[0]["severity"] == "high"


def test_run_oast_unmatched_tag_silently_ignored(upmod):
    """An OAST interaction for an unknown tag must not produce a
    finding (could be unrelated traffic)."""
    settings = _all_off_settings(
        test_svg=True, use_oast=True, oast_settle_s=0,
    )
    sends = iter([_StubResp() for _ in range(10)])
    interaction = type("IX", (), {
        "kind": "http", "remote": "10.0.0.5",
        "path": "/tok/unrelated/x", "method": "GET"
    })()
    ctx = StubContext(
        settings=settings, sends_iter=sends,
        oast=("tok", "http://oast.test/tok/"),
        oast_interactions_=[interaction],
    )
    _run_plugin(upmod, ctx)
    assert not any(f["title"].startswith("OAST callback")
                   for f in ctx.findings)


def test_run_logs_warning_when_oast_unavailable(upmod):
    settings = _all_off_settings(test_svg=True, use_oast=True)
    sends = iter([_StubResp() for _ in range(10)])
    ctx = StubContext(settings=settings, sends_iter=sends, oast=None)
    _run_plugin(upmod, ctx)
    assert any("OAST listener not running" in m for _, m in ctx.logs)


# ============================================================ Discovery


def test_default_plugin_dirs_includes_builtin():
    dirs = default_plugin_dirs()
    assert any(d.name == "builtin_plugins" for d in dirs)


def test_registry_discovers_file_upload_scanner_out_of_box(tmp_path):
    """With the default search path, the bundled plugin is found and
    exposes a runnable PluginApp."""
    reset_registry()
    reg = get_registry(default_plugin_dirs())
    slugs = {a.slug for a in reg.active_plugin_apps()}
    assert "file-upload-scanner" in slugs
    app = reg.get_plugin_app("file-upload-scanner")
    assert app is not None
    assert app.is_runnable()
    # Sanity: the form has a settings field for every major toggle.
    names = {f.name for f in app.fields}
    for must in ("url", "method", "file_field", "extra_fields", "headers",
                 "download_url_template", "use_oast", "test_php",
                 "test_asp", "test_jsp", "test_svg", "test_xxe",
                 "test_pdf", "test_zip", "test_imagick",
                 "test_csv_injection", "test_eicar",
                 "test_path_traversal", "test_shell_metachars",
                 "test_edge_cases", "test_large_file", "honor_scope",
                 "verify_tls", "max_cases", "delay_ms", "timeout_s"):
        assert must in names, f"missing field {must!r}"
    reset_registry()


def test_registry_validates_default_settings(tmp_path):
    """The plugin's defaults form a self-consistent settings dict that
    passes validation (only ``url`` is required)."""
    reset_registry()
    reg = get_registry(default_plugin_dirs())
    app = reg.get_plugin_app("file-upload-scanner")
    raw = {f.name: f.default for f in app.fields}
    raw["url"] = "https://target.test/upload"
    # Empty strings for blank optional fields must validate without
    # raising. (BoolField defaults are bools — keep them as-is.)
    for f in app.fields:
        if f.kind == "bool":
            continue
        if raw.get(f.name) is None:
            raw[f.name] = ""
    normalised = app.validate_settings(raw)
    assert normalised["url"] == "https://target.test/upload"
    assert normalised["method"] in ("POST", "PUT")
    reset_registry()


# ============================================================ Seed derivation
#
# When the operator launched the plugin via "Send to plugin app" from
# History or a Proxy intercept, ``ctx.seed_request`` carries the raw
# captured request. The runner extracts cookie / headers / multipart
# parts and pre-fills the matching settings ONLY when the operator
# left them blank.


def _seed(method="POST", url="http://target.test/upload",
          headers=None, body=b"", history_id=42):
    return sdk.parse_seed_request(
        history_id,
        _make_raw_request(method, url, headers or [], body),
    )


def _make_raw_request(method, url, headers, body):
    from urllib.parse import urlparse
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def _multipart_body(boundary, parts):
    """parts = [(name, filename_or_None, content_type_or_None, payload_bytes)]"""
    crlf = b"\r\n"
    out = io.BytesIO()
    for name, filename, ctype, payload in parts:
        out.write(b"--" + boundary.encode() + crlf)
        cd = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            cd += f'; filename="{filename}"'
        out.write(cd.encode() + crlf)
        if ctype is not None:
            out.write(f"Content-Type: {ctype}".encode() + crlf)
        out.write(crlf)
        out.write(payload)
        out.write(crlf)
    out.write(b"--" + boundary.encode() + b"--" + crlf)
    return out.getvalue()


def test_parse_multipart_seed_body_extracts_file_field(upmod):
    boundary = "BoUnDaRy123"
    body = _multipart_body(boundary, [
        ("csrf", None, None, b"tok123"),
        ("kind", None, None, b"avatar"),
        ("avatar", "cat.png", "image/png", b"\x89PNG\r\n\x1a\nfake"),
    ])
    res = upmod._parse_multipart_seed_body(
        f"multipart/form-data; boundary={boundary}", body,
    )
    assert res is not None
    ff, extras = res
    assert ff == "avatar"
    assert ("csrf", "tok123") in extras
    assert ("kind", "avatar") in extras


def test_parse_multipart_seed_body_skips_binary_extras(upmod):
    boundary = "B2"
    body = _multipart_body(boundary, [
        ("blob", None, None, b"hello\x00world"),  # NUL -> drop
        ("ok", None, None, b"plain"),
    ])
    res = upmod._parse_multipart_seed_body(
        f"multipart/form-data; boundary={boundary}", body,
    )
    assert res is not None
    _, extras = res
    assert ("ok", "plain") in extras
    assert all(k != "blob" for k, _ in extras)


def test_parse_multipart_seed_body_returns_none_for_non_multipart(upmod):
    assert upmod._parse_multipart_seed_body(
        "application/json", b"{}",
    ) is None
    assert upmod._parse_multipart_seed_body("", b"x") is None


def test_parse_multipart_seed_body_returns_none_when_boundary_missing(upmod):
    assert upmod._parse_multipart_seed_body(
        "multipart/form-data", b"--x--",
    ) is None


def test_parse_multipart_seed_body_handles_quoted_boundary(upmod):
    boundary = "Quoted-B"
    body = _multipart_body(boundary, [
        ("a", None, None, b"1"),
        ("f", "x.bin", "application/octet-stream", b"\x00\x01"),
    ])
    res = upmod._parse_multipart_seed_body(
        f'multipart/form-data; boundary="{boundary}"', body,
    )
    assert res is not None
    ff, extras = res
    assert ff == "f"
    assert ("a", "1") in extras


def test_parse_multipart_seed_body_first_file_part_wins(upmod):
    boundary = "Two-Files"
    body = _multipart_body(boundary, [
        ("primary", "a.png", "image/png", b"AAA"),
        ("secondary", "b.png", "image/png", b"BBB"),
    ])
    res = upmod._parse_multipart_seed_body(
        f"multipart/form-data; boundary={boundary}", body,
    )
    assert res is not None
    ff, _ = res
    assert ff == "primary"


def test_derive_headers_allowlists_and_blocks(upmod):
    seed = _seed(headers=[
        ("Authorization", "Bearer abc"),
        ("X-CSRF-Token", "tok"),
        ("X-Foo", "bar"),
        ("Content-Length", "0"),
        ("Content-Type", "multipart/form-data; boundary=x"),
        ("Cookie", "s=1"),
        ("Connection", "close"),
        ("Host", "target.test"),
    ])
    hdrs = upmod._derive_headers_from_seed(seed)
    names = [k for k, _ in hdrs]
    assert "Authorization" in names
    assert "X-CSRF-Token" in names
    assert "X-Foo" in names  # x-* fall-through allowlist
    assert "Cookie" not in names
    assert "Host" not in names
    assert "Content-Length" not in names
    assert "Content-Type" not in names
    assert "Connection" not in names


def test_derive_headers_dedupes_case_insensitively(upmod):
    seed = _seed(headers=[
        ("X-Foo", "first"),
        ("x-foo", "second"),
    ])
    hdrs = upmod._derive_headers_from_seed(seed)
    assert hdrs == [("X-Foo", "first")]


def test_apply_seed_overrides_fills_cookie_when_blank(upmod):
    seed = _seed(headers=[("Cookie", "session=eyJ")])
    s = _all_off_settings()
    s["cookie"] = ""
    logs: list = []
    out = upmod._apply_seed_overrides(s, seed, lambda m, lvl="info": logs.append((lvl, m)))
    assert out["cookie"] == "session=eyJ"
    assert any("cookie" in m for _, m in logs)


def test_apply_seed_overrides_preserves_operator_cookie(upmod):
    seed = _seed(headers=[("Cookie", "from-seed=1")])
    s = _all_off_settings()
    s["cookie"] = "operator=wins"
    out = upmod._apply_seed_overrides(s, seed, None)
    assert out["cookie"] == "operator=wins"


def test_apply_seed_overrides_fills_headers_when_blank(upmod):
    seed = _seed(headers=[
        ("Authorization", "Bearer xyz"),
        ("X-CSRF", "tok123"),
    ])
    s = _all_off_settings()
    out = upmod._apply_seed_overrides(s, seed, None)
    lines = out["headers"].splitlines()
    assert "Authorization: Bearer xyz" in lines
    assert "X-CSRF: tok123" in lines


def test_apply_seed_overrides_preserves_operator_headers(upmod):
    seed = _seed(headers=[("X-Foo", "from-seed")])
    s = _all_off_settings(headers="X-Bar: from-operator")
    out = upmod._apply_seed_overrides(s, seed, None)
    assert out["headers"] == "X-Bar: from-operator"


def test_apply_seed_overrides_fills_file_field_from_multipart(upmod):
    boundary = "B3"
    body = _multipart_body(boundary, [
        ("csrf", None, None, b"t"),
        ("photo", "cat.png", "image/png", b"\x89PNGfake"),
    ])
    seed = _seed(
        headers=[("Content-Type", f"multipart/form-data; boundary={boundary}")],
        body=body,
    )
    s = _all_off_settings()  # file_field default is "file"
    out = upmod._apply_seed_overrides(s, seed, None)
    assert out["file_field"] == "photo"
    assert "csrf=t" in out["extra_fields"].splitlines()


def test_apply_seed_overrides_preserves_operator_file_field(upmod):
    boundary = "B4"
    body = _multipart_body(boundary, [
        ("upload", "x.png", "image/png", b"\x89PNGfake"),
    ])
    seed = _seed(
        headers=[("Content-Type", f"multipart/form-data; boundary={boundary}")],
        body=body,
    )
    s = _all_off_settings(file_field="theirs")
    out = upmod._apply_seed_overrides(s, seed, None)
    assert out["file_field"] == "theirs"


def test_apply_seed_overrides_preserves_operator_extra_fields(upmod):
    boundary = "B5"
    body = _multipart_body(boundary, [
        ("csrf", None, None, b"seed"),
        ("f", "x.png", "image/png", b"P"),
    ])
    seed = _seed(
        headers=[("Content-Type", f"multipart/form-data; boundary={boundary}")],
        body=body,
    )
    s = _all_off_settings(extra_fields="my=field")
    out = upmod._apply_seed_overrides(s, seed, None)
    assert out["extra_fields"] == "my=field"


def test_apply_seed_overrides_no_seed_returns_copy(upmod):
    s = _all_off_settings()
    out = upmod._apply_seed_overrides(s, None, None)
    assert out == s
    assert out is not s  # always returns a new dict


def test_apply_seed_overrides_malformed_body_does_not_raise(upmod):
    seed = _seed(
        headers=[("Content-Type", "multipart/form-data; boundary=Z")],
        body=b"this is not a real multipart body",
    )
    s = _all_off_settings()
    out = upmod._apply_seed_overrides(s, seed, None)
    # No file_field / extra_fields derivation possible, but cookie
    # and headers blocks should still run cleanly.
    assert out["file_field"] == "file"
    assert out["extra_fields"] == ""


def test_apply_seed_overrides_logs_summary_once(upmod):
    seed = _seed(headers=[
        ("Cookie", "s=1"),
        ("Authorization", "Bearer t"),
    ])
    logs: list = []
    out = upmod._apply_seed_overrides(
        _all_off_settings(), seed,
        lambda m, lvl="info": logs.append((lvl, m)),
    )
    assert out["cookie"] == "s=1"
    assert "Authorization: Bearer t" in out["headers"]
    seed_logs = [m for _, m in logs if m.startswith("seed#")]
    assert len(seed_logs) == 1
    assert "cookie" in seed_logs[0]
    assert "headers" in seed_logs[0]


def test_run_consumes_seed_request_end_to_end(upmod):
    """Full runner exercise: a captured upload seed becomes the
    cookie / headers / file_field / extra_fields without the operator
    touching the form."""
    boundary = "EndToEnd-B"
    body = _multipart_body(boundary, [
        ("csrf", None, None, b"abc123"),
        ("avatar", "me.png", "image/png", b"\x89PNGfake"),
    ])
    seed = _seed(
        headers=[
            ("Cookie", "session=eyJsess"),
            ("Authorization", "Bearer tk"),
            ("Content-Type", f"multipart/form-data; boundary={boundary}"),
        ],
        body=body,
    )
    settings = _all_off_settings(test_eicar=True)
    ctx = StubContext(settings=settings, sends_iter=iter([
        _StubResp(status=200, body=b"ok"),
        _StubResp(status=200, body=b"ok"),
    ]), seed_request=seed)
    _run_plugin(upmod, ctx)
    # First send must be the baseline; check its headers + body shape.
    assert len(ctx.sent) >= 1
    _, _, headers, body_sent = ctx.sent[0]
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers)
    assert "Cookie: session=eyJsess" in header_blob
    assert "Authorization: Bearer tk" in header_blob
    ct_line = next((v for k, v in headers if k.lower() == "content-type"), "")
    assert ct_line.startswith("multipart/form-data;")
    # Body must carry the operator's file_field name (avatar) and
    # the captured CSRF field.
    assert b'name="avatar"' in body_sent
    assert b'name="csrf"' in body_sent
    assert b"abc123" in body_sent
