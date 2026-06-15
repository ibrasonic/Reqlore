"""Package the DOM Hunter WebExtension into an XPI for auto-install.

The XPI is a plain ZIP of the extension source folder. We use it together
with Firefox's enterprise ``ExtensionSettings`` policy (set in
:mod:`reqlore.browser`) to force-install the extension into Reqlore's
managed profile. ``force_installed`` add-ons are exempt from Mozilla's
signing requirement, which is exactly what we want for a self-hosted
defensive-testing tool that the operator already trusts.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

# Files we never want in the shipped XPI.
_SKIP_TOP_LEVEL = {"tests", "README.md"}


def find_extension_source() -> Path | None:
    """Locate the DOM Hunter extension source folder on disk.

    Returns:
        Absolute path to the extension source directory, or ``None`` if
        not found. We look in two places, in order:
        1. ``<reqlore-package>/dom_hunter/extension/`` (the shipped
           location — works for any pip / pipx install).
        2. ``<repo>/extensions/dom-hunter/`` (legacy dev layout, kept
           for back-compat with older checkouts).
    """
    here = Path(__file__).resolve()
    # Preferred: packaged-as-data copy next to this module.
    packaged = here.parent / "extension"
    if (packaged / "manifest.json").exists():
        return packaged
    # Fallback: legacy repo-level extensions dir.
    for ancestor in (here.parent, here.parent.parent, here.parent.parent.parent,
                     here.parent.parent.parent.parent):
        candidate = ancestor / "extensions" / "dom-hunter"
        if (candidate / "manifest.json").exists():
            return candidate
    return None


def build_xpi(*, out_path: Path, src_dir: Path | None = None) -> Path:
    """Zip the extension source into a deterministic XPI at ``out_path``.

    The XPI contains every file under ``src_dir`` except the top-level
    ``tests/`` folder and ``README.md`` (neither is needed at runtime).
    Existing files at ``out_path`` are overwritten.

    Raises:
        FileNotFoundError: if ``src_dir`` is not given and the extension
            source cannot be located via :func:`find_extension_source`.
    """
    src = src_dir or find_extension_source()
    if src is None:
        raise FileNotFoundError(
            "DOM Hunter extension source not found. Looked under "
            "<reqlore-package>/dom_hunter/extension/ and "
            "<repo>/extensions/dom-hunter/."
        )
    if not src.is_dir():
        raise FileNotFoundError(
            f"DOM Hunter extension source is not a directory: {src}"
        )
    if not (src / "manifest.json").is_file():
        raise FileNotFoundError(
            f"DOM Hunter source is missing manifest.json: {src}"
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(src.rglob("*")):
            if not f.is_file():
                continue
            rel = f.relative_to(src)
            if rel.parts and rel.parts[0] in _SKIP_TOP_LEVEL:
                continue
            zf.write(f, arcname=str(rel).replace("\\", "/"))
    return out_path
