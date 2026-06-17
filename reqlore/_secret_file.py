"""Atomic owner-only file writes for secrets (CA keys, tokens, hashes).

Avoids the TOCTOU window between ``Path.write_bytes`` (which honours the
process umask, often 0o022 -> world-readable) and a follow-up ``chmod
0o600``. A second local user racing the directory can read the file
during that window. ``secret_write_bytes`` creates the file with the
restrictive permission already applied via ``os.open(..., 0o600)``.

On Windows POSIX-style modes are ignored by the OS but the call still
succeeds; ACL hardening is the OS responsibility there. Documenting
this is intentional: the function returns the same path on every
platform so callers do not branch.
"""
from __future__ import annotations

import os
from pathlib import Path


def secret_write_bytes(path: Path, data: bytes) -> Path:
    """Write ``data`` to ``path`` with mode 0o600 from the moment of creation.

    Overwrites any existing file at the same location. Honours the
    parent directory; create it first if it does not exist.
    """
    p = Path(path)
    # ``O_WRONLY|O_CREAT|O_TRUNC`` matches the semantics of
    # ``Path.write_bytes`` but lets us pass the mode atomically.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    # ``O_NOFOLLOW`` (POSIX) refuses to write through a pre-existing
    # symlink at ``path`` — closes a symlink-attack TOCTOU on the
    # secret path itself.
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(p), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    # Defence-in-depth: on POSIX systems chmod even though we opened
    # with 0o600, in case an unusual umask interfered. Cheap and
    # idempotent.
    try:
        os.chmod(str(p), 0o600)
    except OSError:
        # Windows: ACLs are managed by the OS; chmod is a no-op there.
        pass
    return p


def secret_write_text(path: Path, text: str, encoding: str = "utf-8") -> Path:
    """Like :func:`secret_write_bytes` but accepts text."""
    return secret_write_bytes(path, text.encode(encoding))
