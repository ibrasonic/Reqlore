"""Per-project encryption for stored session payloads.

Threat model
------------

The ``.rlr`` project file lives on disk next to anything else the
operator stores; an attacker who can read the file can decrypt the
payloads too. The encryption here only protects against:

* Accidental disclosure (e.g. the project file is shared without
  realising it contains live tokens / cookies).
* Casual inspection of the SQLite file with ``sqlite3 my.rlr``.

It is **not** a substitute for filesystem permissions. A future
revision can opt-in to a passphrase-derived key for stronger
isolation; the on-disk format reserves a 1-byte version prefix to
make that upgrade non-breaking.

On-disk format
--------------

Each ``payload_blob`` is::

    version (1 byte)  ||  nonce (12 bytes)  ||  ciphertext + tag

with version ``0x01`` reserved for the random-key ChaCha20-Poly1305
scheme. Version ``0x00`` denotes a plaintext payload — only used for
operator-initiated "I have no secrets to hide" sessions (e.g. an
``anon`` identity whose payload is the empty string) so we don't
waste a nonce on nothing.
"""
from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from typing import Any

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    ChaCha20Poly1305: type[Any] | None = None  # type: ignore[no-redef,assignment]  # optional dep fallback
    _HAS_CRYPTO = False


_VERSION_PLAINTEXT = 0x00
_VERSION_CHACHA = 0x01
_NONCE_LEN = 12
_KEY_LEN = 32
_KEY_STATE_KEY = "auth_matrix:key_v1"


@dataclass(frozen=True)
class ProjectKey:
    """Wraps the 32-byte symmetric key used for an open project.

    Constructed once per :class:`reqlore.storage.Project` lifetime
    via :func:`derive_or_load_key`. Callers should not log it.
    """

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, (bytes, bytearray)):
            raise TypeError("ProjectKey.raw must be bytes")
        if len(self.raw) != _KEY_LEN:
            raise ValueError(
                f"ProjectKey.raw must be {_KEY_LEN} bytes, got {len(self.raw)}"
            )

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"ProjectKey(len={_KEY_LEN}, fingerprint={self.fingerprint()})"

    def fingerprint(self) -> str:
        """First 8 base32 chars of the key — for log correlation only.

        Knowing the fingerprint does not help an attacker recover the
        key; it only helps an operator confirm two processes agree on
        the same project key (e.g. when the shadow worker restarts).
        """
        b32 = base64.b32encode(self.raw).decode("ascii").rstrip("=")
        return b32[:8]


def _generate_raw_key() -> bytes:
    return secrets.token_bytes(_KEY_LEN)


def derive_or_load_key(project: Any) -> ProjectKey:
    """Return the project's symmetric key, generating one on first use.

    The key is stored in the ``project_state`` table under
    :data:`_KEY_STATE_KEY` as base64. Concurrent first-use is safe:
    SQLite serialises the writes and the second writer notices the
    first one's value on its re-read.
    """
    raw_b64 = project.get_state(_KEY_STATE_KEY, "") or ""
    if raw_b64:
        try:
            raw = base64.b64decode(raw_b64.encode("ascii"), validate=True)
        except Exception:
            raw = b""
        if len(raw) == _KEY_LEN:
            return ProjectKey(raw=raw)
    raw = _generate_raw_key()
    project.set_state(
        _KEY_STATE_KEY,
        base64.b64encode(raw).decode("ascii"),
    )
    # Re-read in case a concurrent caller wrote first.
    settled = project.get_state(_KEY_STATE_KEY, "") or ""
    try:
        final = base64.b64decode(settled.encode("ascii"), validate=True)
    except Exception:
        final = raw
    if len(final) != _KEY_LEN:
        final = raw
    return ProjectKey(raw=final)


def encrypt_payload(key: ProjectKey, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` under ``key``. Empty input round-trips as
    a versioned plaintext frame so we do not waste a nonce on nothing.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    pt = bytes(plaintext)
    if not pt:
        return bytes([_VERSION_PLAINTEXT])
    if not _HAS_CRYPTO:
        # Fallback: store as versioned plaintext. The schema still
        # accepts it, but the operator should know.
        return bytes([_VERSION_PLAINTEXT]) + pt
    nonce = os.urandom(_NONCE_LEN)
    aead = ChaCha20Poly1305(key.raw)
    ct = aead.encrypt(nonce, pt, associated_data=None)
    return bytes([_VERSION_CHACHA]) + nonce + ct


def decrypt_payload(key: ProjectKey, blob: bytes) -> bytes:
    """Inverse of :func:`encrypt_payload`.

    Raises ``ValueError`` on unknown version, truncated blob, or AEAD
    tag mismatch.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 1:
        raise ValueError("blob is empty or wrong type")
    buf = bytes(blob)
    ver = buf[0]
    if ver == _VERSION_PLAINTEXT:
        return buf[1:]
    if ver == _VERSION_CHACHA:
        if not _HAS_CRYPTO:
            raise ValueError(
                "cryptography is not installed; cannot decrypt v1 payload"
            )
        if len(buf) < 1 + _NONCE_LEN + 16:
            raise ValueError("v1 payload too short")
        nonce = buf[1:1 + _NONCE_LEN]
        ct = buf[1 + _NONCE_LEN:]
        aead = ChaCha20Poly1305(key.raw)
        return aead.decrypt(nonce, ct, associated_data=None)
    raise ValueError(f"unknown payload version: {ver}")
