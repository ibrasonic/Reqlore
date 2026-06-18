"""Certificate Authority for the MITM proxy.

We delegate the actual signing to mitmproxy's certificate machinery, but
expose a simple façade that:

* Creates the CA on first run, under `~/.reqlore/ca/` with 0600 perms.
* Returns the public PEM + DER so the UI can offer "Download CA cert".
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .._secret_file import secret_write_bytes


def _harden_perms(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows: ACLs are managed elsewhere; skipping silently is fine.
        pass


def _ensure_mitmproxy_ca_link(ca_dir: Path,
                              cert_path: Path, key_path: Path) -> Path:
    # mitmproxy reads ``<confdir>/mitmproxy-ca.pem`` (PKCS8 key + cert in
    # one PEM) at startup and silently auto-generates its own CA when the
    # file is absent. That stray CA then signs every forged leaf, but
    # Firefox only trusts the Reqlore CA installed via policies.json, so
    # HSTS sites refuse to load. Mirror our CA into mitmproxy's expected
    # path so the chain validates without manual cert imports.
    combined = ca_dir / "mitmproxy-ca.pem"
    desired = key_path.read_bytes() + cert_path.read_bytes()
    try:
        if combined.exists() and combined.read_bytes() == desired:
            return combined
    except OSError:
        pass
    secret_write_bytes(combined, desired)
    _harden_perms(combined)
    return combined


def ensure_ca(ca_dir: Path) -> tuple[Path, Path]:
    """Make sure a CA exists in `ca_dir`. Returns (cert_pem_path, key_pem_path)."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_path = ca_dir / "reqlore-ca.pem"
    key_path = ca_dir / "reqlore-ca.key"
    if cert_path.exists() and key_path.exists():
        _ensure_mitmproxy_ca_link(ca_dir, cert_path, key_path)
        return cert_path, key_path

    # M-1: new CAs use ECDSA-P256 with a 13-month validity window.
    # ECDSA matches modern CAB Forum guidance and reduces the blast
    # radius if the key ever leaks; 13 months matches public-CA
    # leaf-certificate lifetimes so an old leaked key cannot keep
    # serving for years. Existing on-disk CAs are short-circuited
    # at the top of this function, so users who already imported a
    # 5-year RSA root keep working without surprise re-imports.
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    # M-2: allow operators to override the CA Common Name (e.g. when
    # multiple Reqlore installations co-exist on a shared lab box).
    common_name = (os.environ.get("REQLORE_CA_CN") or "").strip() \
        or "Reqlore Local Root CA"
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Reqlore"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=397))  # 13 months
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # H-2: the CA private key must never exist on disk world-readable,
    # not even for a single scheduler tick. ``secret_write_bytes`` opens
    # the file with mode 0o600 atomically (no TOCTOU between the write
    # and a follow-up chmod). ``_harden_perms`` is kept as a final
    # belt-and-braces guard.
    secret_write_bytes(key_path, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _harden_perms(key_path)
    _ensure_mitmproxy_ca_link(ca_dir, cert_path, key_path)
    return cert_path, key_path
