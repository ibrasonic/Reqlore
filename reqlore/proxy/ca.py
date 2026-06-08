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


def _harden_perms(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows: ACLs are managed elsewhere; skipping silently is fine.
        pass


def ensure_ca(ca_dir: Path) -> tuple[Path, Path]:
    """Make sure a CA exists in `ca_dir`. Returns (cert_pem_path, key_pem_path)."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_path = ca_dir / "reqlore-ca.pem"
    key_path = ca_dir / "reqlore-ca.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    # Lazy import so people who never start the proxy don't pay the cost.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Reqlore Local Root CA"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Reqlore"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365 * 5))
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
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _harden_perms(key_path)
    return cert_path, key_path
