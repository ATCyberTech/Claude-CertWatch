"""Generates the M1 certificate-parsing test fixtures (Section 22).

Run once to (re)populate this directory:

    python tests/fixtures/certs/generate_fixtures.py

Fixtures are checked into the repo as static .pem/.der files rather than
regenerated at test-collection time, so:
  - tests are fast and don't pay RSA keygen cost on every run
  - fixture content is stable and reviewable in diffs
  - "expired" fixtures stay expired forever (not_after is baked in)

This script is a test-support tool, not part of the shipped application.
Nothing under app/ imports it.

Trust model used by the tests: `root_public.pem` stands in for a
publicly-trusted root (like one in the real certifi bundle) — tests pass
it explicitly as `trust_roots` to `parse_certificate_chain`, so M1 tests
never depend on real, live public CAs. `root_private.pem` /
`root_alt.pem` are never in that trust_roots list, simulating private/
internal or otherwise-untrusted CAs.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import asn1crypto.algos as algos
import asn1crypto.x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES_DIR = Path(__file__).parent

NOW = datetime.datetime.now(datetime.UTC)
FAR_FUTURE = NOW + datetime.timedelta(days=3650)
PAST_EXPIRY = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
PAST_START = datetime.datetime(2019, 1, 1, tzinfo=datetime.UTC)


def make_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def make_cert(
    subject_cn: str,
    issuer_cn: str,
    subject_public_key,
    issuer_key: rsa.RSAPrivateKey,
    *,
    is_ca: bool = False,
    path_length: int | None = None,
    sans: list | None = None,
    not_before: datetime.datetime = NOW - datetime.timedelta(days=1),
    not_after: datetime.datetime = FAR_FUTURE,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None),
            critical=True,
        )
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def write_pem(cert: x509.Certificate, name: str) -> None:
    (FIXTURES_DIR / name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    # --- Public CA lineage (stands in for a "certifi-trusted" root in tests) ---
    root_public_key = make_key()
    root_public = make_cert(
        "CertWatch Test Public Root",
        "CertWatch Test Public Root",
        root_public_key.public_key(),
        root_public_key,
        is_ca=True,
        path_length=2,
    )
    write_pem(root_public, "root_public.pem")

    intermediate_public_key = make_key()
    intermediate_public = make_cert(
        "CertWatch Test Public Intermediate",
        "CertWatch Test Public Root",
        intermediate_public_key.public_key(),
        root_public_key,
        is_ca=True,
        path_length=0,
    )
    write_pem(intermediate_public, "intermediate_public.pem")

    # Category 2: valid chain to a (test-)public trusted root
    leaf_valid_key = make_key()
    leaf_valid = make_cert(
        "valid.example.com",
        "CertWatch Test Public Intermediate",
        leaf_valid_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("valid.example.com")],
    )
    write_pem(leaf_valid, "leaf_valid_public_ca.pem")

    # Expired, otherwise identical lineage
    leaf_expired_key = make_key()
    leaf_expired = make_cert(
        "expired.example.com",
        "CertWatch Test Public Intermediate",
        leaf_expired_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("expired.example.com")],
        not_before=PAST_START,
        not_after=PAST_EXPIRY,
    )
    write_pem(leaf_expired, "leaf_expired.pem")

    # Category 1: genuinely self-signed leaf (subject == issuer, self-verifying)
    leaf_selfsigned_key = make_key()
    leaf_selfsigned = make_cert(
        "selfsigned.example.com",
        "selfsigned.example.com",
        leaf_selfsigned_key.public_key(),
        leaf_selfsigned_key,
        sans=[x509.DNSName("selfsigned.example.com")],
    )
    write_pem(leaf_selfsigned, "leaf_self_signed.pem")

    # Category 3: correctly-built private/internal CA chain (root never in trust_roots)
    root_private_key = make_key()
    root_private = make_cert(
        "CertWatch Test Private Root",
        "CertWatch Test Private Root",
        root_private_key.public_key(),
        root_private_key,
        is_ca=True,
        path_length=2,
    )
    write_pem(root_private, "root_private.pem")

    intermediate_private_key = make_key()
    intermediate_private = make_cert(
        "CertWatch Test Private Intermediate",
        "CertWatch Test Private Root",
        intermediate_private_key.public_key(),
        root_private_key,
        is_ca=True,
        path_length=0,
    )
    write_pem(intermediate_private, "intermediate_private.pem")

    leaf_private_ca_key = make_key()
    leaf_private_ca = make_cert(
        "internal.example",
        "CertWatch Test Private Intermediate",
        leaf_private_ca_key.public_key(),
        intermediate_private_key,
        sans=[x509.DNSName("internal.example")],
    )
    write_pem(leaf_private_ca, "leaf_private_ca.pem")

    # Category 4: broken chain — leaf's issuer intermediate is never presented/available
    orphan_intermediate_key = make_key()
    # The orphan intermediate certificate itself is never written to disk or
    # kept — only its key is used to sign the leaf below. That is the point
    # of this fixture: the leaf's issuer is never presented/available.
    make_cert(
        "Orphan Intermediate (never presented)",
        "CertWatch Test Public Root",
        orphan_intermediate_key.public_key(),
        root_public_key,
        is_ca=True,
        path_length=0,
    )
    leaf_broken_key = make_key()
    leaf_broken = make_cert(
        "broken.example.com",
        "Orphan Intermediate (never presented)",
        leaf_broken_key.public_key(),
        orphan_intermediate_key,
        sans=[x509.DNSName("broken.example.com")],
    )
    write_pem(leaf_broken, "leaf_broken_chain.pem")

    # Cross-signed intermediate / alternate path: same key, two issuers, only one trusted
    root_alt_key = make_key()
    root_alt = make_cert(
        "CertWatch Test Alt Root (untrusted)",
        "CertWatch Test Alt Root (untrusted)",
        root_alt_key.public_key(),
        root_alt_key,
        is_ca=True,
        path_length=2,
    )
    write_pem(root_alt, "root_alt_untrusted.pem")

    shared_intermediate_key = make_key()
    intermediate_cross_by_public = make_cert(
        "CertWatch Test Cross Intermediate",
        "CertWatch Test Public Root",
        shared_intermediate_key.public_key(),
        root_public_key,
        is_ca=True,
        path_length=0,
    )
    write_pem(intermediate_cross_by_public, "intermediate_cross_by_public.pem")
    intermediate_cross_by_alt = make_cert(
        "CertWatch Test Cross Intermediate",
        "CertWatch Test Alt Root (untrusted)",
        shared_intermediate_key.public_key(),
        root_alt_key,
        is_ca=True,
        path_length=0,
    )
    write_pem(intermediate_cross_by_alt, "intermediate_cross_by_alt.pem")

    leaf_cross_key = make_key()
    leaf_cross = make_cert(
        "cross.example.com",
        "CertWatch Test Cross Intermediate",
        leaf_cross_key.public_key(),
        shared_intermediate_key,
        sans=[x509.DNSName("cross.example.com")],
    )
    write_pem(leaf_cross, "leaf_cross_signed.pem")

    # Hostname/SAN mismatch (valid chain, SAN doesn't match the host under test)
    leaf_wrong_host_key = make_key()
    leaf_wrong_host = make_cert(
        "other.example.com",
        "CertWatch Test Public Intermediate",
        leaf_wrong_host_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("other.example.com")],
    )
    write_pem(leaf_wrong_host, "leaf_wrong_host.pem")

    # Wildcard SAN
    leaf_wildcard_key = make_key()
    leaf_wildcard = make_cert(
        "*.example.com",
        "CertWatch Test Public Intermediate",
        leaf_wildcard_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("*.example.com")],
    )
    write_pem(leaf_wildcard, "leaf_wildcard.pem")

    # IP address in SAN
    leaf_ip_san_key = make_key()
    leaf_ip_san = make_cert(
        "10.0.0.5",
        "CertWatch Test Public Intermediate",
        leaf_ip_san_key.public_key(),
        intermediate_public_key,
        sans=[x509.IPAddress(__import__("ipaddress").ip_address("10.0.0.5"))],
    )
    write_pem(leaf_ip_san, "leaf_ip_san.pem")

    # Weak key (1024-bit RSA is the floor this cryptography build allows —
    # still well below the 2048-bit modern minimum, exercises the same code path
    # a real legacy-512-bit-RSA certificate would)
    leaf_weak_key_key = make_key(bits=1024)
    leaf_weak_key = make_cert(
        "weakkey.example.com",
        "CertWatch Test Public Intermediate",
        leaf_weak_key_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("weakkey.example.com")],
    )
    write_pem(leaf_weak_key, "leaf_weak_key.pem")

    # SHA1-declared signature algorithm. This cryptography build's OpenSSL
    # backend refuses to actually SIGN with SHA1, so this fixture is built by
    # signing normally with SHA256 and then relabeling the signature-algorithm
    # field to sha1WithRSAEncryption via direct asn1crypto field assignment.
    # It exercises signature_algorithm field *extraction* for a SHA1-labeled
    # certificate — it does NOT contain a cryptographically real SHA1
    # signature, so it is not asserted to validate as a trusted chain.
    leaf_sha1_key = make_key()
    leaf_sha1 = make_cert(
        "sha1.example.com",
        "CertWatch Test Public Intermediate",
        leaf_sha1_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("sha1.example.com")],
    )
    der = leaf_sha1.public_bytes(serialization.Encoding.DER)
    a_cert = asn1_x509.Certificate.load(der)
    sha1_sig_algo = algos.SignedDigestAlgorithm({"algorithm": "sha1_rsa"})
    a_cert["tbs_certificate"]["signature"] = sha1_sig_algo
    a_cert["signature_algorithm"] = sha1_sig_algo
    (FIXTURES_DIR / "leaf_sha1_signed.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\n"
        + _b64_wrap(a_cert.dump(force=True))
        + b"-----END CERTIFICATE-----\n"
    )

    # Adversarial subject CN — control characters / injection-style text.
    # Must be stored and displayed as an inert string, never interpreted.
    leaf_adversarial_key = make_key()
    leaf_adversarial = make_cert(
        "<script>alert(1)</script>",
        "CertWatch Test Public Intermediate",
        leaf_adversarial_key.public_key(),
        intermediate_public_key,
        sans=[x509.DNSName("adversarial.example.com")],
    )
    write_pem(leaf_adversarial, "leaf_adversarial_cn.pem")

    # Malformed / truncated input — not valid PEM or DER at all.
    (FIXTURES_DIR / "malformed_not_pem.txt").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nThisIsNotValidBase64Der!!!\n-----END CERTIFICATE-----\n"
    )
    (FIXTURES_DIR / "malformed_truncated.der").write_bytes(bytes.fromhex("3082") * 3)

    print(f"Wrote fixtures to {FIXTURES_DIR}")


def _b64_wrap(data: bytes) -> bytes:
    import base64

    b64 = base64.b64encode(data)
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return b"\n".join(lines) + b"\n"


if __name__ == "__main__":
    main()
