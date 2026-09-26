"""Certificate parsing and chain validation — owned by M1.

Implements Section 8 of the CertWatch MVP Technical Specification v1:
X.509 field extraction via `cryptography`, and RFC 5280 PKIX path
validation via `pyhanko-certvalidator`'s two-pass algorithm, which
distinguishes a correctly-built private/internal CA chain (category 3)
from a broken chain (category 4) without ever collapsing either of them
into "self-signed" (category 1) or "valid public" (category 2).

`cryptography` is used only for field parsing and the self-signed-leaf
check; it never performs path building on its own — `pyhanko-certvalidator`
is the actual chain-validation engine (see the Decision Log).

No network access happens anywhere in this module. `allow_fetching=False`
is always passed to `ValidationContext` — there is no live OCSP/CRL
fetching (Section 8's stated limitation), and this module does not
itself resolve or connect to anything (that is `app.scanning`'s job, M2).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import cast

import asn1crypto.pem
import asn1crypto.x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from pyhanko_certvalidator import CertificateValidator, ValidationContext

from app.parsing.models import Certificate, ChainCategory
from app.parsing.trust_store import default_public_trust_roots


class CertificateParseError(Exception):
    """Raised when a certificate cannot be parsed at all (Section 8, T9).

    Malformed or truncated ASN.1 must surface as this distinct, catchable
    error — never a silent drop and never an unhandled exception escaping
    into the scan pipeline. Callers (M2) are expected to catch this and
    record a "parse failed" finding rather than losing the host silently.
    A well-formed but untrusted, expired, or hostname-mismatched
    certificate is never an error — those are findings, produced normally
    by `parse_certificate_chain`.
    """


def _strip_pem(pem_bytes: bytes) -> bytes:
    """Return the DER bytes inside a single PEM-armored certificate block."""
    try:
        _type_name, _headers, der = asn1crypto.pem.unarmor(pem_bytes)
    except Exception as exc:
        raise CertificateParseError(f"could not PEM-decode certificate: {exc}") from exc
    return cast(bytes, der)


def _load_cryptography_cert(der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise CertificateParseError(f"could not parse certificate DER: {exc}") from exc


def _load_asn1_cert(der: bytes) -> asn1_x509.Certificate:
    try:
        return asn1_x509.Certificate.load(der)
    except Exception as exc:
        raise CertificateParseError(f"could not parse certificate DER: {exc}") from exc


def _key_algorithm(cert: x509.Certificate) -> str:
    """Return the key-algorithm string stored on `Certificate.key_algorithm`.

    The EC case embeds the curve's bit size (`EC-{name}-{bits}`) and DSA is
    now detected explicitly — both additions made during M4 (not touched at
    M1 time), because Section 9's weak-crypto rule ("RSA under 2048 bits,
    DSA, or ECDSA under P-256") cannot be evaluated from a curve *name*
    alone without a name-to-bits lookup table, and DSA previously fell
    through to the `Unknown (...)` branch with a fragile, backend-specific
    class name. Recorded in the Decision Log as an M4 fix to M1-owned code.
    """
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    if isinstance(public_key, dsa.DSAPublicKey):
        return f"DSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC-{public_key.curve.name}-{public_key.curve.key_size}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    return f"Unknown ({type(public_key).__name__})"


def _signature_algorithm(cert: x509.Certificate) -> str:
    name = getattr(cert.signature_algorithm_oid, "_name", None)
    return name if name else cert.signature_algorithm_oid.dotted_string


def _subject_cn(cert: x509.Certificate) -> str:
    """Extract the subject Common Name as an inert string (Section 8, T9).

    Never interpreted, evaluated, or used to drive control flow beyond
    plain string storage/display — adversarial content (control characters,
    injection-style text) is stored and displayed exactly as presented.
    """
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ""
    return str(attrs[0].value)


def _san_list(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    entries: list[str] = []
    for name in ext.value:
        if isinstance(name, x509.DNSName):
            entries.append(name.value)
        elif isinstance(name, x509.IPAddress):
            entries.append(str(name.value))
        else:
            # Other GeneralName types (URI, email, etc.) are stored as their
            # string form only — never interpreted or dereferenced.
            entries.append(str(name.value))
    return entries


def _is_wildcard(san_list: Sequence[str]) -> bool:
    # Informational metadata only — never used to infer business necessity
    # or "broader than SAN needs" risk (Decision Log: wildcard-inference
    # rule removed from the risk engine; this flag must not resurrect it).
    return any(entry.startswith("*.") for entry in san_list)


def _hostname_matches(observed_hostname: str, san_list: Sequence[str]) -> bool:
    """RFC 6125-style match: exact match, or a single left-most wildcard label.

    `*.example.com` matches `foo.example.com` but never `foo.bar.example.com`
    — multi-level subdomain matching is explicitly rejected (Section 22 test
    list). An IP-literal hostname matches only an IP entry in the SAN list,
    never a DNS name pattern.
    """
    try:
        observed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(
            observed_hostname
        )
    except ValueError:
        observed_ip = None

    for entry in san_list:
        if observed_ip is not None:
            try:
                if ipaddress.ip_address(entry) == observed_ip:
                    return True
            except ValueError:
                pass
            continue

        if entry == observed_hostname:
            return True

        if entry.startswith("*."):
            host_labels = observed_hostname.split(".")
            pattern_labels = entry.split(".")
            if len(host_labels) != len(pattern_labels):
                continue
            # Only the left-most label may stand in for '*'; every remaining
            # label must match exactly (case-insensitively).
            if host_labels[0] and all(
                h.lower() == p.lower()
                for h, p in zip(host_labels[1:], pattern_labels[1:], strict=True)
            ):
                return True
    return False


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Category 1: subject == issuer AND the leaf's own signature self-verifies.

    Checked before any path validation runs (Section 8) — this must never
    be inferred from a path-building failure alone, since a broken chain
    (category 4) also fails path building for an unrelated reason.
    """
    if cert.subject != cert.issuer:
        return False
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        # Any other failure (e.g. an algorithm this build won't verify at
        # all) is not proof of self-signature — fall through to path
        # validation rather than mis-classifying it as category 1.
        return False
    return True


async def _classify_chain(
    leaf: asn1_x509.Certificate,
    intermediates: list[asn1_x509.Certificate],
    trust_roots: Iterable[asn1_x509.Certificate],
) -> ChainCategory:
    """Two-pass validation per Section 8, distinguishing category 3 from 4.

    Pass 1 validates against the public trust bundle (`trust_roots`,
    normally certifi via `trust_store.default_public_trust_roots`). If that
    fails, Pass 2 re-validates with trust extended to every certificate the
    server itself presented, treating the end of whatever consistent path
    can be built as an implicit, unverified trust anchor. This is
    CertWatch's own validation design, not a claim that a specific library
    call performs it automatically.
    """
    pass1_context = ValidationContext(trust_roots=list(trust_roots), allow_fetching=False)
    pass1_validator = CertificateValidator(
        leaf, intermediate_certs=intermediates, validation_context=pass1_context
    )
    try:
        await pass1_validator.async_validate_path()
        return ChainCategory.PUBLIC_CA
    except Exception:
        pass

    pass2_context = ValidationContext(trust_roots=intermediates, allow_fetching=False)
    pass2_validator = CertificateValidator(
        leaf, intermediate_certs=intermediates, validation_context=pass2_context
    )
    try:
        await pass2_validator.async_validate_path()
        return ChainCategory.PRIVATE_CA
    except Exception:
        return ChainCategory.BROKEN


async def parse_certificate_chain(
    pem_chain: list[bytes],
    observed_hostname: str,
    trust_roots: Iterable[asn1_x509.Certificate] | None = None,
) -> Certificate:
    """Parse a server-presented certificate chain into a `Certificate`.

    `pem_chain[0]` is the leaf as presented in the TLS handshake; the
    remaining entries are the intermediates the server presented, in
    whatever order it sent them — path building does not assume they are
    pre-sorted (Section 8: "server-presented chain ordering").

    `trust_roots` defaults to the certifi public trust bundle (Pass 1's
    anchor, via `trust_store.default_public_trust_roots`); tests override
    it with a fixture root so they never depend on real public CAs.

    Never raises on a well-formed but untrusted/expired/mismatched
    certificate — those are findings, not errors. Raises
    `CertificateParseError` only when the input itself cannot be parsed at
    all (Section 8, T9). This function is async because
    `pyhanko-certvalidator`'s path validator is async-only (an M1
    implementation detail, recorded in the Decision Log — the M0 stub
    signature was synchronous).
    """
    if not pem_chain:
        raise CertificateParseError("empty certificate chain")

    leaf_der = _strip_pem(pem_chain[0])
    leaf_crypto = _load_cryptography_cert(leaf_der)
    leaf_asn1 = _load_asn1_cert(leaf_der)
    intermediate_asn1 = [_load_asn1_cert(_strip_pem(pem)) for pem in pem_chain[1:]]

    san_list = _san_list(leaf_crypto)
    now = datetime.now(UTC)
    not_after = leaf_crypto.not_valid_after_utc
    not_before = leaf_crypto.not_valid_before_utc

    if _is_self_signed(leaf_crypto):
        chain_category = ChainCategory.SELF_SIGNED
    else:
        roots = list(trust_roots) if trust_roots is not None else default_public_trust_roots()
        chain_category = await _classify_chain(leaf_asn1, intermediate_asn1, roots)

    return Certificate(
        fingerprint_sha256=leaf_crypto.fingerprint(hashes.SHA256()).hex(),
        subject_cn=_subject_cn(leaf_crypto),
        san_list=san_list,
        issuer=leaf_crypto.issuer.rfc4514_string(),
        serial_number=format(leaf_crypto.serial_number, "X"),
        not_before=not_before,
        not_after=not_after,
        key_algorithm=_key_algorithm(leaf_crypto),
        signature_algorithm=_signature_algorithm(leaf_crypto),
        pem=pem_chain[0].decode("ascii", errors="replace"),
        chain_category=chain_category,
        is_expired=now > not_after,
        days_to_expiry=(not_after - now).days,
        is_wildcard=_is_wildcard(san_list),
        hostname_mismatch=not _hostname_matches(observed_hostname, san_list),
    )
