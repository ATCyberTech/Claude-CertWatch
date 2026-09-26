"""M1 certificate parser tests — Section 22 test list.

All fixtures are local (tests/fixtures/certs/) — no live network dependency,
per the M1 milestone-gating clarification in the Decision Log.

`root_public.pem` stands in for a certifi-trusted public root: it is passed
explicitly as `trust_roots` so these tests never depend on real, live public
CAs (see the docstring in generate_fixtures.py).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import asn1crypto.pem
import asn1crypto.x509 as asn1_x509
import pytest

from app.parsing.certificate_parser import CertificateParseError, parse_certificate_chain
from app.parsing.models import ChainCategory

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "certs"


def load_pem(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


def load_asn1(name: str) -> asn1_x509.Certificate:
    _type_name, _headers, der = asn1crypto.pem.unarmor(load_pem(name))
    return asn1_x509.Certificate.load(der)


@pytest.fixture
def public_trust_roots() -> list[asn1_x509.Certificate]:
    """The fixture "public" root — stands in for certifi in these tests."""
    return [load_asn1("root_public.pem")]


# --- Category 2: valid chain to a (test-)public trusted root ---


@pytest.mark.asyncio
async def test_valid_public_ca_chain(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_valid_public_ca.pem"), load_pem("intermediate_public.pem")],
        "valid.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.chain_category is ChainCategory.PUBLIC_CA
    assert cert.hostname_mismatch is False
    assert cert.is_expired is False
    assert cert.subject_cn == "valid.example.com"
    assert cert.san_list == ["valid.example.com"]
    assert cert.key_algorithm == "RSA-2048"
    assert cert.signature_algorithm == "sha256WithRSAEncryption"
    assert len(cert.fingerprint_sha256) == 64  # hex sha256
    assert "BEGIN CERTIFICATE" in cert.pem


@pytest.mark.asyncio
async def test_expired_certificate(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_expired.pem"), load_pem("intermediate_public.pem")],
        "expired.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.is_expired is True
    assert cert.days_to_expiry < 0
    assert cert.not_after < datetime.now(UTC)


# --- Category 1: genuinely self-signed leaf ---


@pytest.mark.asyncio
async def test_self_signed_leaf(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_self_signed.pem")],
        "selfsigned.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.chain_category is ChainCategory.SELF_SIGNED


# --- Category 3: correctly-built private/internal CA chain ---


@pytest.mark.asyncio
async def test_private_ca_chain_not_flagged_as_broken(public_trust_roots):
    """The credibility threat (T8): category 3 must never collapse into
    category 1 (self-signed) or category 4 (broken)."""
    cert = await parse_certificate_chain(
        [load_pem("leaf_private_ca.pem"), load_pem("intermediate_private.pem")],
        "internal.example",
        trust_roots=public_trust_roots,  # root_private is NOT in this list
    )
    assert cert.chain_category is ChainCategory.PRIVATE_CA
    assert cert.chain_category is not ChainCategory.SELF_SIGNED
    assert cert.chain_category is not ChainCategory.BROKEN


# --- Category 4: broken/incomplete/invalid chain ---


@pytest.mark.asyncio
async def test_broken_chain_missing_intermediate(public_trust_roots):
    """The issuing intermediate is never presented at all — no consistent
    path can be built by either pass."""
    cert = await parse_certificate_chain(
        [load_pem("leaf_broken_chain.pem")],
        "broken.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.chain_category is ChainCategory.BROKEN


# --- Cross-signed intermediate / alternate path ---


@pytest.mark.asyncio
async def test_cross_signed_alternate_path_resolves(public_trust_roots):
    """Two cross-signing certs for the same intermediate key are presented;
    only one issuer (root_public) is trusted. A correct path builder finds
    the valid path through the noise rather than failing outright."""
    cert = await parse_certificate_chain(
        [
            load_pem("leaf_cross_signed.pem"),
            load_pem("intermediate_cross_by_public.pem"),
            load_pem("intermediate_cross_by_alt.pem"),  # noise: untrusted alt issuer
        ],
        "cross.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.chain_category is ChainCategory.PUBLIC_CA


# --- Hostname/SAN mismatch (category 5, orthogonal) ---


@pytest.mark.asyncio
async def test_hostname_mismatch_on_otherwise_valid_chain(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_wrong_host.pem"), load_pem("intermediate_public.pem")],
        "wrong.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.chain_category is ChainCategory.PUBLIC_CA
    assert cert.hostname_mismatch is True


@pytest.mark.asyncio
async def test_hostname_exact_match(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_valid_public_ca.pem"), load_pem("intermediate_public.pem")],
        "valid.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.hostname_mismatch is False


@pytest.mark.asyncio
async def test_hostname_wildcard_match(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_wildcard.pem"), load_pem("intermediate_public.pem")],
        "foo.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.hostname_mismatch is False
    assert cert.is_wildcard is True


@pytest.mark.asyncio
async def test_hostname_wildcard_does_not_match_multilevel_subdomain(public_trust_roots):
    """*.example.com must NOT match foo.bar.example.com (Section 22)."""
    cert = await parse_certificate_chain(
        [load_pem("leaf_wildcard.pem"), load_pem("intermediate_public.pem")],
        "foo.bar.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.hostname_mismatch is True


@pytest.mark.asyncio
async def test_hostname_ip_in_san_matches(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_ip_san.pem"), load_pem("intermediate_public.pem")],
        "10.0.0.5",
        trust_roots=public_trust_roots,
    )
    assert cert.hostname_mismatch is False


@pytest.mark.asyncio
async def test_hostname_ip_in_san_non_matching_ip(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_ip_san.pem"), load_pem("intermediate_public.pem")],
        "10.0.0.6",
        trust_roots=public_trust_roots,
    )
    assert cert.hostname_mismatch is True


# --- Weak key / SHA1 signature: parser must still parse without crashing ---


@pytest.mark.asyncio
async def test_weak_key_parses_without_crashing(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_weak_key.pem"), load_pem("intermediate_public.pem")],
        "weakkey.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.key_algorithm == "RSA-1024"


@pytest.mark.asyncio
async def test_sha1_labeled_signature_parses_without_crashing(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_sha1_signed.pem"), load_pem("intermediate_public.pem")],
        "sha1.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.signature_algorithm == "sha1WithRSAEncryption"


# --- key_algorithm string format for DSA / EC keys (M4, Section 9's weak-crypto rule) ---


@pytest.mark.asyncio
async def test_dsa_key_algorithm_is_detected_explicitly(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_dsa_key.pem"), load_pem("intermediate_public.pem")],
        "dsa.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.key_algorithm == "DSA-1024"


@pytest.mark.asyncio
async def test_ec_key_algorithm_embeds_curve_bit_size():
    cert = await parse_certificate_chain(
        [load_pem("leaf_ec_weak_curve.pem")],
        "ecweak.example.com",
        trust_roots=[],
    )
    assert cert.key_algorithm == "EC-secp224r1-224"
    assert cert.chain_category is ChainCategory.SELF_SIGNED


@pytest.mark.asyncio
async def test_ec_p256_key_algorithm_embeds_curve_bit_size():
    cert = await parse_certificate_chain(
        [load_pem("leaf_ec_strong_curve.pem")],
        "ecstrong.example.com",
        trust_roots=[],
    )
    assert cert.key_algorithm == "EC-secp256r1-256"
    assert cert.chain_category is ChainCategory.SELF_SIGNED


# --- Parser robustness (T9) ---


@pytest.mark.asyncio
async def test_adversarial_subject_cn_stored_as_inert_string(public_trust_roots):
    cert = await parse_certificate_chain(
        [load_pem("leaf_adversarial_cn.pem"), load_pem("intermediate_public.pem")],
        "adversarial.example.com",
        trust_roots=public_trust_roots,
    )
    assert cert.subject_cn == "<script>alert(1)</script>"


@pytest.mark.asyncio
async def test_malformed_pem_raises_certificate_parse_error(public_trust_roots):
    with pytest.raises(CertificateParseError):
        await parse_certificate_chain(
            [load_pem("malformed_not_pem.txt")],
            "whatever.example.com",
            trust_roots=public_trust_roots,
        )


@pytest.mark.asyncio
async def test_truncated_der_raises_certificate_parse_error(public_trust_roots):
    with pytest.raises(CertificateParseError):
        await parse_certificate_chain(
            [load_pem("malformed_truncated.der")],
            "whatever.example.com",
            trust_roots=public_trust_roots,
        )


@pytest.mark.asyncio
async def test_empty_chain_raises_certificate_parse_error():
    with pytest.raises(CertificateParseError):
        await parse_certificate_chain([], "whatever.example.com")


@pytest.mark.asyncio
async def test_default_trust_roots_falls_back_to_certifi_without_crashing():
    """No trust_roots passed: exercises the real production code path
    (trust_store.default_public_trust_roots loading the installed certifi
    bundle). None of our fixture CAs are real public CAs, so Pass 1 against
    real certifi fails; Pass 2 still succeeds because the intermediate is
    presented and self-consistent, landing on PRIVATE_CA rather than
    PUBLIC_CA — the point of this test is that the certifi-backed default
    path runs end to end without raising, not the resulting category."""
    cert = await parse_certificate_chain(
        [load_pem("leaf_valid_public_ca.pem"), load_pem("intermediate_public.pem")],
        "valid.example.com",
    )
    assert cert.chain_category is ChainCategory.PRIVATE_CA


# --- Chain-category correctness: all five categories, explicitly distinct ---


@pytest.mark.asyncio
async def test_all_five_categories_are_pairwise_distinct(public_trust_roots):
    valid = await parse_certificate_chain(
        [load_pem("leaf_valid_public_ca.pem"), load_pem("intermediate_public.pem")],
        "valid.example.com",
        trust_roots=public_trust_roots,
    )
    self_signed = await parse_certificate_chain(
        [load_pem("leaf_self_signed.pem")],
        "selfsigned.example.com",
        trust_roots=public_trust_roots,
    )
    private_ca = await parse_certificate_chain(
        [load_pem("leaf_private_ca.pem"), load_pem("intermediate_private.pem")],
        "internal.example",
        trust_roots=public_trust_roots,
    )
    broken = await parse_certificate_chain(
        [load_pem("leaf_broken_chain.pem")],
        "broken.example.com",
        trust_roots=public_trust_roots,
    )
    wrong_host = await parse_certificate_chain(
        [load_pem("leaf_wrong_host.pem"), load_pem("intermediate_public.pem")],
        "wrong.example.com",
        trust_roots=public_trust_roots,
    )

    categories = {
        valid.chain_category,
        self_signed.chain_category,
        private_ca.chain_category,
        broken.chain_category,
    }
    # Exactly four distinct ChainCategory values seen — none collapsed together.
    assert categories == {
        ChainCategory.PUBLIC_CA,
        ChainCategory.SELF_SIGNED,
        ChainCategory.PRIVATE_CA,
        ChainCategory.BROKEN,
    }
    # Category 5 is orthogonal: a category-2 chain can also be a mismatch.
    assert wrong_host.chain_category is ChainCategory.PUBLIC_CA
    assert wrong_host.hostname_mismatch is True
