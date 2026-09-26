"""Tests for the deterministic risk engine (M4, Section 9)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.parsing.models import Certificate, ChainCategory, Endpoint
from app.risk.risk_engine import (
    apply_risk_engine,
    classify_risk,
    evaluate_flags,
    expiry_tier,
    group_into_certificates,
    is_weak_crypto,
    severity_sort_key,
    summarize_risk_severity,
)
from app.scanning.scanner import HostScanOutcome, HostScanStatus
from app.storage.scan_store import ScanRecord, host_outcome_to_record


def _cert(**overrides) -> Certificate:
    defaults = dict(
        fingerprint_sha256="a" * 64,
        subject_cn="example.com",
        san_list=["example.com"],
        issuer="Example CA",
        serial_number="1",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        key_algorithm="RSA-2048",
        signature_algorithm="sha256WithRSAEncryption",
        pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        chain_category=ChainCategory.PUBLIC_CA,
        is_expired=False,
        days_to_expiry=365,
        is_wildcard=False,
        hostname_mismatch=False,
        risk_severity=None,
        duplicate_of=None,
    )
    defaults.update(overrides)
    return Certificate(**defaults)


# --- expiry_tier (Section 9, "Expiry status") ---


@pytest.mark.parametrize(
    ("days", "expected"),
    [
        (-1, "expired"),
        (-365, "expired"),
        (0, "critical"),
        (7, "critical"),
        (8, "high"),
        (30, "high"),
        (31, "medium"),
        (60, "medium"),
        (61, "low"),
        (90, "low"),
        (91, "ok"),
        (365, "ok"),
    ],
)
def test_expiry_tier_boundaries(days, expected):
    assert expiry_tier(days) == expected


# --- is_weak_crypto (Section 9, "Weak or obsolete cryptography") ---


@pytest.mark.parametrize(
    ("key_algorithm", "signature_algorithm", "expected"),
    [
        ("RSA-2048", "sha256WithRSAEncryption", False),
        ("RSA-4096", "sha256WithRSAEncryption", False),
        ("RSA-2047", "sha256WithRSAEncryption", True),
        ("RSA-1024", "sha256WithRSAEncryption", True),
        ("DSA-2048", "sha256WithDSA", True),  # DSA is unconditionally weak
        ("DSA-1024", "sha256WithDSA", True),
        ("EC-secp256r1-256", "ecdsa-with-SHA256", False),
        ("EC-secp384r1-384", "ecdsa-with-SHA384", False),
        ("EC-secp224r1-224", "ecdsa-with-SHA256", True),
        ("Ed25519", "Ed25519", False),
        ("Ed448", "Ed448", False),
        ("RSA-2048", "sha1WithRSAEncryption", True),  # weak signature overrides a strong key
        ("RSA-2048", "md5WithRSAEncryption", True),
        ("RSA-4096", "sha256WithRSAEncryption", False),
    ],
)
def test_is_weak_crypto(key_algorithm, signature_algorithm, expected):
    assert is_weak_crypto(key_algorithm, signature_algorithm) is expected


# --- classify_risk priority order (Section 9, "Overall risk severity") ---


def test_expired_beats_everything_else():
    cert = _cert(
        days_to_expiry=-1,
        key_algorithm="RSA-1024",  # also weak crypto
        hostname_mismatch=True,
        chain_category=ChainCategory.BROKEN,
    )
    assert classify_risk(cert, [cert]) == "expired"


def test_weak_crypto_beats_hostname_mismatch_and_expiry_tier():
    cert = _cert(key_algorithm="RSA-1024", hostname_mismatch=True, days_to_expiry=5)
    assert classify_risk(cert, [cert]) == "weak_crypto"


def test_broken_chain_beats_hostname_mismatch():
    cert = _cert(chain_category=ChainCategory.BROKEN, hostname_mismatch=True, days_to_expiry=5)
    assert classify_risk(cert, [cert]) == "broken_chain"


def test_hostname_mismatch_beats_approaching_expiry_tier():
    cert = _cert(hostname_mismatch=True, days_to_expiry=5)
    assert classify_risk(cert, [cert]) == "hostname_mismatch"


def test_approaching_expiry_tier_beats_shared():
    cert = _cert(days_to_expiry=5, endpoints=[Endpoint("a.com", 443), Endpoint("b.com", 443)])
    assert classify_risk(cert, [cert]) == "critical"


def test_shared_beats_private_ca():
    cert = _cert(
        chain_category=ChainCategory.PRIVATE_CA,
        endpoints=[Endpoint("a.com", 443), Endpoint("b.com", 443)],
    )
    assert classify_risk(cert, [cert]) == "shared"


def test_private_ca_alone():
    cert = _cert(chain_category=ChainCategory.PRIVATE_CA)
    assert classify_risk(cert, [cert]) == "private_ca"


def test_nothing_applicable_is_ok():
    cert = _cert()
    assert classify_risk(cert, [cert]) == "ok"


def test_single_endpoint_is_not_shared():
    cert = _cert(endpoints=[Endpoint("a.com", 443)])
    assert classify_risk(cert, [cert]) == "ok"


# --- suspicious_configuration (Section 9) — supplementary, not in the priority chain ---


def test_suspicious_configuration_flagged_when_other_certs_are_ca_issued():
    self_signed = _cert(fingerprint_sha256="b" * 64, chain_category=ChainCategory.SELF_SIGNED)
    ca_issued = _cert(fingerprint_sha256="c" * 64, chain_category=ChainCategory.PUBLIC_CA)
    flags = evaluate_flags(self_signed, [self_signed, ca_issued])
    assert "suspicious_configuration" in flags
    # It never becomes the returned severity — the spec's priority list omits it.
    assert classify_risk(self_signed, [self_signed, ca_issued]) == "ok"


def test_self_signed_alone_in_scan_is_not_suspicious():
    self_signed = _cert(chain_category=ChainCategory.SELF_SIGNED)
    assert "suspicious_configuration" not in evaluate_flags(self_signed, [self_signed])


def test_non_self_signed_never_flagged_suspicious():
    ca_issued = _cert(chain_category=ChainCategory.PUBLIC_CA)
    self_signed_other = _cert(fingerprint_sha256="b" * 64, chain_category=ChainCategory.SELF_SIGNED)
    assert "suspicious_configuration" not in evaluate_flags(
        ca_issued, [ca_issued, self_signed_other]
    )


# --- evaluate_flags ordering ---


def test_evaluate_flags_lists_all_applicable_in_priority_order():
    cert = _cert(
        days_to_expiry=-1,
        key_algorithm="RSA-1024",
        chain_category=ChainCategory.BROKEN,
        hostname_mismatch=True,
        endpoints=[Endpoint("a.com", 443), Endpoint("b.com", 443)],
    )
    flags = evaluate_flags(cert, [cert])
    assert flags == ["expired", "weak_crypto", "broken_chain", "hostname_mismatch", "shared"]


# --- severity_sort_key ---


def test_severity_sort_key_orders_worst_first():
    severities = ["ok", "private_ca", "expired", "shared", "low"]
    ordered = sorted(severities, key=severity_sort_key)
    assert ordered == ["expired", "low", "shared", "private_ca", "ok"]


def test_severity_sort_key_unknown_value_sorts_last():
    assert severity_sort_key("not-a-real-severity") > severity_sort_key("private_ca")


# --- group_into_certificates (Section 10's endpoint-grouped shape, built on demand) ---


def _host_result(hostname: str, port: int, *, certificate: Certificate | None) -> object:
    outcome = HostScanOutcome(
        hostname=hostname,
        port=port,
        status=HostScanStatus.OK if certificate else HostScanStatus.HANDSHAKE_FAILED,
        certificate=certificate,
    )
    return host_outcome_to_record(outcome)


def test_group_into_certificates_merges_same_fingerprint_into_one_with_endpoints():
    shared_cert = _cert(fingerprint_sha256="shared" * 8)
    scan = ScanRecord(
        token="t",
        submitted_at=datetime.now(UTC),
        host_count=2,
        status="complete",
        host_results=[
            _host_result("a.com", 443, certificate=shared_cert),
            _host_result("b.com", 443, certificate=shared_cert),
        ],
    )
    grouped = group_into_certificates(scan)
    assert len(grouped) == 1
    assert {(e.host, e.port) for e in grouped[0].endpoints} == {("a.com", 443), ("b.com", 443)}
    assert grouped[0].duplicate_of is None


def test_group_into_certificates_skips_hosts_with_no_certificate():
    scan = ScanRecord(
        token="t",
        submitted_at=datetime.now(UTC),
        host_count=2,
        status="complete",
        host_results=[
            _host_result("a.com", 443, certificate=_cert()),
            _host_result("b.com", 22, certificate=None),
        ],
    )
    grouped = group_into_certificates(scan)
    assert len(grouped) == 1
    assert grouped[0].endpoints[0].host == "a.com"


def test_apply_risk_engine_sets_risk_severity_in_place():
    cert = _cert(days_to_expiry=-1)
    certificates = [cert]
    apply_risk_engine(certificates)
    assert certificates[0].risk_severity == "expired"


# --- summarize_risk_severity (GET /api/scans/{token}'s summary_counts, M4-derived) ---


def test_summarize_risk_severity_buckets_by_severity_and_scan_failures():
    healthy = _cert(fingerprint_sha256="healthy" * 8)
    expiring = _cert(fingerprint_sha256="expiring" * 8, days_to_expiry=3)
    scan = ScanRecord(
        token="t",
        submitted_at=datetime.now(UTC),
        host_count=3,
        status="complete",
        host_results=[
            _host_result("ok.com", 443, certificate=healthy),
            _host_result("expiring.com", 443, certificate=expiring),
            _host_result("failed.com", 443, certificate=None),
        ],
    )
    counts = summarize_risk_severity(scan)
    assert counts == {"ok": 1, "critical": 1, "scan_failed": 1}


def test_summarize_risk_severity_empty_scan():
    scan = ScanRecord(token="t", submitted_at=datetime.now(UTC), host_count=0, status="complete")
    assert summarize_risk_severity(scan) == {}
