"""Tests for token generation and scan-result persistence (M3, Section 11/12)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.parsing.models import Certificate, ChainCategory
from app.scanning.scanner import HostScanOutcome, HostScanStatus
from app.storage.local_filesystem import LocalFilesystemStorage
from app.storage.scan_store import (
    CertificateRecord,
    ScanRecord,
    certificate_to_record,
    generate_scan_token,
    host_outcome_to_record,
    load_scan_record,
    save_scan_record,
    scan_storage_key,
    summarize_host_statuses,
)


def test_generate_scan_token_is_high_entropy_and_urlsafe():
    token = generate_scan_token()
    # secrets.token_urlsafe(32) produces a 43-character base64url string —
    # no sequential/guessable identifier is ever generated (Section 12).
    assert len(token) >= 43
    assert all(c.isalnum() or c in "-_" for c in token)


def test_generate_scan_token_is_unique_across_many_calls():
    tokens = {generate_scan_token() for _ in range(1000)}
    assert len(tokens) == 1000


def test_scan_storage_key_is_token_scoped():
    assert scan_storage_key("abc123") == "scans/abc123/result.json"


def _sample_certificate() -> Certificate:
    return Certificate(
        fingerprint_sha256="deadbeef" * 8,
        subject_cn="example.com",
        san_list=["example.com", "www.example.com"],
        issuer="Example CA",
        serial_number="1234",
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


def test_certificate_to_record_converts_enum_to_plain_string():
    record = certificate_to_record(_sample_certificate())
    assert isinstance(record, CertificateRecord)
    assert record.chain_category == "public_ca"
    assert record.fingerprint_sha256 == "deadbeef" * 8


def test_certificate_to_record_handles_none_chain_category():
    cert = _sample_certificate()
    cert.chain_category = None
    record = certificate_to_record(cert)
    assert record.chain_category is None


def test_host_outcome_to_record_ok_status_carries_certificate():
    outcome = HostScanOutcome(
        hostname="example.com",
        port=443,
        status=HostScanStatus.OK,
        certificate=_sample_certificate(),
    )
    record = host_outcome_to_record(outcome)
    assert record.status == "ok"
    assert record.certificate is not None
    assert record.certificate.subject_cn == "example.com"


def test_host_outcome_to_record_failure_status_has_no_certificate():
    outcome = HostScanOutcome(
        hostname="internal.example.com",
        port=443,
        status=HostScanStatus.DISALLOWED_ADDRESS,
        detail="resolved to a private address",
    )
    record = host_outcome_to_record(outcome)
    assert record.status == "disallowed_address"
    assert record.certificate is None
    assert record.detail == "resolved to a private address"


def test_save_then_load_scan_record_roundtrips(tmp_path):
    storage = LocalFilesystemStorage(tmp_path)
    record = ScanRecord(
        token="test-token-123",
        submitted_at=datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC),
        host_count=1,
        status="complete",
        source_ip="203.0.113.5",
        ai_enabled=True,
        host_results=[
            host_outcome_to_record(
                HostScanOutcome(
                    hostname="example.com",
                    port=443,
                    status=HostScanStatus.OK,
                    certificate=_sample_certificate(),
                )
            )
        ],
    )
    save_scan_record(storage, record)

    loaded = load_scan_record(storage, "test-token-123")
    assert loaded is not None
    assert loaded.token == record.token
    assert loaded.status == "complete"
    assert loaded.host_count == 1
    assert loaded.source_ip == "203.0.113.5"
    assert len(loaded.host_results) == 1
    assert loaded.host_results[0].certificate.chain_category == "public_ca"


def test_load_scan_record_missing_token_returns_none(tmp_path):
    storage = LocalFilesystemStorage(tmp_path)
    assert load_scan_record(storage, "does-not-exist") is None


def test_source_ip_never_appears_in_a_field_meant_for_the_user():
    # Documents the Section 10 constraint at the model level: source_ip is
    # a real field on ScanRecord (for abuse investigation) but is simply
    # absent from any response model — see test_routes_scans.py for the
    # API-level assertion that it's never returned.
    record = ScanRecord(
        token="t",
        submitted_at=datetime.now(UTC),
        host_count=0,
        status="complete",
        source_ip="1.2.3.4",
    )
    assert "source_ip" in type(record).model_fields


def test_summarize_host_statuses_counts_by_status():
    results = [
        host_outcome_to_record(
            HostScanOutcome("a.com", 443, HostScanStatus.OK, certificate=_sample_certificate())
        ),
        host_outcome_to_record(
            HostScanOutcome("b.com", 443, HostScanStatus.OK, certificate=_sample_certificate())
        ),
        host_outcome_to_record(HostScanOutcome("c.com", 22, HostScanStatus.DISALLOWED_PORT)),
        host_outcome_to_record(HostScanOutcome("d.com", 443, HostScanStatus.HANDSHAKE_FAILED)),
    ]
    counts = summarize_host_statuses(results)
    assert counts == {"ok": 2, "disallowed_port": 1, "handshake_failed": 1}


def test_summarize_host_statuses_empty_list():
    assert summarize_host_statuses([]) == {}
