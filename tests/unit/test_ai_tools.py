"""Unit tests for the four fixed, read-only LLM tools (M7, Section 16)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.ai.tools import ScanToolExecutor, _finding_dict
from app.parsing.models import Certificate, ChainCategory, Endpoint
from app.risk.risk_engine import apply_risk_engine, group_into_certificates
from app.storage.scan_store import HostResultRecord, ScanRecord, certificate_to_record


def _certificate(**overrides) -> Certificate:
    defaults = dict(
        fingerprint_sha256="a" * 64,
        subject_cn="example.com",
        san_list=["example.com", "www.example.com"],
        issuer="Example CA",
        serial_number="1",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        key_algorithm="RSA-2048",
        signature_algorithm="sha256WithRSAEncryption",
        pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        chain_category=ChainCategory.PUBLIC_CA,
        is_expired=False,
        days_to_expiry=5,
        is_wildcard=False,
        hostname_mismatch=False,
        risk_severity=None,
        duplicate_of=None,
        endpoints=[Endpoint(host="example.com", port=443)],
    )
    defaults.update(overrides)
    return Certificate(**defaults)


@pytest.fixture
def record() -> ScanRecord:
    return ScanRecord(
        token="test-token",
        submitted_at=datetime(2026, 1, 1, tzinfo=UTC),
        host_count=1,
        status="complete",
        source_ip=None,
        ai_enabled=True,
        host_results=[
            HostResultRecord(
                hostname="example.com",
                port=443,
                status="ok",
                certificate=certificate_to_record(_certificate()),
            )
        ],
    )


def _executor(record: ScanRecord) -> ScanToolExecutor:
    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    return ScanToolExecutor(record=record, certificates=certificates)


def test_finding_dict_never_includes_pem_bytes(record: ScanRecord) -> None:
    executor = _executor(record)
    finding = executor.call("get_findings", {})["findings"][0]
    assert "pem" not in finding
    assert set(finding.keys()) == {
        "certificate_id",
        "subject_cn",
        "san_list",
        "issuer",
        "days_to_expiry",
        "risk_severity",
        "chain_category",
        "endpoints",
        "flags",
    }


def test_get_findings_returns_every_certificate_when_unfiltered(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_findings", {})
    assert len(result["findings"]) == 1
    assert result["findings"][0]["certificate_id"] == "a" * 64


def test_get_findings_filters_by_severity(record: ScanRecord) -> None:
    executor = _executor(record)
    severity = executor.call("get_findings", {})["findings"][0]["risk_severity"]

    matching = executor.call("get_findings", {"severity": severity})
    assert len(matching["findings"]) == 1

    non_matching = executor.call("get_findings", {"severity": "not-a-real-severity"})
    assert non_matching["findings"] == []


def test_get_certificate_returns_the_matching_finding(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_certificate", {"certificate_id": "a" * 64})
    assert result["subject_cn"] == "example.com"


def test_get_certificate_unknown_id_returns_error(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_certificate", {"certificate_id": "does-not-exist"})
    assert "error" in result


def test_get_endpoints_for_certificate(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_endpoints_for_certificate", {"certificate_id": "a" * 64})
    assert result["endpoints"] == [
        {"host": "example.com", "port": 443, "environment": None, "owner": None}
    ]


def test_get_endpoints_for_certificate_unknown_id_returns_error(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_endpoints_for_certificate", {"certificate_id": "nope"})
    assert "error" in result


def test_get_summary_counts(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("get_summary_counts", {})
    assert isinstance(result["summary_counts"], dict)
    assert sum(result["summary_counts"].values()) == 1


def test_unknown_tool_name_returns_error(record: ScanRecord) -> None:
    executor = _executor(record)
    result = executor.call("delete_everything", {})
    assert "error" in result


def test_finding_dict_helper_directly() -> None:
    certificate = _certificate()
    finding = _finding_dict(certificate, [certificate])
    assert finding["certificate_id"] == certificate.fingerprint_sha256
    assert finding["san_list"] == ["example.com", "www.example.com"]
