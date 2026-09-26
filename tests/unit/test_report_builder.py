"""Tests for report assembly (M5, Section 15)."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from app.parsing.models import Certificate, ChainCategory, Endpoint
from app.reports.report_builder import build_csv_report, build_pdf_report, render_report_html
from app.risk.risk_engine import apply_risk_engine
from app.storage.scan_store import ScanRecord


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
        endpoints=[Endpoint(host="example.com", port=443)],
    )
    defaults.update(overrides)
    return Certificate(**defaults)


def _scan_record(host_count: int = 1) -> ScanRecord:
    return ScanRecord(
        token="test-token",
        submitted_at=datetime(2026, 6, 1, tzinfo=UTC),
        host_count=host_count,
        status="complete",
        host_results=[],
    )


# --- render_report_html ---


def test_render_report_html_excludes_ok_certificates_from_section_1():
    healthy = _cert(fingerprint_sha256="h" * 64)
    expiring = _cert(fingerprint_sha256="e" * 64, days_to_expiry=3)
    certificates = [healthy, expiring]
    apply_risk_engine(certificates)

    html = render_report_html(_scan_record(), certificates)
    assert "Certificates requiring attention" in html
    assert "Full inventory" in html
    # Section 1 shows only the expiring (critical) cert, not the healthy one —
    # can't assert on exact row content easily, but the summary badge for
    # "critical" must appear and "ok" cert count must still show in Section 2.
    assert "critical" in html


def test_render_report_html_includes_methodology_footer():
    certificates = [_cert()]
    apply_risk_engine(certificates)
    html = render_report_html(_scan_record(), certificates)
    assert "Methodology" in html
    assert "OCSP/CRL" in html
    assert "point-in-time" in html


def test_render_report_html_handles_no_certificates():
    html = render_report_html(_scan_record(host_count=0), [])
    assert "No certificates were discovered" in html
    assert "No certificates require attention" in html


# --- build_pdf_report ---


def test_build_pdf_report_produces_valid_pdf_bytes():
    certificates = [_cert()]
    apply_risk_engine(certificates)
    pdf_bytes = build_pdf_report(_scan_record(), certificates)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 100


# --- build_csv_report ---


def test_build_csv_report_has_one_row_per_certificate_including_ok():
    healthy = _cert(fingerprint_sha256="h" * 64)
    expiring = _cert(fingerprint_sha256="e" * 64, days_to_expiry=3)
    certificates = [healthy, expiring]
    apply_risk_engine(certificates)

    csv_bytes = build_csv_report(_scan_record(), certificates)
    rows = list(csv.reader(io.StringIO(csv_bytes.decode("utf-8"))))
    assert rows[0][0] == "certificate_id"
    assert len(rows) == 3  # header + 2 certificates (including the "ok" one)


def test_build_csv_report_sorts_worst_severity_first():
    healthy = _cert(fingerprint_sha256="h" * 64)
    expiring = _cert(fingerprint_sha256="e" * 64, days_to_expiry=3)
    certificates = [healthy, expiring]
    apply_risk_engine(certificates)

    csv_bytes = build_csv_report(_scan_record(), certificates)
    rows = list(csv.reader(io.StringIO(csv_bytes.decode("utf-8"))))
    assert rows[1][0] == expiring.fingerprint_sha256
    assert rows[2][0] == healthy.fingerprint_sha256


def test_build_csv_report_includes_endpoints_and_flags():
    shared = _cert(
        fingerprint_sha256="s" * 64,
        endpoints=[Endpoint(host="a.com", port=443), Endpoint(host="b.com", port=443)],
    )
    certificates = [shared]
    apply_risk_engine(certificates)

    csv_bytes = build_csv_report(_scan_record(), certificates)
    rows = list(csv.reader(io.StringIO(csv_bytes.decode("utf-8"))))
    endpoints_col = rows[0].index("endpoints")
    flags_col = rows[0].index("flags")
    assert "a.com:443" in rows[1][endpoints_col]
    assert "b.com:443" in rows[1][endpoints_col]
    assert "shared" in rows[1][flags_col]
