"""API-level tests for the M3-implemented scan routes.

`app.scanning.scan_hosts` is monkeypatched to return canned outcomes for
most tests — the real scanning engine (network_guard/tls_client/scanner)
already has its own full test suite (M2); these tests are about the API
wiring, request validation, and persistence, not re-proving M2.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

import app.api.routes_scans as routes_scans
from app.core.config import Settings, get_settings
from app.main import create_app
from app.parsing.models import Certificate, ChainCategory
from app.scanning.scanner import HostScanOutcome, HostScanStatus
from app.storage import get_object_storage
from app.storage.local_filesystem import LocalFilesystemStorage


def _test_settings(**overrides) -> Settings:
    return Settings(**overrides)


def _sample_certificate(**overrides) -> Certificate:
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


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:
    app = create_app()
    storage = LocalFilesystemStorage(tmp_path)
    app.dependency_overrides[get_object_storage] = lambda: storage
    app.dependency_overrides[get_settings] = lambda: _test_settings(MAX_HOSTS_PER_SCAN=3)
    with TestClient(app) as test_client:
        yield test_client


async def _fake_scan_hosts_all_ok(hosts, settings):
    return [
        HostScanOutcome(
            hostname=h,
            port=p,
            status=HostScanStatus.OK,
            certificate=_sample_certificate(fingerprint_sha256=f"{h}-fp".ljust(64, "0")),
        )
        for h, p in hosts
    ]


def test_submit_scan_returns_token_and_report_url(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    response = client.post("/api/scans", json={"hosts": ["example.com"]})
    assert response.status_code == 201
    body = response.json()
    assert len(body["token"]) >= 43
    assert body["status"] == "complete"
    assert body["token"] in body["report_url"]
    assert body["report_url"].endswith("/report.pdf")


def test_submit_scan_defaults_port_to_443(client, monkeypatch):
    seen_hosts = {}

    async def _capture(hosts, settings):
        seen_hosts["hosts"] = hosts
        return [HostScanOutcome(hostname=h, port=p, status=HostScanStatus.OK) for h, p in hosts]

    monkeypatch.setattr(routes_scans, "scan_hosts", _capture)
    client.post("/api/scans", json={"hosts": ["a.com", "b.com"]})
    assert seen_hosts["hosts"] == [("a.com", 443), ("b.com", 443)]


def test_submit_scan_ports_index_aligned_with_hosts(client, monkeypatch):
    seen_hosts = {}

    async def _capture(hosts, settings):
        seen_hosts["hosts"] = hosts
        return [HostScanOutcome(hostname=h, port=p, status=HostScanStatus.OK) for h, p in hosts]

    monkeypatch.setattr(routes_scans, "scan_hosts", _capture)
    client.post("/api/scans", json={"hosts": ["a.com", "b.com"], "ports": [8443, 993]})
    assert seen_hosts["hosts"] == [("a.com", 8443), ("b.com", 993)]


def test_submit_scan_ports_length_mismatch_is_422(client, monkeypatch):
    called = False

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(routes_scans, "scan_hosts", _fail_if_called)
    response = client.post("/api/scans", json={"hosts": ["a.com", "b.com"], "ports": [443]})
    assert response.status_code == 422
    assert called is False


def test_submit_scan_host_count_exceeds_cap_is_422_before_any_scan(client, monkeypatch):
    called = False

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(routes_scans, "scan_hosts", _fail_if_called)
    # The test client's settings override caps at 3 hosts.
    response = client.post("/api/scans", json={"hosts": ["a.com", "b.com", "c.com", "d.com"]})
    assert response.status_code == 422
    assert called is False


def test_submit_scan_empty_hosts_is_422(client):
    response = client.post("/api/scans", json={"hosts": []})
    assert response.status_code == 422


def test_status_lookup_after_submit_matches_persisted_result(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com", "b.com"]})
    token = submit.json()["token"]

    status = client.get(f"/api/scans/{token}")
    assert status.status_code == 200
    body = status.json()
    assert body["status"] == "complete"
    assert body["summary_counts"] == {"ok": 2}


def test_status_lookup_mixed_outcomes_summary_counts(client, monkeypatch):
    async def _mixed(hosts, settings):
        return [
            HostScanOutcome(
                hostname="a.com",
                port=443,
                status=HostScanStatus.OK,
                certificate=_sample_certificate(),
            ),
            HostScanOutcome(hostname="b.com", port=22, status=HostScanStatus.DISALLOWED_PORT),
        ]

    monkeypatch.setattr(routes_scans, "scan_hosts", _mixed)
    submit = client.post("/api/scans", json={"hosts": ["a.com", "b.com"]})
    token = submit.json()["token"]

    status = client.get(f"/api/scans/{token}")
    # "b.com" never got a certificate (disallowed port) → its own scan_failed
    # bucket; the risk-severity vocabulary supersedes M3's raw status counts
    # (Decision Log, M4).
    assert status.json()["summary_counts"] == {"ok": 1, "scan_failed": 1}


def test_unknown_token_returns_404(client):
    response = client.get("/api/scans/this-token-was-never-issued")
    assert response.status_code == 404


def test_one_scans_token_cannot_reach_another_scans_data(client, monkeypatch):
    """Isolation test (Section 12/22): tokens are unguessable and unrelated
    scans' data is never reachable through a different token."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    first = client.post("/api/scans", json={"hosts": ["a.com"]})
    second = client.post("/api/scans", json={"hosts": ["b.com"]})
    token_a = first.json()["token"]
    token_b = second.json()["token"]
    assert token_a != token_b

    status_a = client.get(f"/api/scans/{token_a}").json()
    status_b = client.get(f"/api/scans/{token_b}").json()
    # Each token's own status reflects only its own scan.
    assert status_a == status_b  # same shape (both single-host, both ok)
    # But swapping in a mangled token never resolves to the other scan by
    # accident — a one-character mutation is a 404, not a hit.
    mangled = token_a[:-1] + ("A" if token_a[-1] != "A" else "B")
    assert client.get(f"/api/scans/{mangled}").status_code == 404


def test_source_ip_never_returned_in_status_response(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post(
        "/api/scans", json={"hosts": ["a.com"]}, headers={"X-Forwarded-For": "203.0.113.9"}
    )
    token = submit.json()["token"]
    status = client.get(f"/api/scans/{token}")
    assert "source_ip" not in status.json()
    assert "203.0.113.9" not in status.text


# --- GET /api/scans/{token}/findings (M4) ---


def test_findings_unknown_token_returns_404(client):
    assert client.get("/api/scans/never-issued/findings").status_code == 404


def test_findings_groups_by_certificate_and_reports_shared_endpoints(client, monkeypatch):
    shared_cert = _sample_certificate(fingerprint_sha256="shared".ljust(64, "0"))

    async def _shared(hosts, settings):
        return [
            HostScanOutcome(hostname=h, port=p, status=HostScanStatus.OK, certificate=shared_cert)
            for h, p in hosts
        ]

    monkeypatch.setattr(routes_scans, "scan_hosts", _shared)
    submit = client.post("/api/scans", json={"hosts": ["a.com", "b.com"]})
    token = submit.json()["token"]

    findings = client.get(f"/api/scans/{token}/findings").json()
    assert findings["total"] == 1
    assert len(findings["findings"]) == 1
    finding = findings["findings"][0]
    assert finding["certificate_id"] == shared_cert.fingerprint_sha256
    assert {(e["host"], e["port"]) for e in finding["endpoints"]} == {
        ("a.com", 443),
        ("b.com", 443),
    }
    assert finding["risk_severity"] == "shared"
    assert "shared" in finding["flags"]


def test_findings_severity_filter(client, monkeypatch):
    expiring_cert = _sample_certificate(
        fingerprint_sha256="expiring".ljust(64, "0"), days_to_expiry=3
    )
    healthy_cert = _sample_certificate(fingerprint_sha256="healthy".ljust(64, "0"))

    async def _mixed(hosts, settings):
        return [
            HostScanOutcome(
                hostname="expiring.com",
                port=443,
                status=HostScanStatus.OK,
                certificate=expiring_cert,
            ),
            HostScanOutcome(
                hostname="healthy.com",
                port=443,
                status=HostScanStatus.OK,
                certificate=healthy_cert,
            ),
        ]

    monkeypatch.setattr(routes_scans, "scan_hosts", _mixed)
    submit = client.post("/api/scans", json={"hosts": ["expiring.com", "healthy.com"]})
    token = submit.json()["token"]

    all_findings = client.get(f"/api/scans/{token}/findings").json()
    assert all_findings["total"] == 2
    # Worst severity first.
    assert all_findings["findings"][0]["risk_severity"] == "critical"

    filtered = client.get(f"/api/scans/{token}/findings", params={"severity": "critical"}).json()
    assert filtered["total"] == 1
    assert filtered["findings"][0]["subject_cn"] == "example.com"
    assert filtered["findings"][0]["days_to_expiry"] == 3


def test_findings_pagination_within_cap(client, monkeypatch):
    certs = [_sample_certificate(fingerprint_sha256=str(i).ljust(64, "0")) for i in range(3)]

    async def _many(hosts, settings):
        return [
            HostScanOutcome(hostname=h, port=p, status=HostScanStatus.OK, certificate=certs[i])
            for i, (h, p) in enumerate(hosts)
        ]

    monkeypatch.setattr(routes_scans, "scan_hosts", _many)
    submit = client.post("/api/scans", json={"hosts": ["h0.com", "h1.com", "h2.com"]})
    token = submit.json()["token"]

    page1 = client.get(f"/api/scans/{token}/findings", params={"page": 1, "page_size": 2}).json()
    assert len(page1["findings"]) == 2
    assert page1["total"] == 3
    page2 = client.get(f"/api/scans/{token}/findings", params={"page": 2, "page_size": 2}).json()
    assert len(page2["findings"]) == 1


def test_findings_one_scans_token_cannot_reach_another_scans_findings(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    first = client.post("/api/scans", json={"hosts": ["a.com"]})
    second = client.post("/api/scans", json={"hosts": ["b.com"]})
    token_a = first.json()["token"]
    token_b = second.json()["token"]

    findings_a = client.get(f"/api/scans/{token_a}/findings").json()
    findings_b = client.get(f"/api/scans/{token_b}/findings").json()
    assert findings_a["findings"][0]["subject_cn"] == "example.com"
    assert findings_b["findings"][0]["subject_cn"] == "example.com"
    assert (
        findings_a["findings"][0]["certificate_id"] != findings_b["findings"][0]["certificate_id"]
    )
