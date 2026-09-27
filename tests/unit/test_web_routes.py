"""Tests for the server-rendered web UI (M6, Section 14)."""

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
    # M8: reset the module-level rate limiter before each test — see the
    # comment above `routes_scans.limiter`'s definition and the matching
    # note in tests/conftest.py's own `client` fixture.
    routes_scans.limiter.reset()
    app = create_app()
    storage = LocalFilesystemStorage(tmp_path)
    app.dependency_overrides[get_object_storage] = lambda: storage
    app.dependency_overrides[get_settings] = lambda: _test_settings(MAX_HOSTS_PER_SCAN=3)
    with TestClient(app, follow_redirects=False) as test_client:
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


# --- GET / (upload/scan page) ---


def test_index_shows_scope_note(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "public port 443 reachability only, no internal network access" in response.text


# --- POST /scan (host-list submission) ---


def test_submit_via_pasted_textarea_redirects_to_scan_page(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    response = client.post("/scan", data={"hosts_text": "a.com\nb.com"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/scans/")


def test_submit_via_uploaded_file(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    response = client.post(
        "/scan",
        data={"hosts_text": ""},
        files={"hosts_file": ("hosts.txt", b"a.com\nb.com\n", "text/plain")},
    )
    assert response.status_code == 303


def test_submit_combines_and_dedupes_textarea_and_file(client, monkeypatch):
    seen_hosts = {}

    async def _capture(hosts, settings):
        seen_hosts["hosts"] = hosts
        return [HostScanOutcome(hostname=h, port=p, status=HostScanStatus.OK) for h, p in hosts]

    monkeypatch.setattr(routes_scans, "scan_hosts", _capture)
    client.post(
        "/scan",
        data={"hosts_text": "a.com, b.com"},
        files={"hosts_file": ("hosts.txt", b"b.com\nc.com\n", "text/plain")},
    )
    assert seen_hosts["hosts"] == [("a.com", 443), ("b.com", 443), ("c.com", 443)]


def test_submit_empty_host_list_rerenders_index_with_error(client):
    response = client.post("/scan", data={"hosts_text": "   \n  "})
    assert response.status_code == 422
    assert "Enter at least one host" in response.text


def test_submit_over_host_cap_rerenders_index_with_error(client, monkeypatch):
    called = False

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(routes_scans, "scan_hosts", _fail_if_called)
    # The test client's settings override caps at 3 hosts.
    response = client.post("/scan", data={"hosts_text": "a.com\nb.com\nc.com\nd.com"})
    assert response.status_code == 422
    assert "exceeds the maximum" in response.text
    assert called is False


# --- GET /scans/{token} (status/risk-summary/inventory/ask/report page) ---


def test_scan_page_unknown_token_is_404(client):
    response = client.get("/scans/never-issued")
    assert response.status_code == 404
    assert "Not found" in response.text


def test_scan_page_shows_risk_summary_and_inventory(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    page = client.get(f"/scans/{token}")
    assert page.status_code == 200
    assert "Risk summary" in page.text
    assert "example.com" in page.text
    assert "Download PDF" in page.text
    assert "Download CSV" in page.text
    assert f"/api/scans/{token}/report.pdf" in page.text
    assert f"/api/scans/{token}/report.csv" in page.text


def test_scan_page_severity_filter_narrows_inventory(client, monkeypatch):
    expiring = _sample_certificate(fingerprint_sha256="expiring".ljust(64, "0"), days_to_expiry=3)
    healthy = _sample_certificate(fingerprint_sha256="healthy".ljust(64, "0"))

    async def _mixed(hosts, settings):
        return [
            HostScanOutcome(
                hostname="expiring.com", port=443, status=HostScanStatus.OK, certificate=expiring
            ),
            HostScanOutcome(
                hostname="healthy.com", port=443, status=HostScanStatus.OK, certificate=healthy
            ),
        ]

    monkeypatch.setattr(routes_scans, "scan_hosts", _mixed)
    submit = client.post("/scan", data={"hosts_text": "expiring.com\nhealthy.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    all_page = client.get(f"/scans/{token}")
    assert "expiring.com" in all_page.text and "healthy.com" in all_page.text

    filtered = client.get(f"/scans/{token}", params={"severity": "critical"})
    assert "expiring.com" in filtered.text
    assert "healthy.com" not in filtered.text


# --- GET /scans/{token}/certificates/{fingerprint} ---


def test_certificate_detail_page(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    page = client.get(f"/scans/{token}")
    fingerprint = "a.com-fp".ljust(64, "0")
    detail = client.get(f"/scans/{token}/certificates/{fingerprint}")
    assert detail.status_code == 200
    assert "example.com" in detail.text
    assert "public_ca" in detail.text
    assert "a.com:443" in detail.text
    del page  # only used to establish the scan exists first


def test_certificate_detail_unknown_token_is_404(client):
    response = client.get(f"/scans/never-issued/certificates/{'a' * 64}")
    assert response.status_code == 404


def test_certificate_detail_unknown_fingerprint_is_404(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    response = client.get(f"/scans/{token}/certificates/{'z' * 64}")
    assert response.status_code == 404


# --- POST /scans/{token}/ai-preference (the M6 toggle control) ---


def test_ai_preference_toggle_persists_and_redirects(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    # Default is AI enabled (Settings.ai_enabled_by_default = True).
    off = client.post(f"/scans/{token}/ai-preference", data={})
    assert off.status_code == 303

    # The JSON API's own GET-equivalent is the PATCH round-trip; verify via
    # the JSON PATCH endpoint that the toggle actually persisted.
    check = client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": False})
    assert check.json() == {"ai_enabled": False}


def test_ai_preference_toggle_unknown_token_is_404(client):
    response = client.post("/scans/never-issued/ai-preference", data={"ai_enabled": "true"})
    assert response.status_code == 404


# --- POST /scans/{token}/ask (M7: real AI layer, no LLM_API_KEY in tests) ---


def test_ask_shows_fallback_message_inline(client, monkeypatch):
    """No `LLM_API_KEY` is configured in the test `Settings` fixture, so
    `build_llm_provider` returns `None` and `app.ai.analyst.answer_question`
    returns its fallback message — this is the real M7 code path, not a
    stub. The page renders that answer inline (200), rather than
    redirecting the way the old M6 placeholder notice did."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    ask = client.post(f"/scans/{token}/ask", data={"question": "What expires soonest?"})
    assert ask.status_code == 200
    assert "What expires soonest?" in ask.text
    assert "isn&#39;t available" in ask.text or "isn't available" in ask.text


def test_ask_unknown_token_is_404(client):
    response = client.post("/scans/never-issued/ask", data={"question": "test?"})
    assert response.status_code == 404


def test_ask_shows_per_scan_cap_message_inline_once_exceeded(client, monkeypatch):
    """M8: once this scan's lifetime `/ask` cap (Section 18: 20/scan) is
    reached, `answer_scan_question` raises `HTTPException(429)` — the web
    UI renders that inline on the same page rather than a raw JSON 429
    (Decision Log), so a person using the Ask box sees a normal page, not
    an error screen."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/scan", data={"hosts_text": "a.com"})
    token = submit.headers["location"].removeprefix("/scans/")

    for _ in range(20):
        response = client.post(f"/scans/{token}/ask", data={"question": "status?"})
        assert response.status_code == 200

    twenty_first = client.post(f"/scans/{token}/ask", data={"question": "status?"})
    assert twenty_first.status_code == 429
    assert "status?" in twenty_first.text


# --- JSON API: PATCH /api/scans/{token}/ai-preference (M6) ---


def test_json_ai_preference_unknown_token_is_404(client):
    response = client.patch("/api/scans/never-issued/ai-preference", json={"ai_enabled": False})
    assert response.status_code == 404


def test_json_ai_preference_round_trips(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    response = client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": False})
    assert response.status_code == 200
    assert response.json() == {"ai_enabled": False}

    # Toggling again reflects the new value, not a cached one.
    response2 = client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": True})
    assert response2.json() == {"ai_enabled": True}
