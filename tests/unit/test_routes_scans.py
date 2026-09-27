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
    # M8: reset the module-level rate limiter before each test — see the
    # comment above `routes_scans.limiter`'s definition and the matching
    # note in tests/conftest.py's own `client` fixture.
    routes_scans.limiter.reset()
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


# --- GET /api/scans/{token}/report.pdf|csv (M5) ---


def test_report_pdf_unknown_token_returns_404(client):
    assert client.get("/api/scans/never-issued/report.pdf").status_code == 404


def test_report_csv_unknown_token_returns_404(client):
    assert client.get("/api/scans/never-issued/report.csv").status_code == 404


def test_report_pdf_is_persisted_at_submission_and_downloadable(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    response = client.get(f"/api/scans/{token}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")
    assert "certwatch-report.pdf" in response.headers["content-disposition"]


def test_report_pdf_regenerates_on_the_fly_when_not_persisted(client, monkeypatch, tmp_path):
    """Defensive fallback for a pre-M5 scan record with no stored PDF."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    storage = LocalFilesystemStorage(tmp_path)
    storage.delete(routes_scans.report_storage_key(token))

    response = client.get(f"/api/scans/{token}/report.pdf")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")


def test_report_csv_downloadable_and_matches_findings(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    response = client.get(f"/api/scans/{token}/report.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "certwatch-report.csv" in response.headers["content-disposition"]
    lines = response.text.strip().splitlines()
    assert lines[0].startswith("certificate_id,subject_cn")
    assert len(lines) == 2  # header + one certificate

    findings = client.get(f"/api/scans/{token}/findings").json()["findings"]
    assert findings[0]["certificate_id"] in lines[1]


def test_report_csv_never_persisted_to_storage(client, monkeypatch, tmp_path):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]
    client.get(f"/api/scans/{token}/report.csv")

    storage = LocalFilesystemStorage(tmp_path)
    assert storage.get(f"scans/{token}/report.csv") is None


# --- POST /api/scans/{token}/ask (M7: AI analyst layer) ---
#
# No `LLM_API_KEY` is set in these tests' `Settings`, so `build_llm_provider`
# returns `None` and every one of these exercises the real
# `answer_scan_question` -> `app.ai.analyst.answer_question` code path, not a
# stub — the fallback path is exactly what a user with no key configured
# gets. `FakeLLMProvider` (below) stands in for a real `LLMProvider` to
# exercise the grounded/ungrounded/unavailable branches without a network
# call, via `build_llm_provider` monkeypatched per-test.


class FakeLLMProvider:
    """A minimal `LLMProvider` for tests — never touches the network."""

    def __init__(self, response, raises: Exception | None = None) -> None:
        self._response = response
        self._raises = raises
        self.calls: list[str] = []

    def ask(self, question, scan_token, tools):
        self.calls.append(question)
        if self._raises is not None:
            raise self._raises
        return self._response


def test_ask_unknown_token_is_404(client):
    response = client.post("/api/scans/never-issued/ask", json={"question": "test?"})
    assert response.status_code == 404


def test_ask_with_no_configured_provider_returns_fallback(client, monkeypatch):
    """The default test `Settings` has no `LLM_API_KEY` — this is the same
    fallback a real user with no key configured sees; there is no LLM call
    to fake here at all."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    response = client.post(f"/api/scans/{token}/ask", json={"question": "What expires soonest?"})
    assert response.status_code == 200
    body = response.json()
    assert "already complete" in body["answer"]
    assert body["citations"] == []


def test_ask_disabled_for_scan_skips_provider_entirely(client, monkeypatch):
    """Section 16's central guarantee: when `scan.ai_enabled` is False, the
    provider is never constructed or called, even if one is configured."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]
    client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": False})

    fake = FakeLLMProvider(response=None)
    monkeypatch.setattr(routes_scans, "build_llm_provider", lambda settings: fake)

    response = client.post(f"/api/scans/{token}/ask", json={"question": "Anything critical?"})
    assert response.status_code == 200
    assert "already complete" in response.json()["answer"]
    assert fake.calls == []


def test_ask_provider_unavailable_returns_fallback(client, monkeypatch):
    from app.ai.llm_client import LLMUnavailableError

    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    fake = FakeLLMProvider(response=None, raises=LLMUnavailableError("boom"))
    monkeypatch.setattr(routes_scans, "build_llm_provider", lambda settings: fake)

    response = client.post(f"/api/scans/{token}/ask", json={"question": "Anything critical?"})
    assert response.status_code == 200
    assert "already complete" in response.json()["answer"]
    assert fake.calls == ["Anything critical?"]


def test_ask_ungrounded_answer_falls_back(client, monkeypatch):
    """An answer naming a host the model never saw in a tool result must be
    rejected, not returned to the user (Section 16's grounding/citation
    check)."""
    from app.ai.llm_client import GroundedAnswer

    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    ungrounded = GroundedAnswer(text="Everything looks fine at totally-invented-host.net.")
    fake = FakeLLMProvider(response=ungrounded)
    monkeypatch.setattr(routes_scans, "build_llm_provider", lambda settings: fake)

    response = client.post(f"/api/scans/{token}/ask", json={"question": "Anything critical?"})
    assert response.status_code == 200
    assert "already complete" in response.json()["answer"]


def test_ask_grounded_answer_returns_real_text_and_citations(client, monkeypatch):
    from app.ai.llm_client import GroundedAnswer, ToolCallResult

    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    # The answer is "grounded" because it only names a certificate/host that
    # actually appeared in a tool result the (fake) model received.
    tool_call = ToolCallResult(
        tool_name="get_findings",
        arguments={},
        result={"findings": [{"subject_cn": "example.com", "san_list": [], "endpoints": []}]},
    )
    grounded = GroundedAnswer(
        text="example.com looks healthy, expiring in 365 days.",
        tool_calls=[tool_call],
    )
    fake = FakeLLMProvider(response=grounded)
    monkeypatch.setattr(routes_scans, "build_llm_provider", lambda settings: fake)

    response = client.post(f"/api/scans/{token}/ask", json={"question": "How's example.com?"})
    assert response.status_code == 200
    body = response.json()
    assert body["answer"] == "example.com looks healthy, expiring in 365 days."
    assert "example.com" in body["citations"]
    assert fake.calls == ["How's example.com?"]


def test_build_llm_provider_returns_none_without_api_key():
    settings = _test_settings()
    assert routes_scans.build_llm_provider(settings) is None


def test_build_llm_provider_constructs_anthropic_provider_with_key():
    from app.ai.llm_client import AnthropicProvider

    settings = _test_settings(LLM_API_KEY="sk-test-key", LLM_MODEL="claude-test-model")
    provider = routes_scans.build_llm_provider(settings)
    assert isinstance(provider, AnthropicProvider)


# --- M8: rate limiting (Section 18) ---


def test_rate_limit_constants_match_section_18_exactly():
    """Section 18 states these two numbers explicitly; a code change to
    either constant is the only way to change what's enforced (Decision
    Log) — this pins them against an accidental edit."""
    assert routes_scans._SUBMIT_RATE_LIMIT == "5/hour"
    assert routes_scans._ASK_IP_RATE_LIMIT == "60/hour"


def test_submit_scan_sixth_submission_in_one_hour_is_429(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    for _ in range(5):
        response = client.post("/api/scans", json={"hosts": ["example.com"]})
        assert response.status_code == 201

    sixth = client.post("/api/scans", json={"hosts": ["example.com"]})
    assert sixth.status_code == 429


def test_ask_per_scan_lifetime_cap_returns_429_on_the_21st_question(client, monkeypatch):
    """Section 18: 20 questions/scan is a lifetime cap, not a sliding
    window — the 21st call on the same scan must be rejected even with no
    provider configured (every accepted call counts, per the Decision
    Log), while the per-IP-hourly cap (60/hour) is not implicated since
    21 < 60."""
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    for _ in range(20):
        response = client.post(f"/api/scans/{token}/ask", json={"question": "status?"})
        assert response.status_code == 200

    twenty_first = client.post(f"/api/scans/{token}/ask", json={"question": "status?"})
    assert twenty_first.status_code == 429


def test_response_carries_referrer_policy_header(client):
    response = client.get("/api/scans/unknown-token")
    assert response.headers["referrer-policy"] == "no-referrer"


# --- M8: DELETE /api/scans/{token} (Section 21's deletion endpoint) ---


def test_delete_scan_returns_204_and_removes_the_scan(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    delete_response = client.delete(f"/api/scans/{token}")
    assert delete_response.status_code == 204

    status_response = client.get(f"/api/scans/{token}")
    assert status_response.status_code == 404


def test_delete_scan_unknown_token_is_404(client):
    response = client.delete("/api/scans/does-not-exist")
    assert response.status_code == 404


def test_delete_scan_twice_is_404_the_second_time(client, monkeypatch):
    monkeypatch.setattr(routes_scans, "scan_hosts", _fake_scan_hosts_all_ok)
    submit = client.post("/api/scans", json={"hosts": ["a.com"]})
    token = submit.json()["token"]

    first = client.delete(f"/api/scans/{token}")
    assert first.status_code == 204

    second = client.delete(f"/api/scans/{token}")
    assert second.status_code == 404
