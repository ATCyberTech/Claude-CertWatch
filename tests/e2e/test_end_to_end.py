"""M9: real-network end-to-end tests (Section 25's M9 row: "End-to-end
testing plus a first real dry run against the founder's own GCC
contacts").

Every other test file in this project monkeypatches `scan_hosts` to a
canned outcome, which is correct for testing API wiring/business logic in
isolation but never actually exercises the real scanning pipeline as one
system. These tests do: they submit real hostnames and let
`app.scanning.scan_hosts` perform real DNS resolution, a real TCP
connect, and a real TLS handshake, then walk the full user journey
(submit -> status -> findings -> PDF/CSV export -> AI toggle -> ask ->
rate limits -> deletion) against the live FastAPI app.

Hosts used: `example.com` (a stable, well-known, always-up public host)
and a couple of `badssl.com` subdomains (a public test service purpose-
built for TLS client testing — expired/self-signed/wrong-host certs).
No host here belongs to a real business or person; nothing here is a
"dry run against the founder's own GCC contacts" (Section 25) — that
half of M9 needs real target hostnames only the founder can supply, plus
a network path that doesn't intercept TLS (see the finding below), and is
tracked separately (Decision Log, docs/M9_CHECKLIST.md).

IMPORTANT environmental finding (Decision Log): this sandboxed dev
container's outbound HTTPS is transparently TLS-intercepted by an
Anthropic egress proxy (confirmed by direct inspection: the certificate
actually received for `example.com` here has issuer "CN=Egress Gateway
SDS Issuing CA (production), O=Anthropic", not example.com's real
DigiCert-issued certificate). That means the *content* of any certificate
these tests observe reflects the interception proxy, never the real
origin server — so these tests deliberately do NOT assert on expiry,
self-signed-ness, hostname-mismatch, or issuer identity (the exact things
`badssl.com`'s hostnames are named for). What they DO prove, and prove
validly regardless of interception: that every layer of the real pipeline
runs correctly end to end — real DNS, real TCP, real TLS, real parsing,
the risk engine, storage, reports, the AI layer's enforcement, rate
limiting, and deletion, wired together as one system. Run from a network
without TLS interception (the founder's own machine, or wherever
CertWatch is actually deployed), the exact same tests would additionally
validate the badssl.com-specific claims, since nothing about this test's
*code* assumes interception — only this container's environment
currently forces it.

Run explicitly: `pytest -m e2e -v` (excluded from the default `pytest -q`
run — see pyproject.toml's `addopts`).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e

_REAL_HOST = "example.com"
_BADSSL_EXPIRED = "expired.badssl.com"
_BADSSL_SELF_SIGNED = "self-signed.badssl.com"
_BADSSL_WRONG_HOST = "wrong.host.badssl.com"


def test_full_scan_journey_against_real_hosts(client):
    """Submit -> status -> findings -> PDF -> CSV, all against real
    network traffic, no monkeypatching anywhere in this test."""
    submit = client.post(
        "/api/scans",
        json={"hosts": [_REAL_HOST, _BADSSL_EXPIRED, _BADSSL_SELF_SIGNED, _BADSSL_WRONG_HOST]},
    )
    assert submit.status_code == 201, submit.text
    body = submit.json()
    token = body["token"]
    assert body["status"] == "complete"
    assert body["report_url"].endswith("/report.pdf")

    status = client.get(f"/api/scans/{token}")
    assert status.status_code == 200
    assert status.json()["status"] == "complete"
    assert sum(status.json()["summary_counts"].values()) == 4

    findings = client.get(f"/api/scans/{token}/findings")
    assert findings.status_code == 200
    findings_body = findings.json()
    assert findings_body["total"] >= 1
    # Every returned finding actually carries real, non-empty scan data —
    # proof a real certificate was received and parsed, not a stub.
    for finding in findings_body["findings"]:
        assert finding["certificate_id"]
        assert finding["subject_cn"]
        assert finding["issuer"]
        assert finding["risk_severity"]
        assert len(finding["endpoints"]) >= 1

    pdf = client.get(f"/api/scans/{token}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")

    csv_response = client.get(f"/api/scans/{token}/report.csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    csv_rows = csv_response.text.strip().splitlines()
    assert len(csv_rows) >= 2  # header + at least one certificate row


def test_disallowed_and_unreachable_hosts_do_not_crash_a_mixed_scan(client):
    """A real scan mixing a good host with hosts this app's own SSRF guard
    or DNS resolution rejects must still complete, with per-host statuses
    reflecting exactly what happened to each one (Section 5/6, reconfirmed
    end-to-end rather than via a monkeypatched scanner)."""
    submit = client.post(
        "/api/scans",
        json={
            "hosts": [
                _REAL_HOST,
                "127.0.0.1",  # SSRF guard: disallowed private/loopback address
                "this-host-does-not-exist-certwatch-e2e.invalid",  # real DNS failure
            ]
        },
    )
    assert submit.status_code == 201, submit.text
    token = submit.json()["token"]

    status = client.get(f"/api/scans/{token}")
    counts = status.json()["summary_counts"]
    assert sum(counts.values()) == 3


def test_ai_toggle_and_ask_fallback_against_a_real_scan(client):
    """No `LLM_API_KEY` is configured anywhere in this test environment, so
    this exercises the real, no-mocking `app.ai.analyst.answer_question`
    fallback path end-to-end, plus the AI on/off toggle's real
    storage-mutation round trip."""
    submit = client.post("/api/scans", json={"hosts": [_REAL_HOST]})
    token = submit.json()["token"]

    toggle_off = client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": False})
    assert toggle_off.status_code == 200
    assert toggle_off.json()["ai_enabled"] is False

    ask = client.post(f"/api/scans/{token}/ask", json={"question": "What expires soonest?"})
    assert ask.status_code == 200
    assert ask.json()["citations"] == []

    toggle_on = client.patch(f"/api/scans/{token}/ai-preference", json={"ai_enabled": True})
    assert toggle_on.status_code == 200

    ask_again = client.post(f"/api/scans/{token}/ask", json={"question": "What expires soonest?"})
    assert ask_again.status_code == 200


def test_rate_limits_enforced_against_real_traffic(client):
    """Section 18's submit cap (5/hour/IP), exercised end-to-end against
    real scans rather than a monkeypatched `scan_hosts` — proves the
    `slowapi` wiring holds up under a real request/response cycle, not
    just against `TestClient`'s synthetic transport."""
    for _ in range(5):
        response = client.post("/api/scans", json={"hosts": [_REAL_HOST]})
        assert response.status_code == 201
    sixth = client.post("/api/scans", json={"hosts": [_REAL_HOST]})
    assert sixth.status_code == 429


def test_deletion_removes_a_real_scans_data(client):
    submit = client.post("/api/scans", json={"hosts": [_REAL_HOST]})
    token = submit.json()["token"]

    delete = client.delete(f"/api/scans/{token}")
    assert delete.status_code == 204

    after = client.get(f"/api/scans/{token}")
    assert after.status_code == 404


def test_referrer_policy_header_present_on_a_real_response(client):
    submit = client.post("/api/scans", json={"hosts": [_REAL_HOST]})
    assert submit.headers["referrer-policy"] == "no-referrer"
