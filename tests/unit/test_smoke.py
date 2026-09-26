"""M0 smoke test: the application boots and the health endpoint responds.

This is the M0 acceptance test — it proves the repository skeleton, dependency
management, and test framework all work together, not that any product
feature exists yet.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_healthz_returns_ok(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "certwatch"


def test_index_page_renders(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "CertWatch" in response.text
    assert "not yet implemented" in response.text


def test_scan_findings_not_yet_implemented(client: TestClient) -> None:
    """M4 (risk engine output) owns this route — `/api/scans` itself is
    implemented as of M3; see tests/unit/test_routes_scans.py for that."""
    response = client.get("/api/scans/some-token/findings")
    assert response.status_code == 501
    assert "M4" in response.json()["detail"]
