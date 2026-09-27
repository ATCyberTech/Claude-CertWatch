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
    """The M0 placeholder page was replaced by the real upload/scan page as
    of M6 — see tests/unit/test_web_routes.py for full UI coverage."""
    response = client.get("/")
    assert response.status_code == 200
    assert "CertWatch" in response.text
    assert "Scan" in response.text


def test_ask_unknown_token_is_404(client: TestClient) -> None:
    """`/ask` is implemented as of M7 — see tests/unit/test_routes_scans.py
    and tests/unit/test_ai_analyst.py for full AI-layer coverage. This
    smoke test only proves the route exists and 404s like every other
    `/api/scans/{token}/...` route on an unknown token."""
    response = client.post("/api/scans/some-token/ask", json={"question": "test?"})
    assert response.status_code == 404
