"""Health-check endpoint — fully implemented at M0 (Section 20)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Basic liveness check, per Section 20 ("basic health-check endpoint")."""
    return {"status": "ok", "service": "certwatch"}
