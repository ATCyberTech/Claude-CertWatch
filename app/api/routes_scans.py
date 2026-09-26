"""Scan API routes — full Section 13 route table, every handler stubbed.

Request/response shapes are typed now so M2-M8 implement against an already-
agreed contract. Each handler raises HTTPException(501) with a note on which
milestone owns it — this is deliberate scaffolding, not a placeholder someone
forgot to finish.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _not_implemented(owning_milestone: str) -> HTTPException:
    return HTTPException(
        status_code=501,
        detail=f"Not implemented yet — owned by {owning_milestone}. "
        "See the CertWatch MVP Technical Specification v1, Section 13/25.",
    )


# --- Request/response models (Section 13) ---


class ScanSubmitRequest(BaseModel):
    hosts: list[str] = Field(..., description="Hostnames or IPs to scan")
    ports: list[int] | None = Field(
        default=None, description="Optional per-host port override; validated against the allowlist"
    )


class ScanSubmitResponse(BaseModel):
    token: str
    status: str
    report_url: str


class ScanStatusResponse(BaseModel):
    status: str
    summary_counts: dict[str, int]


class AskRequest(BaseModel):
    question: str


class AskResponse(BaseModel):
    answer: str
    citations: list[str]


class AiPreferenceRequest(BaseModel):
    ai_enabled: bool


class AiPreferenceResponse(BaseModel):
    ai_enabled: bool


# --- Routes (Section 13 table, in order) ---


@router.post("", response_model=ScanSubmitResponse, status_code=201)
def submit_scan(request: ScanSubmitRequest) -> ScanSubmitResponse:
    """Owned by M2 (scanning) + M3 (token/storage)."""
    raise _not_implemented("M2/M3")


@router.get("/{token}", response_model=ScanStatusResponse)
def get_scan_status(token: str) -> ScanStatusResponse:
    """Owned by M3 (token lookup) + M4 (summary counts)."""
    raise _not_implemented("M3/M4")


@router.get("/{token}/findings")
def get_scan_findings(token: str, filter: str | None = None, page: int = 1) -> None:
    """Owned by M4 (risk engine output)."""
    raise _not_implemented("M4")


@router.get("/{token}/report.pdf")
def get_scan_report_pdf(token: str) -> None:
    """Owned by M5 (report generation)."""
    raise _not_implemented("M5")


@router.get("/{token}/report.csv")
def get_scan_report_csv(token: str) -> None:
    """Owned by M5 (report generation)."""
    raise _not_implemented("M5")


@router.post("/{token}/ask", response_model=AskResponse)
def ask_certwatch(token: str, request: AskRequest) -> AskResponse:
    """Owned by M7 (AI analyst layer). Subject to Section 18 rate limits when wired."""
    raise _not_implemented("M7")


@router.patch("/{token}/ai-preference", response_model=AiPreferenceResponse)
def set_ai_preference(token: str, request: AiPreferenceRequest) -> AiPreferenceResponse:
    """Owned by M6 (UI toggle) + M7 (enforcement)."""
    raise _not_implemented("M6/M7")
