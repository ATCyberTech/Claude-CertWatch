"""Scan API routes — full Section 13 route table.

`submit_scan` and `get_scan_status` are implemented as of M3 (object-
storage persistence, token generation and lookup — Section 11/12). Every
other handler remains a stub: each raises HTTPException(501) with a note
on which milestone owns it — deliberate scaffolding, not a placeholder
someone forgot to finish.

Rate limiting (Section 13's "5 submissions/hour/IP", "20 questions/scan;
60/hour/IP") is explicitly M8's job (Section 18) and is NOT implemented
here yet — `submit_scan` currently has no request-rate limit of its own.

Port-assignment note (M3 implementation clarification, recorded in the
Decision Log): Section 13 describes `ports` only as "optional per-host
port override" without stating its shape. This implementation treats it
as index-aligned with `hosts` (`ports[i]` applies to `hosts[i]`) when
provided, and defaults every host to port 443 when omitted — the most
common TLS port and consistent with Section 19's own worked examples.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from app.core.config import Settings, get_settings
from app.scanning.scanner import scan_hosts
from app.storage import get_object_storage
from app.storage.interface import ObjectStorage
from app.storage.scan_store import (
    ScanRecord,
    generate_scan_token,
    host_outcome_to_record,
    load_scan_record,
    save_scan_record,
    summarize_host_statuses,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

_DEFAULT_SCAN_PORT = 443


def _not_implemented(owning_milestone: str) -> HTTPException:
    return HTTPException(
        status_code=501,
        detail=f"Not implemented yet — owned by {owning_milestone}. "
        "See the CertWatch MVP Technical Specification v1, Section 13/25.",
    )


# --- Request/response models (Section 13) ---


class ScanSubmitRequest(BaseModel):
    hosts: list[str] = Field(..., min_length=1, description="Hostnames or IPs to scan")
    ports: list[int] | None = Field(
        default=None,
        description="Optional per-host port override, index-aligned with `hosts`; "
        "defaults to 443 for every host when omitted. Validated against the "
        "allowlist per host (Section 5), never rejected as a whole request.",
    )

    @model_validator(mode="after")
    def _ports_length_matches_hosts(self) -> ScanSubmitRequest:
        if self.ports is not None and len(self.ports) != len(self.hosts):
            raise ValueError(
                f"ports has {len(self.ports)} entries but hosts has {len(self.hosts)} — "
                "they must be the same length (ports[i] applies to hosts[i])"
            )
        return self


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
async def submit_scan(
    payload: ScanSubmitRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: ObjectStorage = Depends(get_object_storage),
) -> ScanSubmitResponse:
    """Section 13: `POST /api/scans`.

    Host count is capped at `settings.max_hosts_per_scan` (Section 19/24);
    over the cap is a 422, not a silently-truncated scan. Runs the scan
    synchronously against `app.scanning.scan_hosts` (M2) — Section 2's own
    architecture table places "Background jobs" as "None customer-facing"
    at v0, so there is no job queue to hand this off to; Section 19's own
    worst-case estimate (250 hosts, ~85 seconds) is sized for exactly this.
    """
    host_count = len(payload.hosts)
    if host_count > settings.max_hosts_per_scan:
        raise HTTPException(
            status_code=422,
            detail=f"{host_count} hosts exceeds the maximum of "
            f"{settings.max_hosts_per_scan} hosts per scan.",
        )

    ports = payload.ports or [_DEFAULT_SCAN_PORT] * host_count
    host_port_pairs = list(zip(payload.hosts, ports, strict=True))

    token = generate_scan_token()
    outcomes = await scan_hosts(host_port_pairs, settings)

    record = ScanRecord(
        token=token,
        submitted_at=datetime.now(UTC),
        host_count=host_count,
        status="complete",
        source_ip=request.client.host if request.client else None,
        ai_enabled=settings.ai_enabled_by_default,
        host_results=[host_outcome_to_record(outcome) for outcome in outcomes],
    )
    save_scan_record(storage, record)

    report_url = str(request.url_for("get_scan_report_pdf", token=token))
    return ScanSubmitResponse(token=token, status=record.status, report_url=report_url)


@router.get("/{token}", response_model=ScanStatusResponse)
async def get_scan_status(
    token: str, storage: ObjectStorage = Depends(get_object_storage)
) -> ScanStatusResponse:
    """Section 13: `GET /api/scans/{token}`. Token is the sole access
    control (Section 12) — there is no other authorization check.

    `summary_counts` here is `HostScanStatus` counts (M3-scoped), not the
    risk-severity tiers Section 9's deterministic risk engine will
    eventually produce — see `app.storage.scan_store`'s module docstring.
    The response shape does not change when M4 lands.
    """
    record = load_scan_record(storage, token)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")
    return ScanStatusResponse(
        status=record.status, summary_counts=summarize_host_statuses(record.host_results)
    )


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
