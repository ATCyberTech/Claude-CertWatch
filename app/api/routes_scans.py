"""Scan API routes — full Section 13 route table.

`submit_scan`, `get_scan_status` (M3), `get_scan_findings` (M4), and
`get_scan_report_pdf`/`get_scan_report_csv` (M5) are implemented. Every
other handler remains a stub: each raises HTTPException(501) with a note
on which milestone owns it — deliberate scaffolding, not a placeholder
someone forgot to finish.

Report generation note (M5 implementation decision, recorded in the
Decision Log): the PDF is rendered once, synchronously, at the end of
`submit_scan` and persisted to `scans/{token}/report.pdf` (Section 11's
storage layout lists it there, alongside `result.json`) — `report_url` in
`ScanSubmitResponse` is meaningful as soon as the scan itself completes,
with no separate wait. `get_scan_report_pdf` regenerates on the fly, as a
defensive fallback, only for a scan record persisted before this
implementation existed (a dev-only scenario — there is no real production
data yet). The CSV export is never persisted (Section 11 lists no CSV
storage key) and is always generated fresh per request.

Rate limiting (Section 13's "5 submissions/hour/IP", "20 questions/scan;
60/hour/IP") is explicitly M8's job (Section 18) and is NOT implemented
here yet — `submit_scan` currently has no request-rate limit of its own.

Port-assignment note (M3 implementation clarification, recorded in the
Decision Log): Section 13 describes `ports` only as "optional per-host
port override" without stating its shape. This implementation treats it
as index-aligned with `hosts` (`ports[i]` applies to `hosts[i]`) when
provided, and defaults every host to port 443 when omitted — the most
common TLS port and consistent with Section 19's own worked examples.

Findings pagination/filter note (M4 implementation clarification, recorded
in the Decision Log): Section 13 lists the `/findings` request as just
"filter, page" without naming the filter field(s) or a page size. This
implementation filters on `severity` (matching a finding's computed
`risk_severity` — the only per-finding categorical value Section 9 itself
defines) and paginates with `page`/`page_size` (default 50, capped at 200).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, model_validator

from app.core.config import Settings, get_settings
from app.parsing.models import Certificate
from app.reports.report_builder import build_csv_report, build_pdf_report
from app.risk.risk_engine import (
    apply_risk_engine,
    evaluate_flags,
    group_into_certificates,
    severity_sort_key,
    summarize_risk_severity,
)
from app.scanning.scanner import scan_hosts
from app.storage import get_object_storage
from app.storage.interface import ObjectStorage
from app.storage.scan_store import (
    ScanRecord,
    generate_scan_token,
    host_outcome_to_record,
    load_scan_record,
    report_storage_key,
    save_scan_record,
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


class FindingEndpointResponse(BaseModel):
    host: str
    port: int
    environment: str | None = None
    owner: str | None = None


class FindingResponse(BaseModel):
    """Section 13/17's finding shape — the same fields the AI layer's
    `get_findings(filter)` tool will be scoped to (M7): `{certificate_id,
    subject_cn, san_list, issuer, days_to_expiry, risk_severity,
    chain_category, endpoints, flags}`."""

    certificate_id: str
    subject_cn: str
    san_list: list[str]
    issuer: str
    days_to_expiry: int | None
    risk_severity: str
    chain_category: str | None
    endpoints: list[FindingEndpointResponse]
    flags: list[str]


class FindingsPageResponse(BaseModel):
    findings: list[FindingResponse]
    page: int
    page_size: int
    total: int


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

    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    storage.put(report_storage_key(token), build_pdf_report(record, certificates))

    report_url = str(request.url_for("get_scan_report_pdf", token=token))
    return ScanSubmitResponse(token=token, status=record.status, report_url=report_url)


@router.get("/{token}", response_model=ScanStatusResponse)
async def get_scan_status(
    token: str, storage: ObjectStorage = Depends(get_object_storage)
) -> ScanStatusResponse:
    """Section 13: `GET /api/scans/{token}`. Token is the sole access
    control (Section 12) — there is no other authorization check.

    `summary_counts` is a per-host risk-severity summary as of M4 (see
    `app.risk.risk_engine.summarize_risk_severity`) — the same field name
    and response shape as M3's provisional `HostScanStatus` counts, just a
    different vocabulary populating it (Decision Log).
    """
    record = load_scan_record(storage, token)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")
    return ScanStatusResponse(status=record.status, summary_counts=summarize_risk_severity(record))


_DEFAULT_FINDINGS_PAGE_SIZE = 50
_MAX_FINDINGS_PAGE_SIZE = 200


def _finding_from_certificate(
    certificate: Certificate, all_certificates_in_scan: list[Certificate]
) -> FindingResponse:
    return FindingResponse(
        certificate_id=certificate.fingerprint_sha256,
        subject_cn=certificate.subject_cn,
        san_list=certificate.san_list,
        issuer=certificate.issuer,
        days_to_expiry=certificate.days_to_expiry,
        risk_severity=certificate.risk_severity or "ok",
        chain_category=certificate.chain_category.value if certificate.chain_category else None,
        endpoints=[
            FindingEndpointResponse(
                host=endpoint.host,
                port=endpoint.port,
                environment=endpoint.environment,
                owner=endpoint.owner,
            )
            for endpoint in certificate.endpoints
        ],
        flags=evaluate_flags(certificate, all_certificates_in_scan),
    )


@router.get("/{token}/findings", response_model=FindingsPageResponse)
async def get_scan_findings(
    token: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(_DEFAULT_FINDINGS_PAGE_SIZE, ge=1, le=_MAX_FINDINGS_PAGE_SIZE),
    severity: str | None = Query(
        None, description="Filter to findings whose risk_severity matches exactly."
    ),
    storage: ObjectStorage = Depends(get_object_storage),
) -> FindingsPageResponse:
    """Section 13: `GET /api/scans/{token}/findings` — "paginated findings",
    now that M4's risk engine has something to serve (see the module
    docstring for the filter/pagination shape this implementation chose).
    """
    record = load_scan_record(storage, token)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")

    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    certificates.sort(key=lambda c: (severity_sort_key(c.risk_severity or "ok"), c.subject_cn))

    findings = [_finding_from_certificate(c, certificates) for c in certificates]
    if severity is not None:
        findings = [f for f in findings if f.risk_severity == severity]

    total = len(findings)
    start = (page - 1) * page_size
    page_items = findings[start : start + page_size]
    return FindingsPageResponse(findings=page_items, page=page, page_size=page_size, total=total)


@router.get("/{token}/report.pdf")
async def get_scan_report_pdf(
    token: str, storage: ObjectStorage = Depends(get_object_storage)
) -> Response:
    """Section 13/15: `GET /api/scans/{token}/report.pdf`.

    Normally just a storage read — the PDF was rendered once and persisted
    at submission time (see the module docstring's M5 decision note). The
    on-the-fly regeneration branch below is a defensive fallback only, for
    a scan record persisted before this implementation existed.
    """
    record = load_scan_record(storage, token)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")

    pdf_bytes = storage.get(report_storage_key(token))
    if pdf_bytes is None:
        certificates = group_into_certificates(record)
        apply_risk_engine(certificates)
        pdf_bytes = build_pdf_report(record, certificates)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="certwatch-report.pdf"'},
    )


@router.get("/{token}/report.csv")
async def get_scan_report_csv(
    token: str, storage: ObjectStorage = Depends(get_object_storage)
) -> Response:
    """Section 13/15: `GET /api/scans/{token}/report.csv`.

    Always regenerated fresh from the persisted `ScanRecord` — Section 11's
    storage layout lists no CSV key (see the module docstring's M5 decision
    note), so there is nothing to read back here.
    """
    record = load_scan_record(storage, token)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")

    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    csv_bytes = build_csv_report(record, certificates)

    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="certwatch-report.csv"'},
    )


@router.post("/{token}/ask", response_model=AskResponse)
def ask_certwatch(token: str, request: AskRequest) -> AskResponse:
    """Owned by M7 (AI analyst layer). Subject to Section 18 rate limits when wired."""
    raise _not_implemented("M7")


@router.patch("/{token}/ai-preference", response_model=AiPreferenceResponse)
def set_ai_preference(token: str, request: AiPreferenceRequest) -> AiPreferenceResponse:
    """Owned by M6 (UI toggle) + M7 (enforcement)."""
    raise _not_implemented("M6/M7")
