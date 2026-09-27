"""Scan API routes — full Section 13 route table.

`submit_scan`, `get_scan_status` (M3), `get_scan_findings` (M4),
`get_scan_report_pdf`/`get_scan_report_csv` (M5), `set_ai_preference` (M6,
the toggle control itself), `ask_certwatch` (M7, the AI analyst layer),
and `delete_scan` (M8) are all implemented, and rate limiting (Section 18)
now applies across the table.

Rate-limiting note (M8 implementation decision, recorded in the Decision
Log): the two per-IP, per-hour limits Section 18 states exact numbers for
(`submit_scan`: 5/hour; `ask_certwatch`: 60/hour) are enforced with
`slowapi`, as fixed limit strings (`_SUBMIT_RATE_LIMIT`,
`_ASK_IP_RATE_LIMIT`) matching those numbers — slowapi's decorators are
applied at module-import time, before any per-request `Settings` exists,
so they cannot consult a `Depends`-resolved or test-overridden `Settings`
instance the way every other value in this module does; changing the
enforced number requires a code change to these constants, not just an
env var (the `SUBMIT_RATE_LIMIT_PER_IP_PER_HOUR`/
`ASK_RATE_LIMIT_PER_IP_PER_HOUR` config fields remain declared for
Section 24 parity/documentation, but are not consulted at enforcement
time). Section 18's "/ask: 20/scan" is a lifetime cap on one scan, not a
sliding time window, so it cannot be a slowapi limit at all — it is a
persisted `ScanRecord.ask_count` counter (`app.storage.scan_store.
increment_ask_count`), checked and incremented inside
`answer_scan_question` itself, and *does* fully respect the
`Settings`-injected `ask_rate_limit_per_scan` value like everything else.
The remaining `/api/scans/{token}/*` routes (status, findings, the two
report exports, ai-preference) carry no exact number in Section 18, so a
generous, documented `_TOKEN_ROUTE_LIMIT` ("30/minute") is applied to all
of them — defense-in-depth against token brute-forcing per Section 21's
"Rate-limited access" control, not a number the spec states explicitly.

AI-analyst note (M7 implementation decision, recorded in the Decision
Log): `ask_certwatch`'s body is factored into a plain `answer_scan_question`
function, mirroring `execute_scan`'s M6 pattern — `app.web.routes`'s Ask
box calls this same function directly, so the JSON API and the web UI can
never answer a question differently. `answer_scan_question` 404s on an
unknown token, then delegates all AI-disabled enforcement, provider
selection, and grounding/fallback logic to `app.ai.analyst.answer_question`
— this route module has no AI logic of its own. `build_llm_provider`
returns `None` when no `LLM_API_KEY` is configured (a plain-message
fallback, not an error) — this is expected in this sandboxed dev
environment and in the user's own local setup until they supply a key.

Scan-execution note (M6 implementation decision, recorded in the Decision
Log): `submit_scan`'s body (validate, scan, persist, render+persist the
PDF) is factored out into `execute_scan`, a plain function with no
FastAPI-specific dependencies of its own. `app.web.routes`'s host-list
upload form calls the exact same function, so the JSON API and the
server-rendered UI can never scan or persist a submission differently —
`app.web` imports this module directly rather than re-implementing or
HTTP-calling its own API.

AI-preference note (M6 implementation decision, recorded in the Decision
Log): `set_ai_preference` now actually persists `scan.ai_enabled` via
`app.storage.scan_store.update_ai_preference` — this is the UI *toggle
control* Section 25/M6 names. It does not enforce the flag anywhere
(there is no LLM call anywhere yet to gate on it); that enforcement is
explicitly M7's job, once an AI layer exists to enforce it on.

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

Deletion-endpoint note (M8 implementation decision, recorded in the
Decision Log): Section 13's own route table has no deletion row, but
Section 21's security-requirements table independently states "Deletion
endpoint removing the object-storage blob on request" as its own BUILD
NOW item — `DELETE /api/scans/{token}` is this milestone's addition to
Section 13, not a pre-existing spec route. It is JSON-API only; Section
14's UI spec lists no delete affordance, so no web-UI button is added.

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
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.ai.analyst import answer_question
from app.ai.llm_client import AnthropicProvider, LLMProvider
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
    AskLimitExceededError,
    ScanRecord,
    delete_scan,
    generate_scan_token,
    host_outcome_to_record,
    increment_ask_count,
    load_scan_record,
    report_storage_key,
    save_scan_record,
    update_ai_preference,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

_DEFAULT_SCAN_PORT = 443

# Section 18's two exact per-IP-hourly numbers (see the module docstring's
# rate-limiting note for why these are fixed strings, not read from
# `Settings`). `limiter` is a MODULE-LEVEL singleton — this module is
# imported once per process, so its in-memory rate-limit storage is shared
# and accumulates across every test in a single pytest run (Starlette's
# `TestClient` uses one consistent fake IP for all requests). Test
# isolation is achieved by calling `limiter.reset()` in the `client`
# fixtures (`tests/conftest.py`, and the local fixtures in
# `tests/unit/test_routes_scans.py`/`test_web_routes.py`) before each
# test, not by any per-`create_app()`-call isolation — there is none.
limiter = Limiter(key_func=get_remote_address)
_SUBMIT_RATE_LIMIT = "5/hour"
_ASK_IP_RATE_LIMIT = "60/hour"
_TOKEN_ROUTE_LIMIT = "30/minute"


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


async def execute_scan(
    payload: ScanSubmitRequest,
    settings: Settings,
    storage: ObjectStorage,
    source_ip: str | None,
) -> ScanRecord:
    """The actual submit-a-scan work, independent of any web framework:
    validate, scan, persist, render+persist the PDF (M5). Both `submit_scan`
    (JSON API) and `app.web.routes`'s host-list upload form (M6) call this
    directly, so the two front ends can never scan or persist a submission
    differently (Decision Log).

    Host count is capped at `settings.max_hosts_per_scan` (Section 19/24);
    over the cap is a 422 (`HTTPException`), not a silently-truncated scan.
    Runs the scan synchronously against `app.scanning.scan_hosts` (M2) —
    Section 2's own architecture table places "Background jobs" as "None
    customer-facing" at v0, so there is no job queue to hand this off to;
    Section 19's own worst-case estimate (250 hosts, ~85 seconds) is sized
    for exactly this.
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
        source_ip=source_ip,
        ai_enabled=settings.ai_enabled_by_default,
        host_results=[host_outcome_to_record(outcome) for outcome in outcomes],
    )
    save_scan_record(storage, record)

    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    storage.put(report_storage_key(token), build_pdf_report(record, certificates))

    return record


@router.post("", response_model=ScanSubmitResponse, status_code=201)
@limiter.limit(_SUBMIT_RATE_LIMIT)
async def submit_scan(
    payload: ScanSubmitRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    storage: ObjectStorage = Depends(get_object_storage),
) -> ScanSubmitResponse:
    """Section 13: `POST /api/scans`. See `execute_scan` for the actual work."""
    record = await execute_scan(
        payload, settings, storage, request.client.host if request.client else None
    )
    report_url = str(request.url_for("get_scan_report_pdf", token=record.token))
    return ScanSubmitResponse(token=record.token, status=record.status, report_url=report_url)


@router.get("/{token}", response_model=ScanStatusResponse)
@limiter.limit(_TOKEN_ROUTE_LIMIT)
async def get_scan_status(
    request: Request, token: str, storage: ObjectStorage = Depends(get_object_storage)
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
@limiter.limit(_TOKEN_ROUTE_LIMIT)
async def get_scan_findings(
    request: Request,
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
@limiter.limit(_TOKEN_ROUTE_LIMIT)
async def get_scan_report_pdf(
    request: Request, token: str, storage: ObjectStorage = Depends(get_object_storage)
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
@limiter.limit(_TOKEN_ROUTE_LIMIT)
async def get_scan_report_csv(
    request: Request, token: str, storage: ObjectStorage = Depends(get_object_storage)
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


def build_llm_provider(settings: Settings) -> LLMProvider | None:
    """The one place an `LLMProvider` is constructed (Section 17's provider
    abstraction) — returns `None` when no `LLM_API_KEY` is configured, which
    `app.ai.analyst.answer_question` treats as "use the fallback message",
    not as an error. Swapping providers touches only this function."""
    if not settings.llm_api_key:
        return None
    return AnthropicProvider(api_key=settings.llm_api_key, model=settings.llm_model)


def answer_scan_question(
    token: str, question: str, storage: ObjectStorage, settings: Settings
) -> AskResponse:
    """The actual ask-a-question work, independent of any web framework —
    mirrors `execute_scan`'s (M6) pattern. `POST /api/scans/{token}/ask`
    (JSON API) and `app.web.routes`'s Ask box (M7) both call this directly,
    so the two front ends can never answer a question differently
    (Decision Log).

    Section 18's lifetime "/ask: 20/scan" cap is enforced here, via
    `increment_ask_count`, before any AI logic runs — every accepted call
    counts against it, even one that ends up answering with the plain
    fallback message, since the cap protects the endpoint itself from
    volume (Decision Log). The per-IP-hourly "/ask: 60/hour" number is a
    separate concern, enforced by `slowapi` at the route level (both the
    JSON route and the web UI's own `/scans/{token}/ask` route), not here.

    AI-disabled enforcement, provider selection, and the grounding/fallback
    behavior all live in `app.ai.analyst.answer_question` — this function's
    only other job is to load the scan, 404 on an unknown token, and
    translate the result into `AskResponse`.
    """
    try:
        record = increment_ask_count(storage, token, settings.ask_rate_limit_per_scan)
    except AskLimitExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")

    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    provider = build_llm_provider(settings)
    answer_text, citations = answer_question(record, certificates, question, provider)
    return AskResponse(answer=answer_text, citations=citations)


@router.post("/{token}/ask", response_model=AskResponse)
@limiter.limit(_ASK_IP_RATE_LIMIT)
def ask_certwatch(
    request: Request,
    token: str,
    payload: AskRequest,
    storage: ObjectStorage = Depends(get_object_storage),
    settings: Settings = Depends(get_settings),
) -> AskResponse:
    """Section 13/16: `POST /api/scans/{token}/ask`. See
    `answer_scan_question` for the actual work — including Section 18's
    per-scan cap. The per-IP-hourly cap is this decorator."""
    return answer_scan_question(token, payload.question, storage, settings)


@router.patch("/{token}/ai-preference", response_model=AiPreferenceResponse)
@limiter.limit(_TOKEN_ROUTE_LIMIT)
def set_ai_preference(
    request: Request,
    token: str,
    payload: AiPreferenceRequest,
    storage: ObjectStorage = Depends(get_object_storage),
) -> AiPreferenceResponse:
    """Section 13/16: `PATCH /api/scans/{token}/ai-preference` — the toggle
    *control* itself, owned by M6. Persists `scan.ai_enabled`
    (`app.storage.scan_store.update_ai_preference`); enforcement of the
    flag lives in `app.ai.analyst.answer_question` (M7).
    """
    record = update_ai_preference(storage, token, payload.ai_enabled)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown scan token.")
    return AiPreferenceResponse(ai_enabled=record.ai_enabled)


@router.delete("/{token}", status_code=204)
@limiter.limit(_TOKEN_ROUTE_LIMIT)
def delete_scan_endpoint(
    request: Request, token: str, storage: ObjectStorage = Depends(get_object_storage)
) -> Response:
    """M8 addition to Section 13 (Section 21: "Deletion endpoint removing
    the object-storage blob on request"). Removes the persisted
    `result.json` and `report.pdf` for `token`; the CSV export is never
    persisted, so there is nothing to remove there (see
    `app.storage.scan_store.delete_scan`'s docstring). 404s on a token
    that was never a real scan, exactly like every other
    `/api/scans/{token}/*` route, so this can't be used to distinguish
    "never existed" from "already deleted" — both read the same to a
    caller, which is the correct behavior for a token-as-sole-identifier
    design (Section 12)."""
    existed = delete_scan(storage, token)
    if not existed:
        raise HTTPException(status_code=404, detail="Unknown scan token.")
    return Response(status_code=204)
