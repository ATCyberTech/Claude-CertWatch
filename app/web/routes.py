"""Web UI routes — Section 14, owned by M6.

Server-rendered only (Jinja2, no React/SPA — Section 2). Every page here
reads the same persisted `ScanRecord` and calls the same
`app.risk`/`app.reports` building blocks the JSON API uses; the host-list
upload form calls `app.api.routes_scans.execute_scan` directly (the exact
function `POST /api/scans` itself calls), so the web UI and the JSON API
can never scan or persist a submission differently (Decision Log).

Section 14's eight UI elements, and where each lives:
  1. Upload/scan               -> `index` (GET /) + `submit_scan_via_web` (POST /scan)
  2. Scanning/progress          -> trivial: scans run synchronously (M3), so by
                                    the time the redirect lands on `scan_status_page`
                                    the scan is already `complete`; no polling needed.
  3. Risk summary                -> `scan_status_page` (severity counts + top findings)
  4. Certificate inventory        -> `scan_status_page` (sortable/filterable via
                                    `?sort=` / `?severity=` query params — plain links,
                                    no JS, consistent with "no React/SPA")
  5. Certificate detail            -> `certificate_detail_page`
  6. Finding explanation (AI)       -> absent entirely — Section 14 itself says this
                                    element is "absent entirely when AI is off," and
                                    it is not a distinct control from the Ask box at
                                    v0 (recorded as an M7 decision); a per-finding
                                    "explain this" affordance is left for a later
                                    milestone to add if wanted.
  7. Ask CertWatch + AI toggle       -> `scan_status_page` renders both; the toggle
                                    posts to `toggle_ai_preference_web`. The question
                                    box posts to `ask_certwatch_web` (M7), which calls
                                    the real `app.api.routes_scans.answer_scan_question`
                                    and re-renders this same page with the answer (or
                                    the fallback message) inline — no redirect, since
                                    the answer varies per question and can't be
                                    round-tripped through a query-string flag the way
                                    M6's placeholder notice was.
  8. Report/export                  -> plain links to the M5 `.../report.pdf`/`.csv` routes.

M8 note (recorded in the Decision Log): `submit_scan_via_web` (`POST
/scan`) and `ask_certwatch_web` (`POST /scans/{token}/ask`) now carry the
identical `@limiter.limit(...)` decorators as their JSON-API counterparts
(`app.api.routes_scans.submit_scan`/`ask_certwatch`), reusing the same
`limiter` instance and the same fixed Section 18 limit strings, so the two
front ends enforce identically and can never disagree about how many
submissions or questions an IP gets. The per-scan lifetime `/ask` cap
(enforced inside `answer_scan_question` itself) is caught here and
rendered inline on the results page rather than propagating as a raw 429
— see `ask_certwatch_web`'s own docstring.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.responses import Response

from app.api.routes_scans import (
    _ASK_IP_RATE_LIMIT,
    _SUBMIT_RATE_LIMIT,
    ScanSubmitRequest,
    answer_scan_question,
    execute_scan,
    limiter,
)
from app.core.config import Settings, get_settings
from app.parsing.models import Certificate
from app.risk.risk_engine import (
    apply_risk_engine,
    evaluate_flags,
    group_into_certificates,
    severity_sort_key,
    summarize_risk_severity,
)
from app.storage import get_object_storage
from app.storage.interface import ObjectStorage
from app.storage.scan_store import ScanRecord, load_scan_record, update_ai_preference

router = APIRouter(tags=["web"])
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _parse_host_list(*sources: str) -> list[str]:
    """Split one or more freeform blocks of pasted/uploaded text into a
    deduplicated (order-preserving) host list — one host per line, or
    comma-separated within a line, matching how someone would naturally
    paste a list of hosts (M6 implementation clarification: Section 14
    just says "paste or upload a host list" without specifying a syntax).
    """
    seen: dict[str, None] = {}
    for source in sources:
        for line in source.splitlines():
            for piece in line.split(","):
                host = piece.strip()
                if host:
                    seen[host] = None
    return list(seen.keys())


@router.get("/")
def index(request: Request, error: str | None = None, hosts_text: str = "") -> Response:
    """Section 14 element 1 (upload/scan): paste-or-upload a host list, with
    the spec's own visible scope note."""
    return _templates.TemplateResponse(
        request, "index.html", {"error": error, "hosts_text": hosts_text}
    )


@router.post("/scan")
@limiter.limit(_SUBMIT_RATE_LIMIT)
async def submit_scan_via_web(
    request: Request,
    hosts_text: str = Form(""),
    hosts_file: UploadFile | None = File(None),
    settings: Settings = Depends(get_settings),
    storage: ObjectStorage = Depends(get_object_storage),
) -> Response:
    """Parses the pasted/uploaded host list and hands it straight to
    `app.api.routes_scans.execute_scan` — the same function `POST
    /api/scans` calls — then redirects to the results page (Section 14
    element 2: by the time this redirect lands, the synchronous scan
    (M3) has already finished, so there is no separate progress poll)."""
    file_text = ""
    if hosts_file is not None and hosts_file.filename:
        file_text = (await hosts_file.read()).decode("utf-8", errors="ignore")

    hosts = _parse_host_list(hosts_text, file_text)

    try:
        payload = ScanSubmitRequest(hosts=hosts)
        record = await execute_scan(
            payload, settings, storage, request.client.host if request.client else None
        )
    except ValidationError:
        return _templates.TemplateResponse(
            request,
            "index.html",
            {"error": "Enter at least one host to scan.", "hosts_text": hosts_text},
            status_code=422,
        )
    except HTTPException as exc:
        return _templates.TemplateResponse(
            request,
            "index.html",
            {"error": exc.detail, "hosts_text": hosts_text},
            status_code=exc.status_code,
        )

    return RedirectResponse(url=f"/scans/{record.token}", status_code=303)


_SORT_KEYS = {
    "severity": lambda c: severity_sort_key(c.risk_severity or "ok"),
    "expiry": lambda c: c.days_to_expiry if c.days_to_expiry is not None else 0,
    "subject_cn": lambda c: c.subject_cn,
}
_DEFAULT_SORT = "severity"


def _sort_certificates(certificates: list[Certificate], sort: str) -> list[Certificate]:
    reverse = sort.startswith("-")
    field = sort[1:] if reverse else sort
    key_fn = _SORT_KEYS.get(field, _SORT_KEYS[_DEFAULT_SORT])
    return sorted(certificates, key=key_fn, reverse=reverse)


def _load_certificates(
    storage: ObjectStorage, token: str
) -> tuple[ScanRecord, list[Certificate]] | None:
    record = load_scan_record(storage, token)
    if record is None:
        return None
    certificates = group_into_certificates(record)
    apply_risk_engine(certificates)
    return record, certificates


def _build_scan_page_context(
    record: ScanRecord,
    certificates: list[Certificate],
    sort: str,
    severity: str | None,
    ask_question: str | None = None,
    ask_answer: str | None = None,
    ask_citations: list[str] | None = None,
) -> dict[str, object]:
    """Shared template context for `scan_status.html` — built once here so
    both `scan_status_page` (GET, no question yet) and `ask_certwatch_web`
    (POST, rendering the page with a real answer inline — M7) stay in sync
    on the risk summary / inventory / sort / filter fields (Decision Log)."""
    all_severities = sorted({c.risk_severity or "ok" for c in certificates})
    inventory = [
        c for c in certificates if severity is None or (c.risk_severity or "ok") == severity
    ]
    inventory = _sort_certificates(inventory, sort)

    top_findings = sorted(
        (c for c in certificates if (c.risk_severity or "ok") != "ok"),
        key=lambda c: (
            severity_sort_key(c.risk_severity or "ok"),
            c.days_to_expiry if c.days_to_expiry is not None else 0,
        ),
    )[:5]

    return {
        "record": record,
        "summary_counts": summarize_risk_severity(record),
        "top_findings": top_findings,
        "certificates": inventory,
        "all_severities": all_severities,
        "current_sort": sort,
        "current_severity": severity or "",
        "ask_question": ask_question,
        "ask_answer": ask_answer,
        "ask_citations": ask_citations or [],
    }


@router.get("/scans/{token}")
async def scan_status_page(
    request: Request,
    token: str,
    sort: str = _DEFAULT_SORT,
    severity: str | None = None,
    storage: ObjectStorage = Depends(get_object_storage),
) -> Response:
    """Section 14 elements 2, 3, 4, 7, 8: status, risk summary, the
    sortable/filterable certificate inventory, the Ask box + AI toggle, and
    the report download links, all on one page."""
    loaded = _load_certificates(storage, token)
    if loaded is None:
        return _templates.TemplateResponse(
            request, "not_found.html", {"token": token}, status_code=404
        )
    record, certificates = loaded
    return _templates.TemplateResponse(
        request,
        "scan_status.html",
        _build_scan_page_context(record, certificates, sort, severity),
    )


@router.get("/scans/{token}/certificates/{fingerprint}")
async def certificate_detail_page(
    request: Request,
    token: str,
    fingerprint: str,
    storage: ObjectStorage = Depends(get_object_storage),
) -> Response:
    """Section 14 element 5: chain category (visually distinct), SAN list,
    endpoints, for one certificate found in this scan."""
    loaded = _load_certificates(storage, token)
    if loaded is None:
        return _templates.TemplateResponse(
            request, "not_found.html", {"token": token}, status_code=404
        )
    record, certificates = loaded
    certificate = next((c for c in certificates if c.fingerprint_sha256 == fingerprint), None)
    if certificate is None:
        return _templates.TemplateResponse(
            request, "not_found.html", {"token": token}, status_code=404
        )

    return _templates.TemplateResponse(
        request,
        "certificate_detail.html",
        {
            "record": record,
            "certificate": certificate,
            "flags": evaluate_flags(certificate, certificates),
        },
    )


@router.post("/scans/{token}/ai-preference")
async def toggle_ai_preference_web(
    request: Request,
    token: str,
    ai_enabled: bool = Form(False),
    storage: ObjectStorage = Depends(get_object_storage),
) -> Response:
    """Section 14 element 7's visible AI on/off control (Section 16/17):
    posts straight to `app.storage.scan_store.update_ai_preference`, the
    same storage-mutation function the JSON `PATCH .../ai-preference`
    route uses."""
    record = update_ai_preference(storage, token, ai_enabled)
    if record is None:
        return _templates.TemplateResponse(
            request, "not_found.html", {"token": token}, status_code=404
        )
    return RedirectResponse(url=f"/scans/{token}", status_code=303)


@router.post("/scans/{token}/ask")
@limiter.limit(_ASK_IP_RATE_LIMIT)
async def ask_certwatch_web(
    request: Request,
    token: str,
    question: str = Form(...),
    storage: ObjectStorage = Depends(get_object_storage),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Section 14 element 7's question box (M7). Calls the same plain
    `answer_scan_question` function `POST /api/scans/{token}/ask` calls —
    so the web UI and the JSON API can never answer a question differently
    (Decision Log) — and re-renders the results page with the real answer
    (or `app.ai.analyst`'s fallback message, per Section 16's own
    "Fallback" bullet) inline, rather than redirecting: the answer varies
    per question, so it can't be round-tripped through a query-string flag
    the way M6's placeholder notice was.

    M8: `answer_scan_question` now raises `HTTPException(429)` once this
    scan's lifetime `/ask` cap (Section 18: 20/scan) is reached. A web-UI
    visitor gets that rendered back inline on this same page (the answer
    slot shows the cap message) rather than a raw JSON 429 — the one place
    this milestone's rate limiting gets a friendlier treatment than the
    JSON API, since this route is the one a human is actually looking at
    when it fires. The per-IP-hourly cap (the decorator above) is not
    caught here: an exceeded route-level limit raises `RateLimitExceeded`,
    handled globally by `app.main`'s registered handler, the same way it is
    for every other rate-limited route in this app (Decision Log)."""
    loaded = _load_certificates(storage, token)
    if loaded is None:
        return _templates.TemplateResponse(
            request, "not_found.html", {"token": token}, status_code=404
        )
    record, certificates = loaded
    try:
        response = answer_scan_question(token, question, storage, settings)
    except HTTPException as exc:
        return _templates.TemplateResponse(
            request,
            "scan_status.html",
            _build_scan_page_context(
                record,
                certificates,
                _DEFAULT_SORT,
                None,
                ask_question=question,
                ask_answer=str(exc.detail),
                ask_citations=[],
            ),
            status_code=exc.status_code,
        )
    return _templates.TemplateResponse(
        request,
        "scan_status.html",
        _build_scan_page_context(
            record,
            certificates,
            _DEFAULT_SORT,
            None,
            ask_question=question,
            ask_answer=response.answer,
            ask_citations=response.citations,
        ),
    )
