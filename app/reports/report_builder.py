"""Report assembly — Section 15, owned by M5.

Renders the three-section report exactly as Section 15 specifies it:
"Section 1 — Certificates requiring attention" (sorted by severity then
days-to-expiry; only certificates whose risk_severity isn't "ok"),
"Section 2 — Full inventory" (every certificate discovered, including
OK-status ones), and "Section 3 — Methodology/scope footer" (what was
scanned, the scan timestamp, a point-in-time disclaimer, and the OCSP/CRL
revocation-checking limitation — Section 8's known limitation, restated
here per that section's own instruction).

Report generation never blocks on an LLM call (Section 15/19) — everything
here is deterministic, built purely from `app.risk`'s already-computed
`Certificate` objects. Section 1's per-certificate "one-line explanation
with citation, if AI is enabled" is simply absent in this implementation
(there is no AI layer yet — M7) rather than an empty placeholder; M7 adds
it later "where available" per Section 15's own wording, without this
module needing to change.

Signature note (M5 implementation decision, recorded in the Decision Log):
the M0 stub declared `build_pdf_report(certificates: list[Certificate])`
and `build_csv_report(certificates: list[Certificate])`. Both now also take
the owning `ScanRecord`, because Section 3's methodology footer needs
scan-level metadata (submitted_at, host_count) that a bare certificate list
can't supply — the stub's signature was a rough sketch, not a frozen
contract (the same latitude M3 used for `resolve_and_validate`).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from app.parsing.models import Certificate
from app.risk.risk_engine import evaluate_flags, severity_sort_key, summarize_risk_severity
from app.storage.scan_store import ScanRecord

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)


def _sorted_certificates(certificates: list[Certificate]) -> list[Certificate]:
    """Section 1/2's sort: worst severity first, then soonest-expiring first."""
    return sorted(
        certificates,
        key=lambda c: (
            severity_sort_key(c.risk_severity or "ok"),
            c.days_to_expiry if c.days_to_expiry is not None else 0,
        ),
    )


def render_report_html(scan_record: ScanRecord, certificates: list[Certificate]) -> str:
    """Build the report's HTML — the single source both `build_pdf_report`
    and (indirectly, via the same `certificates` input) `build_csv_report`
    render from, so the two exports can never disagree with each other or
    with `GET /api/scans/{token}/findings`."""
    ordered = _sorted_certificates(certificates)
    attention_certificates = [c for c in ordered if (c.risk_severity or "ok") != "ok"]
    template = _env.get_template("report.html")
    return template.render(
        scan=scan_record,
        summary_counts=summarize_risk_severity(scan_record),
        attention_certificates=attention_certificates,
        all_certificates=ordered,
    )


def build_pdf_report(scan_record: ScanRecord, certificates: list[Certificate]) -> bytes:
    """Section 15/11: the rendered PDF, stored at `scans/{token}/report.pdf`."""
    html = render_report_html(scan_record, certificates)
    pdf_bytes: bytes = HTML(string=html).write_pdf()
    return pdf_bytes


_CSV_COLUMNS = (
    "certificate_id",
    "subject_cn",
    "san_list",
    "issuer",
    "not_after",
    "days_to_expiry",
    "risk_severity",
    "chain_category",
    "endpoints",
    "flags",
)


def build_csv_report(scan_record: ScanRecord, certificates: list[Certificate]) -> bytes:
    """Section 15: the CSV export — one row per certificate (Section 2's
    "every certificate discovered, including OK-status ones"), in the same
    worst-first order as the PDF's Section 1/2 tables.

    Not persisted to object storage (Section 11's storage layout lists only
    `scans/{token}/report.pdf` alongside `result.json` — no CSV key), so
    this is generated fresh on every request from the standard library's
    `csv` module — no pandas dependency needed for something this simple
    (Section 15 names "standard library/pandas" as either being acceptable).
    """
    ordered = _sorted_certificates(certificates)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_CSV_COLUMNS)
    for c in ordered:
        writer.writerow(
            [
                c.fingerprint_sha256,
                c.subject_cn,
                "; ".join(c.san_list),
                c.issuer,
                c.not_after.isoformat(),
                c.days_to_expiry,
                c.risk_severity or "ok",
                c.chain_category.value if c.chain_category else "",
                "; ".join(f"{e.host}:{e.port}" for e in c.endpoints),
                "; ".join(evaluate_flags(c, certificates)),
            ]
        )
    return buffer.getvalue().encode("utf-8")
