# M5 completion checklist

Mapped directly to Section 15 (report generation) of the CertWatch MVP
Technical Specification v1, plus the `report.pdf`/`report.csv` rows of
Section 13 and Section 11's storage-layout list.

| Requirement | Status | Evidence |
| --- | --- | --- |
| Section 1 — certificates requiring attention (worst severity first, "ok" excluded) | Done | `_sorted_certificates`, `render_report_html`; `test_render_report_html_excludes_ok_certificates_from_section_1`, `test_build_csv_report_sorts_worst_severity_first` |
| Section 2 — full inventory, every certificate including "ok" | Done | `render_report_html`, `build_csv_report`; `test_build_csv_report_has_one_row_per_certificate_including_ok` |
| Section 3 — methodology/scope footer (scan scope, point-in-time disclaimer, OCSP/CRL limitation) | Done | `report.html`'s footer block; `test_render_report_html_includes_methodology_footer` |
| PDF export | Done | `build_pdf_report` via WeasyPrint; `test_build_pdf_report_produces_valid_pdf_bytes`, `test_report_pdf_is_persisted_at_submission_and_downloadable` |
| CSV export | Done | `build_csv_report` via stdlib `csv`; `test_report_csv_downloadable_and_matches_findings` |
| PDF and CSV match the web report's findings (Section 22) | Done by construction | All three (`GET /findings`, `build_pdf_report`, `build_csv_report`) consume the same `group_into_certificates`/`apply_risk_engine` pipeline output |
| Report generation never blocks on an LLM call (Section 15/19) | Done | No AI layer exists yet (M7); `render_report_html` has no AI-narration code path at all, not a stub |

## Section 13 coverage (this milestone's routes)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/scans/{token}/report.pdf` | GET | Implemented — persisted at submission time, regenerated on the fly only as a defensive fallback |
| `/api/scans/{token}/report.csv` | GET | Implemented — always generated fresh per request |

Rate limiting (Section 18) remains M8's explicit scope — not implemented
on either route here.

167 tests pass (13 net-new: 7 in `tests/unit/test_report_builder.py` +
6 in `tests/unit/test_routes_scans.py` for `report.pdf`/`.csv`; plus 1
existing `tests/unit/test_smoke.py` test moved from the now-implemented
`/report.pdf` route to the still-stubbed `/ask` route, mirroring the same
move M4's checklist made from `/findings` to `/report.pdf`). `ruff check`,
`ruff format --check`, and `mypy app` all pass cleanly against the full
M0–M5 codebase. Coverage: `app/reports/report_builder.py` 100%,
`app/api/routes_scans.py` 99% (the remaining line is the still-stubbed
`ai-preference` 501 handler for M6/M7).

## M5 implementation decisions (recorded in the Decision Log)

1. **`build_pdf_report`/`build_csv_report` signatures extended beyond the
   M0 stub to also take the owning `ScanRecord`** — Section 3's
   methodology footer needs scan-level metadata (`submitted_at`,
   `host_count`) a bare certificate list can't supply. Same latitude M3
   used for `resolve_and_validate`'s signature change.
2. **PDF rendered once, synchronously, at the end of `submit_scan` and
   persisted to `scans/{token}/report.pdf`** — Section 11's storage
   layout explicitly lists that key alongside `result.json`.
3. **CSV is never persisted; always generated fresh per request** —
   Section 11 lists no CSV storage key.
4. **`GET /report.pdf` regenerates on the fly only as a defensive
   fallback**, for a scan record persisted before this implementation
   existed — a dev-only scenario, since there is no real production data
   yet.
5. **No pandas dependency added for CSV** — stdlib `csv` is simple enough
   for one row per certificate; Section 15 names "standard library/pandas"
   as either being acceptable.
6. **AI narration in Section 1 is simply absent, not stubbed** — there is
   no AI layer yet (M7); Section 15 itself describes it as added "where
   available" later, without this module needing to change.
7. **`mypy` overrides `weasyprint.*` with `ignore_missing_imports`** —
   `weasyprint` ships no type stubs or `py.typed` marker, same class of
   fix as the existing `asn1crypto.*` override.

## Open items before M6

- M6 owns the minimal UI, including the AI on/off toggle — it will need a
  way to link to `report.pdf`/`.csv` from a web page, but nothing in this
  module needs to change for that.
- Certificate `environment`/`owner` tagging (Section 10's `endpoints[]`
  optional fields) still stays unset in every report row — no UI to set
  them yet (M6+).
- Pre-M5 persisted scan records (from local testing before this milestone)
  have no stored PDF to read back — the defensive on-the-fly-regeneration
  fallback in `get_scan_report_pdf` covers this; not a concern in this
  dev-only environment with no real production data yet.
