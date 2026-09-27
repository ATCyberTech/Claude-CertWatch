# M6 completion checklist

Mapped directly to Section 14 (UI specification) of the CertWatch MVP
Technical Specification v1, plus the `ai-preference` row of Section 13
and the AI-toggle bullet of Section 16.

| Section 14 element | Status | Evidence |
| --- | --- | --- |
| 1. Upload/scan (paste or upload; visible scope note) | Done | `index`, `submit_scan_via_web`; `test_index_shows_scope_note`, `test_submit_via_pasted_textarea_redirects_to_scan_page`, `test_submit_via_uploaded_file`, `test_submit_combines_and_dedupes_textarea_and_file` |
| 2. Scanning/progress (simple status view) | Done (trivially, by construction) | Scans are synchronous (M3); `scan_status_page` always shows a completed scan — no polling needed |
| 3. Risk summary (severity counts + top findings) | Done | `scan_status_page`; `test_scan_page_shows_risk_summary_and_inventory` |
| 4. Certificate inventory (sortable, filterable) | Done | `_sort_certificates`, `?sort=`/`?severity=` query params; `test_scan_page_severity_filter_narrows_inventory` |
| 5. Certificate detail (chain category, SAN list, endpoints) | Done | `certificate_detail_page`; `test_certificate_detail_page` |
| 6. Finding explanation (AI narration) | Absent, not stubbed | No AI layer exists yet (M7); Section 14 itself says this is "absent entirely when AI is off" |
| 7. Ask CertWatch + visible AI on/off control | Done | `toggle_ai_preference_web` (real persistence), `ask_certwatch_web` (plain "not available yet" notice on the M7 stub's 501); `test_ai_preference_toggle_persists_and_redirects`, `test_ask_shows_not_available_notice` |
| 8. Report/export (PDF and CSV download buttons) | Done | Plain links to the M5 `/api/scans/{token}/report.pdf`/`.csv` routes |

## Section 13 coverage (this milestone's route)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/scans/{token}/ai-preference` | PATCH | Implemented — persists `scan.ai_enabled` via `app.storage.scan_store.update_ai_preference`; no enforcement (M7) |

Rate limiting (Section 18) remains M8's explicit scope — not implemented
on any web or API route here.

185 tests pass (18 net-new in `tests/unit/test_web_routes.py`, covering
the upload form, host-list parsing/dedup, the results page, sorting/
filtering, certificate detail, the AI toggle — both the web form and the
JSON `PATCH` route — and the Ask box's fallback notice; plus
`tests/unit/test_smoke.py::test_index_page_renders` updated for the real
upload page replacing the M0 placeholder). `ruff check`, `ruff format
--check`, and `mypy app` all pass cleanly against the full M0–M6
codebase. Coverage: `app/web/routes.py` 100%, `app/api/routes_scans.py`
100%.

## M6 implementation decisions (recorded in the Decision Log)

1. **`submit_scan`'s body is factored into a plain `execute_scan`
   function**, shared by the JSON API and the web UI's upload form — so
   the two front ends can never scan or persist a submission
   differently.
2. **The web UI's pasted-textarea and uploaded-file host lists are
   combined and deduplicated (order-preserving), split on newlines and
   commas** — Section 14 doesn't specify a syntax or whether both inputs
   can be used together; this lets someone use either or both without
   double-scanning a host.
3. **The certificate inventory's sort/filter state lives entirely in
   query parameters** (`?sort=`, `?severity=`) — no client-side JS,
   consistent with Section 2's "no React/SPA," and the page is
   bookmarkable/shareable in a given sort/filter state.
4. **`PATCH /api/scans/{token}/ai-preference` persists the flag but
   enforces nothing** — this milestone builds the toggle *control*
   Section 25's M6 row names; there is no LLM call anywhere yet to gate
   on it. Enforcement is explicitly M7's job.
5. **The Ask CertWatch box calls the real (still-M7-stubbed)
   `ask_certwatch` function and catches its 501**, rather than being
   wired to nothing — so the moment M7 implements it for real, the web
   UI needs no changes to start working.
6. **`ruff`'s `extend-immutable-calls` now also lists `fastapi.File` and
   `fastapi.Form`** — the same framework-idiom exception already made for
   `Depends`/`Query`/`Path`.

## Open items before M7

- M7 owns the actual AI analyst layer (Sections 16/17): `ask_certwatch`
  needs a real LLM tool-calling loop, grounding/citation checks, and
  enforcement of `scan.ai_enabled` (skip the LLM call entirely when
  `False`) — none of that exists yet; M6 only built the toggle and the
  UI's graceful fallback around the still-missing implementation.
- Once M7 lands, `app/web/routes.py`'s Ask box and the (currently
  absent) finding-explanation element should start working with no
  further web-layer changes, since both already call the real API
  functions and just need those functions to stop raising 501.
- Rate limiting (Section 18, M8) applies to `/ask` and submission but is
  not implemented on the web routes either.
