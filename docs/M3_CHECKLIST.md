# M3 completion checklist

Mapped directly to Section 10 (data model), Section 11 (object-storage
design), Section 12 (token/access-control model), and the relevant rows
of Section 13 (API specification) in the CertWatch MVP Technical
Specification v1.

| Requirement | Status | Evidence |
| --- | --- | --- |
| One JSON document per scan, not relational tables | Done | `ScanRecord` (Pydantic) in `app/storage/scan_store.py`; `save_scan_record`/`load_scan_record` |
| Object-storage layout `scans/{token}/result.json` | Done | `scan_storage_key`; `test_scan_storage_key_is_token_scoped` |
| Storage interface abstraction (swap-in-able backend) | Done (M0, reused) | `ObjectStorage` interface unchanged; `get_object_storage()` factory added in `app/storage/__init__.py` |
| CSPRNG token generation, ≥122 bits entropy, token IS the storage key | Done | `generate_scan_token()` uses `secrets.token_urlsafe(32)` (~256 bits); `test_generate_scan_token_is_high_entropy_and_urlsafe`, `test_generate_scan_token_is_unique_across_many_calls` |
| No sequential/guessable scan identifier anywhere | Done | Only `generate_scan_token()` produces identifiers; no counter or DB auto-increment exists |
| Isolation: one scan's token cannot reach another scan's data | Done | `test_one_scans_token_cannot_reach_another_scans_data` (distinct tokens; a mutated token 404s, never hits another scan) |
| Unknown token → 404, not a different-shaped response | Done | `test_unknown_token_returns_404`, `test_load_scan_record_missing_token_returns_none` |
| `source_ip` persisted for abuse investigation only, never returned | Done | `ScanRecord.source_ip` has no path into any response model; `test_source_ip_never_returned_in_status_response` |
| `POST /api/scans`: host-count cap enforced before any scan | Done | `settings.max_hosts_per_scan` check raises 422 before `scan_hosts` is ever called; `test_submit_scan_host_count_exceeds_cap_is_422_before_any_scan` |
| `POST /api/scans` → `{token, status, report_url}` | Done | `ScanSubmitResponse`; `test_submit_scan_returns_token_and_report_url` |
| `GET /api/scans/{token}` → `{status, summary_counts}`, token is the sole access control | Done | `get_scan_status`; no other authorization check exists |
| Never stored: private keys, CA private keys, passwords, credentials | Done (inherited from M1) | `Certificate.pem` is the public certificate only; nothing else persisted carries secret material |

## Section 13 API-specification coverage (this milestone's two routes)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/scans` | POST | Implemented — `submit_scan` |
| `/api/scans/{token}` | GET | Implemented — `get_scan_status` |
| `/api/scans/{token}/findings` | GET | Stub (501) — M4 |
| `/api/scans/{token}/report.pdf` \| `.csv` | GET | Stub (501) — M5 |
| `/api/scans/{token}/ask` | POST | Stub (501) — M7 |
| `/api/scans/{token}/ai-preference` | PATCH | Stub (501) — M6/M7 |

Rate limiting on all of the above (Section 13's "5 submissions/hour/IP",
"20 questions/scan; 60/hour/IP") is explicitly M8's job (Section 18) and
is **not** implemented in M3 — `submit_scan` has no request-rate limit of
its own yet.

100/100 tests pass (27 new M3 tests: 12 in `test_scan_store.py` + 11 in
`test_routes_scans.py` + 4 in `test_get_object_storage.py`; plus 1 M0
smoke test rewritten to match a real 501 route instead of the now-
implemented `POST /api/scans`). `ruff check`, `ruff format --check`, and
`mypy app` all pass cleanly against the full M0–M3 codebase. Coverage:
`scan_store.py` 100%, `app/storage/__init__.py` 100%, `routes_scans.py`
94% (remaining lines are the still-stubbed 501 handlers for later
milestones).

## M3 implementation decisions (recorded in the Decision Log)

1. **M3 persists raw per-host scan outcomes**, not Section 10's endpoint-
   grouped-by-certificate shape (`Certificate.endpoints`, `duplicate_of`).
   Certificate deduplication across hosts and `risk_severity` computation
   are M4's job once the risk engine exists to do that grouping/scoring.
2. **A real S3-compatible cloud backend is deliberately not added yet.**
   `get_object_storage()`'s factory only implements `"local"`
   (`LocalFilesystemStorage`) and raises `UnsupportedStorageBackendError`
   for anything else — local Windows dev is still the current active
   deployment target (M2 gate) and there are no cloud credentials to test
   a real backend against. The `ObjectStorage` interface makes this a
   drop-in addition later.
3. **`ports` in `POST /api/scans` is index-aligned with `hosts`**
   (`ports[i]` applies to `hosts[i]`) — the spec describes it only as
   "optional per-host port override" without stating its shape. A length
   mismatch is a 422. Omitted `ports` defaults every host to 443.
4. **Scans run synchronously inside the `POST /api/scans` request** — no
   background job queue exists at v0 (Section 2's own architecture table:
   "Background jobs: None customer-facing"), and Section 19's worst-case
   estimate (250 hosts, ~85 seconds) is sized for exactly this design.
5. **`get_object_storage()` takes no parameters**, unlike token/settings-
   parameterized factories elsewhere — a FastAPI dependency callable with
   a `Settings`-typed parameter is itself treated by FastAPI as a nested
   dependency needing a `Settings` object from the request body, which
   silently broke `POST /api/scans`'s own body parsing (discovered while
   testing, not assumed). Fixed by making the factory parameterless (like
   `get_settings`) and using `app.dependency_overrides` in tests instead.

## Open items before M4

- M4 owns the deterministic risk engine (Section 9): `risk_severity`,
  `duplicate_of`/certificate grouping into `endpoints[]`, and the
  eight-rule severity table. `summary_counts` in `GET /api/scans/{token}`
  will need to be re-derived from that engine's output instead of raw
  `HostScanStatus` counts — the response *shape* doesn't change, only what
  populates it.
- `GET /api/scans/{token}/findings` (paginated, filterable findings) stays
  a stub until M4 has real findings to paginate.
- Rate limiting (Section 18) on `POST /api/scans` and all `{token}`
  sub-routes remains M8's explicit scope — not a blocker for M4.
