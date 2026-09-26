# M4 completion checklist

Mapped directly to Section 9 (deterministic risk engine) of the CertWatch
MVP Technical Specification v1, plus the `/findings` row and the
`summary_counts` field of Section 13.

| Requirement | Status | Evidence |
| --- | --- | --- |
| Expiry status tiers: EXPIRED/CRITICAL/HIGH/MEDIUM/LOW/OK | Done | `expiry_tier`; `test_expiry_tier_boundaries` (all 12 boundary cases) |
| Chain outcome: one of the five categories, never collapsed | Done (M1, reused) | `Certificate.chain_category`; feeds `broken_chain`/`private_ca` flags unchanged |
| Weak or obsolete cryptography: RSA<2048, DSA (any size), ECDSA<P-256, sig MD5/SHA1 | Done | `is_weak_crypto`; `test_is_weak_crypto` (14 cases incl. boundaries) |
| Duplicate certificates / shared across endpoints (count(endpoints)>1) | Done | `_is_shared`, `group_into_certificates`; `test_group_into_certificates_merges_same_fingerprint_into_one_with_endpoints`, `test_shared_beats_private_ca` |
| Suspicious/unusual configuration: self-signed among CA-issued peers | Done | `_is_suspicious_configuration`; `test_suspicious_configuration_flagged_when_other_certs_are_ca_issued`, `test_self_signed_alone_in_scan_is_not_suspicious` |
| Wildcard hostname mismatch folds into ordinary hostname_mismatch, not a separate rule | Done (M1, unchanged) | No separate wildcard-mismatch flag exists; `hostname_mismatch` alone drives that flag |
| Wildcard-breadth inference stays removed | Done | Not present anywhere in `risk_engine.py`; `Certificate.is_wildcard` is read nowhere in this module |
| Overall risk_severity: single worst flag by fixed priority table, never a weighted score | Done | `classify_risk`; `test_expired_beats_everything_else` through `test_nothing_applicable_is_ok` (priority-order tests) |

## Section 13 coverage (this milestone's route)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/scans/{token}/findings` | GET | Implemented — `get_scan_findings`, paginated + `severity`-filterable |
| `/api/scans/{token}` | GET | `summary_counts` re-derived from the risk engine (M3 → M4) |

Rate limiting (Section 18) remains M8's explicit scope — not implemented
on `/findings` or any other route here.

154 tests pass (54 net-new: 46 in `test_risk_engine.py` + 3 in
`test_certificate_parser.py` for DSA/EC key-algorithm formatting + 5 in
`test_routes_scans.py` for `/findings`; plus 2 existing `test_routes_scans.py`
tests updated for the severity-based `summary_counts`, and 1 M0 smoke test
moved from the now-implemented `/findings` route to the still-stubbed
`/report.pdf`). `ruff check`,
`ruff format --check`, and `mypy app` all pass cleanly against the full
M0–M4 codebase. Coverage: `app/risk/risk_engine.py` 100%,
`app/storage/scan_store.py` 100%, `app/api/routes_scans.py` 97% (the
remaining 3% is the still-stubbed 501 handlers for M5–M7).

## M4 implementation decisions (recorded in the Decision Log)

1. **`_key_algorithm` (M1's parser) now embeds EC curve bit-size and
   detects DSA explicitly** — Section 9's weak-crypto rule needs bit-size
   comparisons a bare curve-name string can't supply, and DSA previously
   fell through to a fragile `Unknown (...)` class-name string. Format:
   `EC-{curve}-{bits}`, `DSA-{bits}`. Safe, additive change — no existing
   test asserted the old EC format, and none covered DSA.
2. **DSA is flagged weak unconditionally** — the spec gives RSA and EC
   each a bit-size floor but names DSA with none.
3. **`duplicate_of` is never populated** — `group_into_certificates`
   merges same-fingerprint occurrences into one record with an aggregated
   `endpoints[]`; there is no second record left over needing a pointer
   back to a canonical one. Kept on the dataclass for Section 10 schema
   compatibility only.
4. **`suspicious_configuration` is supplementary, not part of the
   `risk_severity` priority chain** — Section 9's own priority sentence
   names only six flags; suspicious configuration is surfaced via
   `evaluate_flags` but never wins `classify_risk`'s selection.
5. **`GET /api/scans/{token}/findings`'s `severity` filter and
   `page`/`page_size` pagination** — Section 13 names the request shape
   only as "filter, page" without specifics; `severity` matches
   `risk_severity` exactly, `page_size` defaults to 50, capped at 200.
6. **`GET /api/scans/{token}`'s `summary_counts` is now risk-severity-based**
   — same field name and response shape as M3's provisional
   `HostScanStatus` counts (planned in the M3 Decision Log entry), just a
   different vocabulary: hosts with no certificate fall into `scan_failed`.
7. **Weak-crypto tie-break: weak_crypto checked before broken_chain** —
   Section 9 groups both at one priority position ("then weak crypto or
   broken chain") without ordering them relative to each other; this is
   an arbitrary, documented choice, not derived from the spec.

## Open items before M5

- M5 owns report generation (PDF/CSV, Section 15) — it renders the same
  findings this milestone computes; no new risk-engine work is expected.
- Certificate `environment`/`owner` tagging (Section 10's
  `endpoints[]` optional fields) stays unset in every finding — there is
  no UI to set them yet (M6+); `group_into_certificates` never invents a
  value for either.
- Pre-M4 persisted scan records (from local testing before this
  milestone) have no risk data to re-derive `summary_counts`/`findings`
  from cleanly — not a concern in this dev-only environment with no real
  production data yet, and not addressed with migration/backfill logic.
