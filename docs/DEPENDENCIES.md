# M0 dependency justification

Every dependency below is tied to a specific section of the CertWatch MVP
Technical Specification v1 or an explicit M0 implementation decision (see the
Decision Log). Nothing is added speculatively. This is the standalone version
of the inline justification comments already present in `pyproject.toml`.

## Runtime dependencies

| Package | Spec section | Why |
| --- | --- | --- |
| `fastapi` | §2, §13, §14 | The application framework — a single monolith, no microservices |
| `uvicorn[standard]` | §2 | ASGI server to run the FastAPI app |
| `jinja2` | §2, §14 | Server-rendered report/UI templates — no React/SPA at v0 |
| `python-multipart` | §14 | Required by FastAPI for the host-list upload form |
| `pydantic` | §24 | Typed request/response models and settings validation |
| `pydantic-settings` | §24 | Server-side environment-variable configuration (never client-controlled) |
| `cryptography` | §8, §10 | Low-level X.509 field parsing and signature primitives — explicitly **not** used for PKIX path building (see below) |
| `pyhanko-certvalidator` | §8, Decision Log | The actual chain-validation engine: RFC 5280 path building, handles cross-signed certs and alternate paths, supports the two-pass validation algorithm needed to distinguish private-CA chains from broken ones. Selected specifically because `cryptography` + `certifi` alone do not perform path building — using them alone would have been an overclaim, corrected during the Final Implementation Clarifications pass |
| `certifi` | §8 | Maintained public trust-root bundle used as Pass 1's trust anchor |
| `asn1crypto` | §8, Decision Log (M1) | `pyhanko-certvalidator`'s own certificate representation; `app.parsing` imports it directly to build `ValidationContext` trust roots from the certifi bundle, so it is pinned explicitly rather than relied on only as a transitive dependency |
| `pyopenssl` | §6, §7, Decision Log (M2) | Retrieves the **full** server-presented certificate chain (leaf + intermediates) via OpenSSL's `SSL_get_peer_cert_chain()`. The stdlib `ssl` module has no public API for this in this Python version — `SSLSocket.getpeercert()` returns the leaf only — confirmed by direct introspection (`dir(ssl.SSLSocket)`) before choosing this dependency |
| `slowapi` | §18 | Per-IP submission and `/ask` rate limiting without standing up a separate service |
| `weasyprint` | §15 | Server-side HTML→PDF rendering for reports, no separate rendering service. Wired as of M5 (`app.reports.report_builder.build_pdf_report`) |

**Deliberately not included:** any cloud SDK (`boto3`, `azure-storage-blob`,
etc.), still, even after M3. The M2 gate resolved to local Windows dev as
the current active deployment target — no cloud credentials exist to test
a real S3-compatible backend against, so `LocalFilesystemStorage` remains
the only `ObjectStorage` backend; the interface itself (M0) makes adding
one trivial once a specific cloud target is actually stood up (Decision
Log). No `psycopg2`/ORM — PostgreSQL was superseded by the object-storage
design (Decision Log). No new runtime dependency was needed for M3 —
token generation uses stdlib `secrets`, and persistence reuses `pydantic`
(already a dependency) for the JSON-safe scan-record schema. No new
runtime dependency was needed for M4 either — the risk engine is pure
Python over data `cryptography`/`pydantic` (already dependencies) already
produce. No new runtime dependency was needed for M5 either — CSV export
uses stdlib `csv`, not pandas, and `weasyprint`/`jinja2` were already
declared dependencies, just not yet wired to anything.

## Dev / test dependencies

| Package | Why |
| --- | --- |
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support (FastAPI routes are async) |
| `pytest-cov` | Coverage reporting, used in CI |
| `httpx` | Transport required by FastAPI's `TestClient` |
| `ruff` | Lint + format in a single tool (M0 implementation decision — not named explicitly in the spec; recorded in the Decision Log) |
| `mypy` | Strict static type checking (same M0 implementation decision) |

## Toolchain / CI decisions (not Python packages)

- **ruff + mypy** as the lint/format/type-check toolchain — an M0
  implementation decision, recorded in the Decision Log per Rule 14.
- **GitHub Actions** as the CI provider — same basis.
- **`parse_certificate_chain` is async** — M1 implementation decision,
  because `pyhanko-certvalidator`'s path validator (`async_validate_path`)
  is async-only; the M0 stub signature was synchronous. Recorded in the
  Decision Log.
- **`mypy` overrides `asn1crypto.*` with `ignore_missing_imports`** —
  `asn1crypto` ships no type stubs or `py.typed` marker.
- **M2 gate resolved: local Windows machine is the current deployment
  target; AWS, GCP, Azure, Oracle OCI, and self-hosted are all documented
  and supported by the same provider-agnostic code** (M2 implementation
  decision, user-directed). See `docs/deployment/` for each target's
  network-isolation mechanism and the Decision Log for the full rationale.
- **`SSL.VERIFY_NONE` at the TLS layer is an intentional design choice, not
  an oversight** (M2 implementation decision) — CertWatch's own two-pass
  validator (`app.parsing.certificate_parser`) is the sole source of truth
  for chain trust; a strict OpenSSL verify would refuse to complete a
  handshake at all for the private/internal-CA case CertWatch is
  specifically designed to still report on.
- **Global scan concurrency is a `functools.lru_cache(maxsize=1)`-backed
  `asyncio.Semaphore` singleton** (M2 implementation decision) — this is
  what makes the Section 19 concurrency cap hold across *simultaneous scan
  submissions*, not just within one `scan_hosts` call; a fresh per-scan
  semaphore is created on every call to additionally bound concurrency
  within a single scan.
- **pyOpenSSL handshakes require a manual `WantReadError`/`WantWriteError`
  retry loop** (M2 implementation note, discovered while writing
  `tests/unit/test_tls_client.py`) — a Python socket with `settimeout(x)`
  set retries transparently at the socket-module level, but pyOpenSSL
  talks to the fd directly via OpenSSL's BIO layer and bypasses that retry,
  surfacing transient not-ready states as exceptions instead. Fixed with
  `select.select`-driven retries bounded by the same per-host timeout
  budget (`app/scanning/tls_client.py::_run_ssl_op`).
- **Encoded-private-IP tests accept either `DisallowedAddressError` or
  `ResolutionError`** (M2 fix, found testing on Windows) — Linux's glibc
  canonicalizes decimal/octal/hex-encoded IP forms before validation ever
  sees them; Windows' WinSock `getaddrinfo` refuses to resolve them at all
  (`WSANO_DATA`). Both are safe outcomes; the tests only fail if a host is
  ever treated as allowed.
- **M3 persists raw per-host scan outcomes, not Section 10's endpoint-
  grouped-by-certificate shape** (M3 implementation decision) —
  certificate deduplication (`duplicate_of`, grouping into
  `Certificate.endpoints`) and `risk_severity` are M4's job once the risk
  engine exists to do that grouping/scoring; M3 only needs a durable,
  lookup-able record of exactly what `scan_hosts` produced.
- **`ports` in `POST /api/scans` is index-aligned with `hosts`** (M3
  implementation clarification) — Section 13 describes it only as
  "optional per-host port override" without stating its shape; this
  implementation requires `len(ports) == len(hosts)` when provided
  (422 otherwise) and defaults every host to port 443 when omitted.
- **Scans run synchronously inside the `POST /api/scans` request**, not
  via a background job queue (M3 implementation decision) — Section 2's
  own architecture table places "Background jobs" as "None customer-
  facing" at v0, and Section 19's worst-case estimate (250 hosts, ~85
  seconds) is explicitly sized for exactly this.
- **`get_object_storage()` takes no parameters**, unlike an earlier draft
  that took an optional `Settings` argument (M3 implementation note,
  found while wiring the API routes) — a FastAPI dependency callable with
  a `Settings`-typed parameter is itself treated as needing a `Settings`
  object from the request body, breaking `POST /api/scans`'s own body
  parsing. Tests override the dependency via FastAPI's
  `app.dependency_overrides` instead of parameterizing the factory.
- **`_key_algorithm` (M1's parser) now embeds EC curve bit-size and detects
  DSA explicitly** (M4 fix to M1-owned code, found while implementing
  Section 9's weak-crypto rule) — the rule needs bit-size comparisons
  ("RSA under 2048 bits ... ECDSA under P-256") that a bare curve *name*
  string (`EC-secp256r1`) can't supply without a name-to-bits lookup table,
  and DSA previously fell through to a fragile, backend-specific
  `Unknown (...)` class-name string. Format is now `EC-{curve}-{bits}`;
  DSA is `DSA-{bits}`. No existing test asserted the old EC format, and no
  test covered DSA at all, so this was a safe, additive change.
- **DSA is flagged as weak crypto unconditionally, with no bit-size floor
  of its own** (M4 implementation decision) — Section 9 gives RSA and EC
  each an explicit bit-size threshold but names DSA with none, so any DSA
  key size is treated as weak.
- **`duplicate_of` is never populated** (M4 implementation decision) —
  `group_into_certificates` merges every occurrence of a given fingerprint
  into one `Certificate` record with an aggregated `endpoints[]`, so there
  is no second, separate record left over that would need a pointer back
  to a canonical one. The field stays on the dataclass for Section 10
  schema compatibility but is unused by this implementation.
- **`suspicious_configuration` is a supplementary flag, not part of the
  `risk_severity` priority chain** (M4 implementation decision) — Section
  9's own priority sentence for "Overall risk severity" names only six
  flags (EXPIRED, weak crypto/broken chain, hostname mismatch,
  approaching-expiry tiers, shared, private CA); suspicious configuration
  is surfaced via `evaluate_flags`'s `flags` list but never wins
  `classify_risk`'s single-worst-flag selection.
- **`GET /api/scans/{token}/findings`'s `severity` filter and
  `page`/`page_size` pagination** (M4 implementation clarification) —
  Section 13 describes the request only as "filter, page" without naming
  the filter field or a page size. `severity` matches a finding's computed
  `risk_severity` (the only per-finding categorical value Section 9 itself
  defines); `page_size` defaults to 50, capped at 200.
- **`GET /api/scans/{token}`'s `summary_counts` is now risk-severity-based**
  (M4 implementation decision, planned since M3) — same field name and
  response shape as M3's provisional `HostScanStatus` counts, different
  vocabulary: each host contributes to the severity bucket of the
  certificate it presented, or to a `scan_failed` bucket if it has none.
- **`build_pdf_report`/`build_csv_report` now also take the owning
  `ScanRecord`, beyond the M0 stub's bare `list[Certificate]`** (M5
  implementation decision) — Section 3's methodology footer needs
  scan-level metadata (`submitted_at`, `host_count`) a certificate list
  alone can't supply; the same latitude M3 used for
  `resolve_and_validate`'s signature change from its own M0 stub.
- **The PDF is rendered once, synchronously, at the end of `submit_scan`
  and persisted to `scans/{token}/report.pdf`; the CSV is never persisted
  and is always regenerated per request** (M5 implementation decision) —
  Section 11's storage layout explicitly lists a `report.pdf` key
  alongside `result.json` but no CSV key, so this maps the stated storage
  design directly rather than inventing a policy.
- **`GET /api/scans/{token}/report.pdf` regenerates the PDF on the fly
  only as a defensive fallback**, when no persisted PDF is found for a
  token (M5 implementation decision) — a scenario that can only arise for
  a scan record persisted before this milestone existed; there is no real
  production data yet, so this is dev-only scaffolding, not a documented
  production behavior.
- **`mypy` overrides `weasyprint.*` with `ignore_missing_imports`** (M5
  implementation note) — `weasyprint` ships no type stubs or `py.typed`
  marker, same class of fix as the existing `asn1crypto.*` override.
