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
| `python-multipart` | §14 | Required by FastAPI for the host-list upload form. Wired as of M6 (`app.web.routes`) |
| `pydantic` | §24 | Typed request/response models and settings validation |
| `pydantic-settings` | §24 | Server-side environment-variable configuration (never client-controlled) |
| `cryptography` | §8, §10 | Low-level X.509 field parsing and signature primitives — explicitly **not** used for PKIX path building (see below) |
| `pyhanko-certvalidator` | §8, Decision Log | The actual chain-validation engine: RFC 5280 path building, handles cross-signed certs and alternate paths, supports the two-pass validation algorithm needed to distinguish private-CA chains from broken ones. Selected specifically because `cryptography` + `certifi` alone do not perform path building — using them alone would have been an overclaim, corrected during the Final Implementation Clarifications pass |
| `certifi` | §8 | Maintained public trust-root bundle used as Pass 1's trust anchor |
| `asn1crypto` | §8, Decision Log (M1) | `pyhanko-certvalidator`'s own certificate representation; `app.parsing` imports it directly to build `ValidationContext` trust roots from the certifi bundle, so it is pinned explicitly rather than relied on only as a transitive dependency |
| `pyopenssl` | §6, §7, Decision Log (M2) | Retrieves the **full** server-presented certificate chain (leaf + intermediates) via OpenSSL's `SSL_get_peer_cert_chain()`. The stdlib `ssl` module has no public API for this in this Python version — `SSLSocket.getpeercert()` returns the leaf only — confirmed by direct introspection (`dir(ssl.SSLSocket)`) before choosing this dependency |
| `slowapi` | §18 | Per-IP submission and `/ask` rate limiting without standing up a separate service |
| `weasyprint` | §15 | Server-side HTML→PDF rendering for reports, no separate rendering service. Wired as of M5 (`app.reports.report_builder.build_pdf_report`) |
| `anthropic` | §16, §17, §28 open decision #3 | The v0 LLM provider's SDK, chosen as the M7 implementation resolving Section 28's open provider-selection decision (Decision Log). Used only behind `app.ai.llm_client.LLMProvider` (Section 17's "Provider abstraction" requirement) — `app.ai.analyst` and the `/ask` route never import it directly, so swapping providers touches only `app/ai/llm_client.py` |

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
declared dependencies, just not yet wired to anything. No new runtime
dependency was needed for M6 either — `fastapi`/`jinja2`/`python-multipart`
were already declared (for exactly this purpose, per their own table
rows above) and just not yet wired to a real UI. **M7 adds exactly one
new runtime dependency, `anthropic`** — no dev/test dependency was needed;
`FakeLLMProvider`/`_FakeProvider` test doubles implement the same
`LLMProvider` interface without importing the SDK at all.

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
- **`submit_scan`'s body is factored into a plain `execute_scan`
  function**, called by both the JSON `POST /api/scans` route and the
  web UI's `POST /scan` form handler (M6 implementation decision) — so
  the two front ends can never scan or persist a submission differently;
  `app.web` importing a function from `app.api.routes_scans` is a
  one-directional dependency (the reverse never happens), so no import
  cycle is introduced.
- **The web UI's pasted-textarea and uploaded-file host lists are
  combined and deduplicated (order-preserving), then split on newlines
  and commas** (M6 implementation clarification) — Section 14 says only
  "paste or upload a host list" without specifying a syntax or whether
  both inputs can be used together; this implementation lets someone use
  either or both without scanning a host twice.
- **`ruff`'s `extend-immutable-calls` now also lists `fastapi.File` and
  `fastapi.Form`** (M6 implementation note) — the same class of fix as
  the existing `fastapi.Depends`/`Query`/`Path` entries: these are the
  framework's own idiom for declaring a form field or file upload, not
  the mutable-default-argument bug B008 exists to catch.
- **`PATCH /api/scans/{token}/ai-preference` persists `scan.ai_enabled`
  but enforces nothing** (M6 implementation decision) — this milestone
  builds the toggle *control* Section 25's own M6 row names; there is no
  LLM call anywhere yet to gate on the flag, so "enforcement" (never
  calling the LLM when it's `False`) is explicitly left to M7, once an
  AI layer exists to enforce it on.
- **Anthropic's Messages API is the v0 LLM provider, resolving Section
  28's open decision #3** (M7 implementation decision, recorded in the
  Decision Log) — its native tool-use support maps directly onto Section
  16's "system prompt + tool-calling loop" design; the choice is recorded
  rather than left open because the provider abstraction (Section 17's
  own requirement) already makes it swappable later at no cost.
- **`LLMProvider.ask` takes a `tools: ScanToolExecutor` parameter beyond
  the M0 stub's `(question, scan_token)`** (M7 implementation decision) —
  the stub predates the tool-calling design; a provider needs the tool
  executor bound to *this* scan's data to run its own tool-calling loop.
- **`ask_certwatch`'s body is factored into a plain `answer_scan_question`
  function**, called by both the JSON `POST /api/scans/{token}/ask` route
  and the web UI's Ask box (M7 implementation decision, mirroring M6's
  `execute_scan` pattern) — so the two front ends can never answer a
  question differently.
- **Grounding is a regex-based known-names check, not a second LLM call**
  (M7 implementation decision) — every certificate_id/subject_cn/SAN/
  endpoint-host string seen in a tool result the model actually received
  is collected into a known-names set; any hostname-shaped string in the
  model's answer that isn't in that set fails the check. This is
  deterministic and free, versus asking a second LLM call to verify the
  first (real cost, and itself unverifiable). An answer that fails is
  retried once (a fresh provider call), then falls back to the plain
  message — this is "reject and fall back," not "reject and regenerate
  indefinitely," given the fixed per-question retry budget Section 18's
  rate limits imply is scarce.
- **Every LLM tool call is logged via a dedicated `certwatch.ai` logger**
  (M7 implementation decision, Section 17's audit requirement) — kept
  separate from ordinary app logs so tool-call audit trails (tool name,
  scan token) can be reviewed or shipped independently; the question text
  itself is not logged by this logger (Section 17 says it should be
  logged for abuse investigation but shown to no one but the scan owner —
  left for M8's rate-limiting/abuse-investigation work to wire a
  question-text log sink with its own access controls, rather than
  building that here with no consumer yet).
- **Rate limiting (Section 18: 20 questions/scan, 60/hour/IP) is not
  implemented on `/ask`** (M7 implementation decision) — Section 25's own
  milestone table lists rate limiting under M8, distinct from M7's
  "grounding and citation checks, AI-disabled enforcement" scope; this
  continues the same deferral pattern used for `submit_scan` since M3.
- **`submit_scan`'s 5/hour/IP and `ask_certwatch`'s 60/hour/IP caps
  (Section 18) are enforced via `slowapi` as fixed limit strings, not
  read from `Settings`** (M8 implementation decision) — `slowapi`'s
  `@limiter.limit(...)` decorators are applied once at module-import
  time, before any per-request `Settings` exists, so they cannot consult
  a `Depends`-resolved or test-overridden `Settings` instance the way
  every other value in `app.api.routes_scans` does. Changing either
  enforced number now requires a code change to `_SUBMIT_RATE_LIMIT`/
  `_ASK_IP_RATE_LIMIT`, not just an env var — the
  `submit_rate_limit_per_ip_per_hour`/`ask_rate_limit_per_ip_per_hour`
  `Settings` fields remain declared for Section 24 documentation parity
  only. The remaining `/api/scans/{token}/*` routes (status, findings,
  the two report exports, ai-preference, and the new deletion route) get
  a generous, explicitly-not-spec-stated `_TOKEN_ROUTE_LIMIT`
  ("30/minute") — defense-in-depth against token brute-forcing per
  Section 21's "Rate-limited access" control, not a number Section 18
  itself gives.
- **Section 18's "/ask: 20/scan" is a persisted `ScanRecord.ask_count`
  counter, not a `slowapi` limit** (M8 implementation decision) — it's a
  lifetime cap on one scan, not a sliding time window, so it cannot be
  expressed as a `slowapi` rate string at all. Checked and incremented by
  `app.storage.scan_store.increment_ask_count` inside
  `answer_scan_question`, before any AI logic runs; every accepted call
  counts, even one that ends up answering with the plain fallback
  message, since the cap protects the endpoint itself from volume, not
  just LLM spend. Unlike the two `slowapi` limits above, this fully
  respects the existing `Settings`-injected `ask_rate_limit_per_scan`
  value and the test suite's `dependency_overrides` convention.
- **Rate-limiting a shared, module-level `slowapi.Limiter` requires an
  explicit `.reset()` in every test's `client` fixture** (M8
  implementation note, found while writing the M8 test suite) —
  `app.api.routes_scans.limiter` is a process-wide singleton (the module
  is imported once per test process), so its in-memory rate-limit
  storage would otherwise accumulate across every test in a single
  `pytest` run and eventually cause spurious 429s in unrelated tests.
  `tests/conftest.py`'s `client` fixture and the two local `client`
  fixtures in `tests/unit/test_routes_scans.py`/`test_web_routes.py` each
  call `limiter.reset()` before yielding their `TestClient`.
- **`DELETE /api/scans/{token}` is an M8 addition to Section 13's route
  table, sourced from Section 21's independent security-requirements
  table** (M8 implementation decision) — Section 13 itself lists no
  deletion row, but Section 21 states "Deletion endpoint removing the
  object-storage blob on request" as its own BUILD NOW item. Removes the
  persisted `result.json` and `report.pdf` for a token
  (`app.storage.scan_store.delete_scan`); the CSV export is never
  persisted, so there is nothing to remove there. JSON-API only — Section
  14's UI spec lists no delete affordance, so no web-UI button was added.
- **`Referrer-Policy: no-referrer` is applied globally, via one ASGI
  middleware in `app.main.create_app`, not per-route** (M8 implementation
  decision) — Section 12 (BUILD NOW since M3, never actually implemented
  until this milestone) requires it on "all token-bearing pages"; applying
  it to every response is a strict superset that's simpler to keep correct
  than tracking which specific paths carry a token as the route table
  grows.
- **Scan-token redaction in application logs is a `logging.Filter`
  (`app.core.logging_config.RedactTokensFilter`) attached to the root
  logger and `certwatch.ai`, not a real log-shipping pipeline** (M8
  implementation decision) — CertWatch has no log-shipping infrastructure
  of its own at v0 (the same "no cloud target stood up yet" framing as
  Section 21's secret-manager requirement). This reliably covers every
  logger CertWatch's own code writes through, but does **not** reach
  uvicorn's own built-in access log (`uvicorn.access`), whose handler
  wiring is controlled by uvicorn's own `dictConfig` at a point in the
  startup sequence this application factory cannot reliably order itself
  around. Documented, honest mitigation: run uvicorn with `--no-access-log`
  in any environment where access-log token exposure matters, or route
  access logs through a reverse proxy/log pipeline with its own
  redaction — this module does not claim a guarantee it cannot keep.
- **No new runtime dependency was needed for M8** — `slowapi` was already
  declared (§18, since M0) and simply wired up for the first time; the
  deletion endpoint reuses the existing `ObjectStorage.delete` (present
  since M0); log redaction and the Referrer-Policy header use only the
  stdlib `logging` module and Starlette's own middleware hook.
- **M9's real-network e2e tests (`tests/e2e/`) are opt-in via a
  registered `e2e` pytest marker, excluded from the default `pytest -q`
  run by `addopts = "-m 'not e2e'"`** (M9 implementation decision) —
  every other test in this project monkeypatches `scan_hosts` and needs
  no network; these hit real public hosts over real DNS/TCP/TLS, which a
  CI runner may not have and which would otherwise slow down the
  fast, always-run unit suite every prior milestone relied on.
- **This sandboxed dev container's outbound HTTPS is transparently
  TLS-intercepted by an Anthropic egress proxy** (M9 finding, recorded in
  the Decision Log) — confirmed by direct inspection: a real scan of
  `example.com` run from here receives a certificate issued by `CN=Egress
  Gateway SDS Issuing CA (production), O=Anthropic`, never the origin's
  real certificate. Raw TCP/TLS reachability to arbitrary public hosts on
  port 443 is otherwise unrestricted (unlike the HTTP(S) proxy governing
  `curl`/`pip`/etc.) — the problem is strictly that certificate *content*
  seen here always reflects the interception proxy, not the real origin
  server. This blocks two things specifically: validating `badssl.com`'s
  expired/self-signed/hostname-mismatch claims from this container (the
  e2e tests deliberately don't assert on them), and Section 25's "first
  real dry run against the founder's own GCC contacts," which needs both
  real target hostnames only the founder can supply and a network path
  that doesn't intercept TLS (the founder's own machine, per the M2 gate
  decision's local-Windows-dev target) — see `docs/M9_CHECKLIST.md`.
