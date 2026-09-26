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
| `weasyprint` | §15 | Server-side HTML→PDF rendering for reports, no separate rendering service. Dependency is declared now; wiring is deferred to M5 |

**Deliberately not included:** any cloud SDK (`boto3`, `azure-storage-blob`,
etc.). Cloud provider selection is an explicit M2 gate recorded in the
Decision Log — M0 ships only the `LocalFilesystemStorage` backend behind the
`ObjectStorage` interface, so local development and CI need no cloud
credentials at all. No `psycopg2`/ORM — PostgreSQL was superseded by the
object-storage design (Decision Log).

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
