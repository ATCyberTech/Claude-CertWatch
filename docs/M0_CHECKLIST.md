# M0 completion checklist

Mapped directly to the M0 deliverables (A–J) in the "CertWatch — Begin MVP
Implementation" instruction and the CertWatch MVP Technical Specification v1.

| # | Deliverable | Status | Evidence |
| --- | --- | --- | --- |
| A | Repository structure | Done | `app/` package tree with one subpackage per milestone owner; `tests/`; `docs/`; `.github/workflows/` |
| B | Architecture skeleton | Done | `app/core`, `app/scanning`, `app/parsing`, `app/risk`, `app/storage`, `app/ai`, `app/reports`, `app/api`, `app/web` — each with a docstring stating its owning milestone and gating condition; only `core/config.py`, `storage/local_filesystem.py`, `api/routes_health.py`, `web/routes.py` + template, and `main.py` contain real logic. Everything else raises `NotImplementedError` from a correctly-typed stub |
| C | Configuration / environment-variable structure | Done | `app/core/config.py` (`Settings`, `get_settings()`), field-for-field matching Section 24; `.env.example` mirrors it with inline comments |
| D | Local development instructions | Done | README "How to run locally"; `Makefile` (`install`, `dev-install`, `run`) |
| E | Test framework + initial smoke test | Done | `pytest` + `pytest-asyncio` + `pytest-cov` + `httpx`; `tests/conftest.py`; `tests/unit/test_smoke.py` (healthz, index page, scan-submission-501); `tests/unit/test_config.py`; `tests/unit/test_storage_local_filesystem.py` |
| F | CI pipeline | Done | `.github/workflows/ci.yml` — checkout → setup-python 3.11 → install → ruff check → ruff format --check → mypy → pytest --cov. Provider-independent (no cloud credentials/SDK) |
| G | Dependency list with justification | Done | Inline comments in `pyproject.toml`, expanded into a standalone table in `docs/DEPENDENCIES.md` |
| H | README | Done | `README.md` — what CertWatch is, MVP scope (included/excluded), architecture, milestone table, how to run locally, how to run tests, explicit M2-not-implemented statement |
| I | M0 completion checklist | Done | This file |
| J | Blockers / decisions required before M1 | Done | See "Open items before M1" below |

## Verification run

See the implementation report for the exact commands and their output. Any
failure surfaced by `pip install -e ".[dev]"`, `ruff check .`,
`ruff format --check .`, `mypy app`, or `pytest -v` must be fixed before M0 is
considered complete — this checklist is not satisfied by scaffolding that
doesn't actually pass its own toolchain.

## Explicit non-scope confirmations (Implementation Rules 1–13)

- [x] Only M0 is implemented; M1–M9 are stubs (Rules 1, 2)
- [x] No product features added beyond the spec (Rule 3)
- [x] No architectural redesign — single FastAPI monolith as specified (Rules 4, 12)
- [x] None of PostgreSQL, Kubernetes, microservices, React, background-job infra, vendor integrations, auth/SSO, ACME, continuous monitoring, MSP functionality, auto-remediation, ML, graph DB, vector DB, or multi-agent AI appear anywhere in the tree (Rule 5)
- [x] M0 is cloud-provider independent — the only storage backend is local filesystem; CI has no cloud credentials (Rule 6)
- [x] No live TLS/network scanning — `app/scanning/network_guard.py` raises `NotImplementedError` for both resolution and port validation (Rule 9)
- [x] No certificate parsing beyond module/test structure — `app/parsing/certificate_parser.py` raises `NotImplementedError`; only the data-model contract (`Certificate`, `Endpoint`, `ChainCategory`) is defined, per Rule 10
- [x] Module boundaries are in place so M1–M9 land without restructuring (Rule 11)
- [x] Security principles (SSRF defense-in-depth references, wildcard-inference removal, port allowlist) are referenced in stub docstrings, not weakened for convenience (Rule 13)

## Open items before M1

1. **Decision Log entry pending** — the M0-level tooling decisions (ruff+mypy
   as the lint/format/typecheck toolchain, GitHub Actions as CI provider, the
   `LocalFilesystemStorage` path-traversal-guard design) must be recorded in
   the CertWatch Decision Log before M1 begins, per Rule 14.
2. **M1 needs no new decisions to start** — it can proceed entirely against
   local fixtures (Section 22) with no live network dependency, per the
   milestone-gating clarification already resolved in the Decision Log.
3. **The M2 gate remains open and is not part of M0 or M1** — cloud provider
   selection and verification of the Section 23 network-isolation mechanism
   must happen before any scanner code is written. This is a blocker for M2
   only, not for M1.
4. No other blockers identified for M1.
