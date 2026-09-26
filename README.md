# CertWatch

Deterministic-first, AI-assisted TLS certificate discovery and expiry
monitoring for network/security engineers, consultants, and MSPs — built
for the CA-agnostic gap at the mid-market/MSP tier that vendor-native
certificate-lifecycle tools don't cover.

**Status: M1 — certificate parsing and chain validation implemented,
against local fixtures only. No live network scanning, storage, or AI
logic is implemented yet.** See [M2 network scanning](#m2-network-scanning-is-not-yet-implemented)
below.

## What CertWatch is

Upload a list of hosts and get a risk-tiered certificate report you can ask
questions about — no login, no credentials, no private key ever requested,
transmitted, or stored. See `docs/` (or the project's CertWatch — Product
Definition v1) for the full product definition; this README covers only what's
needed to build and run the code.

## MVP scope (v0)

**Included:** upload-based host-list input; a network-restricted, read-only
TLS handshake scanner; deterministic X.509 parsing and an eight-rule risk
engine; a per-scan JSON result in object storage; a risk-tiered PDF/CSV
report; a web report view; one AI layer (natural-language explanation and
query over confirmed findings only, with a user-facing off switch).

**Explicitly excluded:** F5 iControl / FortiGate / FortiManager / Palo Alto /
AD CS integration; scheduled or continuous scanning; a hybrid on-prem
scanning agent; MSP multi-tenancy; enterprise SSO; ACME auto-renewal;
certificate deployment/write-back; ownership inference; ML anomaly
detection; inferred (non-confirmed) relationship data; Kubernetes,
microservices, a graph database, a vector database, an event bus, a
multi-agent framework; PostgreSQL.

## Architecture

A single monolithic FastAPI service, server-rendered (Jinja2, no React/SPA at
v0), with clear module boundaries so each build milestone lands in its own
package without restructuring the project:

```
app/
  core/      — configuration (Settings), owned by M0
  scanning/  — DNS resolution, SSRF/rebinding guard, TLS discovery — M2
  parsing/   — X.509 parsing, five-category chain classification — DONE (M1)
  risk/      — deterministic risk engine, no LLM involvement — M4
  storage/   — object-storage abstraction (local backend at M0, cloud at M3)
  ai/        — LLM tool-calling layer, AI on/off toggle — M7
  reports/   — PDF/CSV report generation — M5
  api/       — HTTP API routes (Section 13 route table, stubbed at M0) — M2-M8
  web/       — server-rendered UI — M6
```

`app/parsing/certificate_parser.py` parses server-presented certificate
chains and classifies chain outcome into one of five categories (Section 8)
using `cryptography` for field extraction and `pyhanko-certvalidator` for
RFC 5280 PKIX path validation via a two-pass algorithm (public trust bundle,
then trust extended to the server's own presented certificates). It runs
entirely against local fixtures (`tests/fixtures/certs/`) — no live network
dependency, and `app.scanning` (M2) does not need to exist yet for M1 to work.

Persistence is one JSON document + one PDF per scan in object storage, keyed
by a CSPRNG-generated token — not PostgreSQL. See the CertWatch MVP Technical
Specification v1 for the full rationale (Sections 2, 11).

## Milestone sequence

| Milestone | Deliverable |
| --- | --- |
| **M0** | Repository, architecture skeleton, hosting/CI setup — provider-independent |
| **M1** | Certificate parser + fixture test suite. No live network dependency (this README describes M0+M1) |
| **M2 gate** | Cloud provider selected and the network-isolation mechanism configured and verified, *before* any scanner code is written |
| M2 | TLS discovery + full SSRF/rebinding design. Not complete until the SSRF/rebinding test suite passes |
| M3 | Object-storage persistence, token generation and lookup |
| M4 | Deterministic risk engine, including the five-category chain classification |
| M5 | Report generation (PDF/CSV) |
| M6 | Minimal UI, including the AI on/off toggle |
| M7 | AI analyst layer, grounding/citation checks, AI-disabled enforcement |
| M8 | Rate limiting, secrets management, deletion endpoint, prompt-injection tests |
| M9 | End-to-end testing + first real dry run |

## M2 network scanning is not yet implemented

`app/scanning/` contains only module-boundary stubs. No hostname is resolved,
no DNS lookup happens, and no TCP/TLS connection is ever made by this codebase
at M0. The `/api/scans` endpoint exists (see Section 13) but returns HTTP 501
for every request. This is deliberate: the SSRF/DNS-rebinding defense-in-depth
design (Section 5) is gated on selecting a cloud provider and configuring its
network-isolation mechanism first — see the M2 gate above and the Decision
Log for why.

## How to run locally

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
make run
```

The app serves at `http://localhost:8000/`. `/healthz` returns a liveness
check; `/api/scans` and its sub-routes all return HTTP 501 until their owning
milestone lands.

No cloud account, API key, or network access is required to run or test
CertWatch at M0 — the object-storage backend defaults to the local
filesystem (`.data/scans/`, gitignored).

## How to run tests

```bash
make test        # pytest
make lint         # ruff check
make fmt          # ruff format
make typecheck    # mypy
make check        # all of the above, same order as CI
```

## Dependencies

See `docs/DEPENDENCIES.md` for the full list with a one-line justification
for each package — nothing is added without a reason tied back to a
specification section.

## Contributing / next milestone

Do not implement M1 or later against this skeleton without first reading the
CertWatch MVP Technical Specification v1 section for that milestone and its
corresponding entry in the Decision Log. See `docs/M0_CHECKLIST.md` for what
M0 actually completed and what M1 needs before it can start.
