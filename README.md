# CertWatch

Deterministic-first, AI-assisted TLS certificate discovery and expiry
monitoring for network/security engineers, consultants, and MSPs — built
for the CA-agnostic gap at the mid-market/MSP tier that vendor-native
certificate-lifecycle tools don't cover.

**Status: M2 — TLS discovery and SSRF/DNS-rebinding defense implemented.
Certificate parsing (M1) and the scanning engine (M2) both work end-to-end
against real hosts, but nothing is wired to the HTTP API yet: `/api/scans`
still returns HTTP 501 because it needs M3's object-storage persistence to
have anywhere to save a scan result/token.** See
[M2 — network scanning](#m2--network-scanning) below.

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
  scanning/  — DNS resolution, SSRF/rebinding guard, TLS discovery — DONE (M2)
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
dependency, and can be exercised on its own without `app.scanning` existing.

`app/scanning/` implements the live side (Section 5, 6, 7, 19):
`network_guard.py` resolves a hostname exactly once and validates every
returned address before any connection is attempted (blocks RFC1918/ULA,
loopback, link-local including the cloud metadata address, multicast,
unspecified, and IPv4-mapped-IPv6 forms of all of the above — this is the
defense against SSRF and DNS-rebinding attacks); `tls_client.py` performs
the TLS handshake against the validated IP literal (never re-resolving)
using pyOpenSSL to retrieve the *full* server-presented certificate chain,
which the stdlib `ssl` module cannot do in this Python version;
`scanner.py` wires network_guard → tls_client → M1's certificate parser
into a single non-raising per-host pipeline, under a two-level concurrency
cap (global + per-scan) and a scan-wide safety-net timeout (Section 19).

Persistence is one JSON document + one PDF per scan in object storage, keyed
by a CSPRNG-generated token — not PostgreSQL. See the CertWatch MVP Technical
Specification v1 for the full rationale (Sections 2, 11).

## Milestone sequence

| Milestone | Deliverable |
| --- | --- |
| **M0** | Repository, architecture skeleton, hosting/CI setup — provider-independent |
| **M1** | Certificate parser + fixture test suite. No live network dependency |
| **M2 gate** | Deployment target decided (local Windows dev, current) and the network-isolation mechanism documented for every supported target — resolved, see the Decision Log |
| **M2** | TLS discovery + full SSRF/rebinding defense. `network_guard.py`, `tls_client.py`, `scanner.py`, full test suite passing (this README describes M0–M2) |
| M3 | Object-storage persistence, token generation and lookup |
| M4 | Deterministic risk engine, including the five-category chain classification |
| M5 | Report generation (PDF/CSV) |
| M6 | Minimal UI, including the AI on/off toggle |
| M7 | AI analyst layer, grounding/citation checks, AI-disabled enforcement |
| M8 | Rate limiting, secrets management, deletion endpoint, prompt-injection tests |
| M9 | End-to-end testing + first real dry run |

## M2 — network scanning

`app/scanning/` is fully implemented: hostname resolution, SSRF/DNS-rebinding
defense, TLS handshake and full certificate-chain retrieval, and the
concurrency/timeout-bounded scan pipeline. The `/api/scans` endpoint still
returns HTTP 501 for every request — that's M3's job, since submitting a
scan needs somewhere to persist its token and result, and object storage
isn't wired up yet.

**The M2 gate (deployment target + network-isolation mechanism) is
resolved.** The current, active deployment target is a **local Windows
development machine** — application-layer SSRF defense
(`network_guard.py`) runs unconditionally regardless of target and is
fully tested (`tests/unit/test_network_guard.py`), but the network-layer
half of defense-in-depth (a dedicated subnet with no route to private
address space, an explicit firewall/ACL deny rule for the cloud metadata
address, provider-specific metadata-service hardening) has no equivalent
on an unconfigured local machine. This is an accepted, explicitly-documented
dev-only gap — **do not expose a local-dev instance of this scanner to the
public internet.** See `docs/deployment/` for the full, provider-agnostic
picture: the same codebase is documented and supported for **AWS, GCP,
Azure, Oracle OCI, and self-hosted** deployment, each with its specific
network-isolation mechanism, so switching the active target later is a
deployment-configuration change, not a code change.

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
