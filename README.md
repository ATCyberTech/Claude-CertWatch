# CertWatch

Deterministic-first, AI-assisted TLS certificate discovery and expiry
monitoring for network/security engineers, consultants, and MSPs — built
for the CA-agnostic gap at the mid-market/MSP tier that vendor-native
certificate-lifecycle tools don't cover.

**Status: M6 — minimal UI implemented. A full server-rendered web
workflow now sits on top of the M3–M5 JSON API: paste or upload a host
list at `/`, watch it scan synchronously, and land on a results page with
a risk summary, a sortable/filterable certificate inventory, per-
certificate detail pages, PDF/CSV download links, and a visible AI
on/off toggle (`PATCH /api/scans/{token}/ai-preference` is now real, not
a stub). `ask`/the Ask CertWatch box still show "not available yet" —
there is no AI layer to answer with until M7.** See
[M6 — minimal UI](#m6--minimal-ui) below.

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
  risk/      — deterministic risk engine, no LLM involvement — DONE (M4)
  storage/   — object-storage abstraction + scan persistence — DONE (M3)
  ai/        — LLM tool-calling layer, AI on/off toggle enforcement — M7
  reports/   — PDF/CSV report generation — DONE (M5)
  api/       — HTTP API routes (Section 13 route table) — all but /ask DONE (M3/M4/M5/M6), /ask still M7
  web/       — server-rendered UI — DONE (M6)
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

`app/storage/scan_store.py` implements persistence (Section 10/11/12):
`generate_scan_token()` produces a CSPRNG token (`secrets.token_urlsafe(32)`,
~256 bits of entropy) that is both the sole scan identifier and the
object-storage key (`scans/{token}/result.json`) — no sequential or
guessable ID exists anywhere. `ScanRecord`/`HostResultRecord`/
`CertificateRecord` are the JSON-safe persisted shape; `save_scan_record`/
`load_scan_record` round-trip it through the `ObjectStorage` interface
(M0). Persistence is one JSON document per scan in object storage — not
PostgreSQL. See the CertWatch MVP Technical Specification v1 for the full
rationale (Sections 2, 11).

`app/risk/risk_engine.py` implements the deterministic risk engine
(Section 9): `group_into_certificates` builds Section 10's endpoint-
grouped-by-certificate shape from a scan's raw persisted per-host results,
on demand (never written back to storage); `classify_risk`/`evaluate_flags`
compute the single-worst-flag `risk_severity` via a fixed priority table
(never a weighted score) plus the full list of applicable flags. No LLM
involvement anywhere in this module.

`app/reports/report_builder.py` implements report generation (Section
15): `render_report_html` renders one Jinja2 template (Section 1 —
certificates requiring attention, Section 2 — full inventory, Section 3 —
methodology/scope footer) from the same `app.risk`-grouped-and-scored
`Certificate` list `GET /findings` serves, so the PDF, the CSV, and the
API can never disagree with each other. `build_pdf_report` renders that
HTML to PDF via WeasyPrint; `build_csv_report` writes the same data as
CSV via the standard library's `csv` module. No LLM involvement — report
generation never blocks on an AI call.

`app/web/routes.py` implements the minimal server-rendered UI (Section
14): the upload/scan form, the scan results page (risk summary,
sortable/filterable certificate inventory, Ask CertWatch box + AI
toggle, report download links), and per-certificate detail pages. It
calls the exact same `execute_scan`/`app.risk`/`app.reports` functions
the JSON API uses — never its own copy of that logic — so the two front
ends can never scan, score, or render a result differently.

## Milestone sequence

| Milestone | Deliverable |
| --- | --- |
| **M0** | Repository, architecture skeleton, hosting/CI setup — provider-independent |
| **M1** | Certificate parser + fixture test suite. No live network dependency |
| **M2 gate** | Deployment target decided (local Windows dev, current) and the network-isolation mechanism documented for every supported target — resolved, see the Decision Log |
| **M2** | TLS discovery + full SSRF/rebinding defense. `network_guard.py`, `tls_client.py`, `scanner.py`, full test suite passing |
| **M3** | Object-storage persistence, token generation and lookup. `POST /api/scans` + `GET /api/scans/{token}` implemented end-to-end |
| **M4** | Deterministic risk engine (five-category chain classification was M1). `GET /api/scans/{token}/findings` implemented end-to-end; `summary_counts` now severity-based |
| **M5** | Report generation (PDF/CSV). `GET /api/scans/{token}/report.pdf` and `.csv` implemented end-to-end |
| **M6** | Minimal UI, including the AI on/off toggle control. `app/web/routes.py` implemented end-to-end; `PATCH /api/scans/{token}/ai-preference` implemented (this README describes M0–M6) |
| M7 | AI analyst layer, grounding/citation checks, AI-disabled enforcement |
| M8 | Rate limiting, secrets management, deletion endpoint, prompt-injection tests |
| M9 | End-to-end testing + first real dry run |

## M6 — minimal UI

`app/web/routes.py` implements Section 14's eight UI elements as a plain
server-rendered (Jinja2, no React/SPA) workflow:

1. **Upload/scan** (`GET /`) — paste a host list into a textarea and/or
   upload a `.txt`/`.csv` file; both are parsed, combined, and
   deduplicated (order-preserving) into one host list, then handed to
   `POST /scan`, which calls `app.api.routes_scans.execute_scan` — the
   exact function `POST /api/scans` itself calls — so pasted, uploaded,
   and JSON-API submissions can never be scanned or persisted
   differently. The page shows the spec's own scope note verbatim:
   "public port 443 reachability only, no internal network access."
2. **Scanning/progress** — trivial by construction: scans run
   synchronously (M3), so by the time `POST /scan`'s redirect lands on
   the results page the scan has already finished. No polling, no job
   status, no separate progress UI needed.
3. **Risk summary** — severity-tiered badge counts
   (`summarize_risk_severity`) plus a "top findings" list (worst
   severity, then soonest-expiring, capped at 5), each linking to its
   certificate's detail page.
4. **Certificate inventory** — a table over every certificate the risk
   engine grouped and scored, sortable (`?sort=severity|expiry|subject_cn`,
   a leading `-` reverses) and filterable by severity
   (`?severity=critical`) via plain links and query parameters — no
   client-side JS, consistent with Section 2's "no React/SPA."
5. **Certificate detail** (`/scans/{token}/certificates/{fingerprint}`)
   — chain category (visually distinct via a color-coded badge, one of
   the five from Section 8), SAN list, and every observing endpoint.
6. **Finding explanation** — absent entirely, not a placeholder. There
   is no AI layer yet (M7); Section 14 itself says this element is
   "absent entirely when AI is off," so there is nothing to build here
   before an AI layer exists to explain anything (the same latitude M5
   used for the report's own AI-narration slot).
7. **Ask CertWatch + the AI on/off toggle** — the toggle
   (`POST /scans/{token}/ai-preference`) is the real deliverable of this
   milestone: it persists `scan.ai_enabled` via
   `app.storage.scan_store.update_ai_preference`, the same
   storage-mutation function the JSON `PATCH .../ai-preference` route
   now calls too (previously a 501 stub). The question box posts to
   `POST /scans/{token}/ask`, which calls the still-M7-stubbed
   `ask_certwatch` and — on its expected 501 — shows a plain "not
   available yet" notice instead of an error page, per Section 16's own
   "Fallback" bullet ("if the LLM call fails, times out, or AI is
   toggled off, the Ask box shows a plain message").
8. **Report/export** — plain links to the M5 `/api/scans/{token}/report.pdf`/`.csv` routes.

**What M6 does *not* do (explicitly out of scope, Decision Log):**
enforce `ai_enabled` against any LLM call — there is no LLM call
anywhere yet to gate, so "enforcement" has nothing to enforce; that is
M7's job, once an AI layer exists. The toggle here is only the *control*
Section 25's own M6 row names.

## M5 — report generation

`app/reports/report_builder.py` implements Section 15 in full:

- **`render_report_html(scan_record, certificates)`** — the single shared
  HTML render both exports and (indirectly) `GET /findings` agree with:
  Section 1 lists only certificates whose `risk_severity` isn't `"ok"`,
  sorted worst-severity-first then soonest-expiring-first; Section 2 lists
  every discovered certificate, `"ok"` ones included; Section 3 restates
  Section 8's stated OCSP/CRL revocation-checking limitation and a
  point-in-time disclaimer. No AI narration exists in this implementation
  (there is no AI layer yet — M7) — Section 1's optional per-certificate
  AI explanation is simply absent, not a placeholder.
- **`build_pdf_report(scan_record, certificates)`** — renders that HTML to
  PDF bytes via WeasyPrint.
- **`build_csv_report(scan_record, certificates)`** — one CSV row per
  certificate (matching Section 2's "every certificate, including
  OK-status ones"), via the standard library's `csv` module — no pandas
  dependency needed for something this simple.

Both signatures extend the M0 stub (`list[Certificate]` only) to also
take the owning `ScanRecord`, because the methodology footer needs
scan-level metadata (`submitted_at`, `host_count`) a bare certificate list
can't supply — recorded in the Decision Log, the same latitude M3 used
for `resolve_and_validate`'s signature.

**Persistence design (Decision Log):** Section 11's storage layout lists
`scans/{token}/report.pdf` alongside `result.json` but no CSV key. So the
PDF is rendered once, synchronously, at the end of `submit_scan` and
persisted to that key — `report_url` in `ScanSubmitResponse` is meaningful
the moment the scan itself completes. `GET /api/scans/{token}/report.pdf`
normally just reads that persisted PDF back; it only regenerates on the
fly as a defensive fallback, for a scan record persisted before this
milestone existed (a dev-only scenario). The CSV export is never
persisted and is always generated fresh per request from the persisted
`ScanRecord`.

## M4 — deterministic risk engine

`app/risk/risk_engine.py` implements Section 9 in full:

- **`expiry_tier`** — EXPIRED (days_to_expiry < 0), CRITICAL (≤7 days), HIGH
  (≤30), MEDIUM (≤60), LOW (≤90), OK otherwise.
- **`is_weak_crypto`** — RSA under 2048 bits, DSA (any size — the spec
  gives it no threshold of its own), or ECDSA under P-256; or a signature
  algorithm of MD5 or SHA1.
- **`_is_shared`** — more than one endpoint observed the same certificate
  fingerprint in the scan (the rule table's "Duplicate certificates" and
  "Certificates shared across endpoints" rows are the same underlying
  signal, "surfaced as shared, not an error").
- **`classify_risk`** — the single worst applicable flag by Section 9's
  fixed priority table: EXPIRED, then weak crypto or broken chain, then
  hostname/SAN mismatch, then approaching-expiry tiers, then shared, then
  private CA. Never a weighted numeric score.
- **`_is_suspicious_configuration`** — a self-signed certificate alongside
  other CA-issued certificates in the same scan (an inconsistent trust
  posture). This is a supplementary flag surfaced via `evaluate_flags`,
  not part of the `risk_severity` priority chain above — Section 9's own
  priority sentence names only the six flags in `classify_risk`.

`group_into_certificates` builds Section 10's endpoint-grouped-by-
certificate shape from a scan's raw per-host results **on demand** — one
`Certificate` per unique fingerprint, with every observing host:port
merged into `.endpoints`. Nothing is written back to storage; M3's
persisted shape is unchanged. `duplicate_of` is never populated (see the
Decision Log) — merging same-fingerprint occurrences into one record
already expresses "this certificate is shared/duplicated," so there is no
second record left over needing a pointer back to a canonical one.

`GET /api/scans/{token}/findings` serves this grouped, risk-scored view,
paginated (`page`/`page_size`, default 50, capped at 200) and filterable
by `severity` (Section 13 describes the request only as "filter, page"
without naming the filter field — this implementation's choice, recorded
in the Decision Log). `GET /api/scans/{token}`'s `summary_counts` now
buckets by risk severity per host (superseding M3's raw `HostScanStatus`
counts) — a host with no certificate at all (a failed handshake, a
disallowed port) falls into a `scan_failed` bucket.

## M3 — persistence and the scan API

`POST /api/scans` runs the scan synchronously against M2's `scan_hosts`
(there is no background-job queue at v0 — Section 2's own architecture
table places "Background jobs" as "None customer-facing", and Section 19's
worst-case estimate, ~85 seconds for 250 hosts, is sized for exactly this),
generates a CSPRNG token, persists the result, and returns
`{token, status, report_url}`. `GET /api/scans/{token}` looks the scan back
up by token alone — no other authorization check exists or is needed
(Section 12: the token *is* the access control). An unknown token is a 404,
never a 403 or a different-shaped response, so a wrong guess reveals
nothing. `source_ip` is persisted for abuse investigation only and is
never present in any API response.

`summary_counts` in the status response is, for now, a count of M2's
`HostScanStatus` values (`ok`, `disallowed_port`, `handshake_failed`, ...)
— **not** the risk-severity tiers Section 9's deterministic risk engine
will eventually produce. M4 replaces/extends the data behind that field;
the response shape itself doesn't change.

Certificate deduplication across hosts sharing a certificate
(`Certificate.duplicate_of`, grouping into `endpoints[]`) and
`risk_severity` are also explicitly M4's job — M3 persists one record per
submitted host:port, exactly as `scan_hosts` produced it.

## M2 — network scanning

`app/scanning/` is fully implemented: hostname resolution, SSRF/DNS-rebinding
defense, TLS handshake and full certificate-chain retrieval, and the
concurrency/timeout-bounded scan pipeline.

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

The app serves at `http://localhost:8000/`. Open `/` in a browser for the
full upload/scan-report workflow (M6), or use `/healthz` and the
`/api/scans/...` JSON routes directly — `POST /api/scans`,
`GET /api/scans/{token}`, `GET /api/scans/{token}/findings`,
`GET /api/scans/{token}/report.pdf`/`.csv`, and
`PATCH /api/scans/{token}/ai-preference` all work end-to-end. Only `ask`
still returns HTTP 501, until M7 lands.

No cloud account, API key, or network access beyond the actual scan
targets is required to run or test CertWatch — the object-storage backend
defaults to the local filesystem (`.data/scans/`, gitignored).

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
