# M9 completion checklist

Mapped to Section 25's M9 row ("End-to-end testing plus a first real dry
run against the founder's own GCC contacts") and Section 26's Definition
of Done.

## What M9 delivers from inside this sandboxed dev container

**Done — real-network end-to-end testing** (`tests/e2e/`, opt-in via
`pytest -m e2e`, deliberately excluded from the default `pytest -q` run):

| Definition-of-Done bullet (Section 26) | Status | Evidence |
| --- | --- | --- |
| A no-account user submits a host list and gets a working report link | Done | `test_full_scan_journey_against_real_hosts` — real DNS + TCP + TLS, no monkeypatching |
| PDF and CSV exports match the web report's findings | Done | Same test — both exports fetched and checked non-empty/well-formed against a real scan |
| Ask CertWatch / AI-disabled mode makes zero LLM calls | Done | `test_ai_toggle_and_ask_fallback_against_a_real_scan` — no `LLM_API_KEY` anywhere in this environment, so the real (non-mocked) fallback path is what's actually exercised |
| A scan owner can request and confirm deletion of their own data | Done | `test_deletion_removes_a_real_scans_data` |
| Rate limits (Section 18) are independently verified by their own tests | Done (reconfirmed against real traffic) | `test_rate_limits_enforced_against_real_traffic` — the M8 unit tests already covered this against `TestClient`'s synthetic transport; this one hits the same code path with real scans |
| The deterministic engine classifies chain categories / SSRF-DNS handling holds under real conditions | Partially reconfirmed | `test_disallowed_and_unreachable_hosts_do_not_crash_a_mixed_scan` proves a real loopback address is rejected and a real DNS failure doesn't crash a mixed scan — see the finding below for why exact chain-category/expiry claims aren't asserted here |

**Not done from here, and not attemptable from here — a real environmental
finding, not a gap in the code:**

This sandboxed dev container's outbound HTTPS is transparently
TLS-intercepted by an Anthropic egress proxy. Confirmed by direct
inspection: a scan of `example.com` run from this container receives a
certificate whose issuer is `CN=Egress Gateway SDS Issuing CA
(production), O=Anthropic` — not example.com's real, publicly-issued
certificate. Every certificate this container's network can see is this
proxy's synthetic one, regardless of which real host is dialed.

Consequences:

- **The `badssl.com`-specific claims (expired, self-signed, hostname
  mismatch) cannot be validated from this container** — the interception
  proxy presents its own always-current, always-trusted-looking
  certificate no matter what the real origin actually serves. This is
  why `tests/e2e/test_end_to_end.py` deliberately does not assert on
  `is_expired`, `chain_category`, or `hostname_mismatch` values, only
  that the pipeline runs and produces internally-consistent findings.
  The exact same test code, run from a network that doesn't intercept
  TLS (the founder's own machine, or CertWatch's actual deployment
  target), would validate those claims too — nothing in the test itself
  assumes interception.
- **"A first real dry run against the founder's own GCC contacts"
  (Section 25) cannot be performed meaningfully from this container at
  all.** CertWatch's entire value proposition is inspecting the real
  certificate a server presents; from behind this interception proxy,
  every scan would report the proxy's certificate, not the target
  organization's. Running it anyway and reporting the results as if they
  reflected the founder's actual contacts' infrastructure would be
  actively misleading, not just incomplete.
- This is unrelated to network **destination** reachability — the
  sandbox's raw TCP/TLS egress on port 443 to arbitrary public hosts
  works fine (confirmed: `example.com`, several `badssl.com` subdomains
  all connect and complete a handshake). The problem is strictly that
  what comes back over that connection isn't the real origin's
  certificate.

## Open items before this milestone can be called fully complete

- **The founder needs to supply the real target hostnames** for the dry
  run — CertWatch cannot invent or guess which companies are "the
  founder's own GCC contacts," and scanning real third-party
  infrastructure needs the founder's own knowledge that it's fine to run
  a passive, read-only TLS handshake against those hosts (the same kind
  of connection any browser visiting the site makes — no login, no
  credentials, nothing written).
- **The dry run itself needs to run from a network that doesn't
  TLS-intercept egress** — the founder's own machine (`uvicorn
  app.main:app` locally, per the README's "How to run locally" section)
  is the simplest option, since it's also where CertWatch is expected to
  run for local dev per the M2 gate decision. Running it from this
  sandboxed container would produce misleading results, as explained
  above.
- Once both are available, the dry run itself is operationally simple:
  submit the real host list through the running app (via `curl` or the
  web UI) and review the resulting report — no new code is needed for
  this; M0–M8 already built everything the dry run exercises.

## Verification

`ruff check`, `ruff format --check`, and `mypy app` (strict) all pass
cleanly. The existing 238-test unit suite is unaffected (still runs by
default under `pytest -q`); the 6 new e2e tests run only via
`pytest -m e2e` (registered in `pyproject.toml`, `addopts = "-m 'not
e2e'"` keeps them out of the default run and out of any CI job that
doesn't explicitly opt in — appropriate given they depend on real
internet egress that a CI runner may not have, unlike everything else in
this project's test suite).
