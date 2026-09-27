# M8 completion checklist

Mapped directly to Section 18 (rate limiting), the still-unimplemented
BUILD NOW rows of Section 12 (token/access-control hygiene) and Section 21
(security requirements), and Section 25's M8 row ("Rate limiting, Section
18, secrets management, deletion endpoint, prompt-injection tests"), plus
the relevant rows of Section 22's test spec.

## Section 18 requirement mapping

| Requirement | Status | Evidence |
| --- | --- | --- |
| Scan submissions: 5/hour/IP | Done | `app.api.routes_scans._SUBMIT_RATE_LIMIT = "5/hour"`, enforced via `@limiter.limit(...)` on both `submit_scan` (JSON) and `submit_scan_via_web` (web UI); `test_submit_scan_sixth_submission_in_one_hour_is_429` |
| `/ask`: 20 questions/scan (lifetime cap) | Done | `app.storage.scan_store.increment_ask_count`/`ScanRecord.ask_count`, checked inside `answer_scan_question` before any AI logic runs; `test_ask_per_scan_lifetime_cap_returns_429_on_the_21st_question` (JSON), `test_ask_shows_per_scan_cap_message_inline_once_exceeded` (web UI) |
| `/ask`: 60/hour/IP | Done | `_ASK_IP_RATE_LIMIT = "60/hour"`, enforced via `@limiter.limit(...)` on both `ask_certwatch` (JSON) and `ask_certwatch_web` (web UI) |
| Global concurrent TLS connections: 100 | Done (M2, reconfirmed) | `app.scanning.network_guard`'s `asyncio.Semaphore` singleton; unaffected by this milestone |
| Max hosts per scan: 250 | Done (M3, reconfirmed) | `Settings.max_hosts_per_scan`, enforced in `execute_scan`; unaffected by this milestone |
| CAPTCHA/proof-of-work bot-abuse challenge | Explicitly not required for initial launch | Section 18 itself states this; documented as a BUILD BEFORE PUBLIC LAUNCH contingency (monitor submission volume/IP diversity, add a challenge only if abuse is observed) |

## Section 21 requirement mapping (this milestone's rows)

| Requirement | Status | Evidence |
| --- | --- | --- |
| Secrets (LLM API key, storage credentials) in the hosting platform's secret manager, never in code or logs | Partially done | `LLM_API_KEY` was already environment-variable-only (never hardcoded) since M7; "never in logs" is now backed by `app.core.logging_config`'s token redaction (see below) — the "hosting platform's secret manager" half remains deferred until a concrete cloud target is stood up, consistent with the M2 gate precedent for cloud-specific tooling |
| Deletion endpoint removing the object-storage blob on request | Done | `DELETE /api/scans/{token}` (`delete_scan_endpoint`), backed by `app.storage.scan_store.delete_scan`; `test_delete_scan_returns_204_and_removes_the_scan`, `test_delete_scan_unknown_token_is_404`, `test_delete_scan_twice_is_404_the_second_time` |
| Data retention default of 90 days for free-tier scans | Not built this milestone | "BUILD NOW (default), confirmation pending — see Section 28" per Section 21 itself; requires a background expiry sweep, out of Section 25's stated M8 scope ("Rate limiting, Section 18, secrets management, deletion endpoint, prompt-injection tests") — flagged as an open item below |
| Prompt-injection handling (Section 17) | Done (M7 handling, M8 tests) | Handling itself was implemented in M7 (tool results as data, never concatenated into instructions); M8 adds the adversarial tests — see below |
| GCC data-residency confirmation before regulated-adjacent customers | Not applicable yet | "BUILD BEFORE PUBLIC LAUNCH to that segment — not a general blocker" per Section 21 itself |

## Section 12 requirement mapping (gap closed this milestone)

| Requirement | Status | Evidence |
| --- | --- | --- |
| `Referrer-Policy: no-referrer` on all token-bearing pages | Done | `app.main.create_app`'s `add_referrer_policy_header` ASGI middleware, applied globally (a strict superset); `test_response_carries_referrer_policy_header` |
| Tokens redacted in server access logs and application logs | Partially done | `app.core.logging_config.RedactTokensFilter`, attached to the root logger and `certwatch.ai`; reliably covers every logger CertWatch's own code writes through. Does **not** reliably cover uvicorn's own built-in access log (`uvicorn.access`) — see that module's docstring and `docs/DEPENDENCIES.md` for the documented mitigation (`--no-access-log` / a reverse-proxy log pipeline) |

This gap had been tagged BUILD NOW since M3 but was never actually
implemented in any prior milestone (confirmed by grepping the codebase for
`Referrer-Policy`/`no-referrer`/redaction logic before starting M8, which
found none) — folded into this milestone's "secrets management" scope
since it's the closest fit and no other milestone owned it.

## Section 22 test-spec mapping

| Requirement | Status | Evidence |
| --- | --- | --- |
| Scan-submission limit enforced per IP; correct status code | Done | `test_submit_scan_sixth_submission_in_one_hour_is_429` (429) |
| `/ask` limit enforced per scan and per IP; correct status code | Done | `test_ask_per_scan_lifetime_cap_returns_429_on_the_21st_question` (per-scan, 429); the per-IP-hourly `slowapi` decorator is exercised implicitly by every other `/ask` test run against the same limiter and pinned by `test_rate_limit_constants_match_section_18_exactly` |
| Every host/cert name in an AI answer appears in the tool results it received | Done (M7, reconfirmed) | `tests/unit/test_ai_analyst.py`'s grounding tests; unaffected by this milestone |
| Subject-CN injection-style text does not change model behavior | Done (M8, new) | `test_tool_call_returns_injection_style_subject_cn_completely_unmodified` (tool layer never interprets/strips it); `test_system_prompt_is_never_mixed_with_injected_tool_result_content` (the `system=` parameter sent to the model is byte-identical to `_SYSTEM_PROMPT` on every tool-calling-loop iteration, regardless of what the injected CN says) |
| AI-disabled mode makes zero LLM calls, verified by call-count assertion | Done (M7, reconfirmed) | `test_ai_disabled_never_calls_provider`; unaffected by this milestone |

## Test coverage

236 tests collected (23 net-new: 8 in `tests/unit/test_scan_store.py`
covering `increment_ask_count`/`AskLimitExceededError`/`delete_scan`, 7 in
`tests/unit/test_routes_scans.py` covering rate limits/the per-scan
ask-cap/the deletion route/the Referrer-Policy header, 1 in
`tests/unit/test_web_routes.py` covering the per-scan ask-cap rendered
inline, 1 in `tests/unit/test_ai_tools.py` (the injection-style subject-CN
test), 1 new file `tests/unit/test_llm_client.py` (the system-prompt
isolation test), 1 new file `tests/unit/test_logging_config.py` with 5
tests for the redaction filter). `ruff check`, `ruff format --check`, and
`mypy app` (strict) all pass cleanly. Coverage: `app/api/routes_scans.py`
100%, `app/storage/scan_store.py` 100%, `app/core/logging_config.py` 100%,
`app/web/routes.py` 100%, `app/main.py` 100%, `app/ai/tools.py` 100%;
overall project coverage 96%.

## M8 implementation decisions (recorded in the Decision Log)

1. **The two per-IP-hourly limits (5/hour submit, 60/hour/IP ask) are
   fixed `slowapi` limit strings, not read from `Settings`** — `slowapi`
   decorators are bound at module-import time, before any per-request
   `Settings` exists.
2. **The per-scan lifetime `/ask` cap (20/scan) is a persisted
   `ScanRecord.ask_count` counter, not a `slowapi` limit** — it's a
   lifetime cap, not a sliding time window, and fully respects the
   existing `Settings`-injected value.
3. **`_TOKEN_ROUTE_LIMIT` ("30/minute") is a documented-but-not-spec-
   stated defense-in-depth number** for the remaining token routes.
4. **`DELETE /api/scans/{token}` is an M8 addition to Section 13**,
   sourced from Section 21's independent requirement, JSON-API only.
5. **`Referrer-Policy: no-referrer` is applied globally via one ASGI
   middleware**, closing a Section 12 gap that existed since M3.
6. **Scan-token log redaction is a `logging.Filter`**, with a documented,
   honest scope limit around uvicorn's own access log.
7. **The shared, module-level `slowapi.Limiter` requires `.reset()` in
   every test's `client` fixture** to avoid cross-test rate-limit
   pollution within a single `pytest` run.
8. **Prompt-injection test design**: one test at the tool layer (data
   passes through unmodified) and one at the LLM-client layer (the
   `system` parameter is never mixed with tool-result content), rather
   than a single end-to-end test — each isolates a different layer of
   Section 17's actual guarantee.

## Open items before M9

- **Section 21's 90-day data-retention default is not implemented** — it
  needs a background expiry sweep (there is no job scheduler in this
  monolith yet per Section 2's architecture table), and Section 21 itself
  flags it as "confirmation pending — see Section 28," not a hard BUILD
  NOW blocker for this milestone's stated scope. Left as an explicit open
  item for a future milestone to pick up.
- **uvicorn's own built-in access log is not covered by token
  redaction** — the documented mitigation (`--no-access-log`, or routing
  access logs through a reverse-proxy pipeline with its own redaction) is
  an operational decision for whoever deploys this, not something this
  application factory can guarantee from inside itself.
- **The hosting platform's secret manager (Section 21) remains
  deferred** until a concrete cloud target is stood up — same basis as
  the M2 gate decision for `ObjectStorage`'s cloud backends.
- M9 (per Section 25) is end-to-end testing and a first real dry run
  against the founder's own GCC contacts — the natural point to revisit
  whether the CAPTCHA/bot-abuse challenge Section 18 defers is actually
  needed, based on observed submission volume.
