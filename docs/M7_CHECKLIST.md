# M7 completion checklist

Mapped directly to Sections 16 (AI architecture) and 17 (AI privacy/
prompt-injection design) of the CertWatch MVP Technical Specification v1,
plus the `/ask` row of Section 13 and the M7 row of Section 25's milestone
table ("AI analyst layer, grounding/citation checks, AI-disabled
enforcement").

## Section 16 requirement mapping

| Requirement | Status | Evidence |
| --- | --- | --- |
| One AI layer: NL explanation/query over confirmed findings only, no autonomous remediation | Done | `app/ai/analyst.py::answer_question` only ever calls read-only tools; no write tool exists anywhere in `app/ai/tools.py` |
| Per-scan `scan.ai_enabled` toggle; when disabled, zero LLM calls | Done | `answer_question` returns the fallback message before constructing a `ScanToolExecutor` or calling `provider.ask` at all when `not record.ai_enabled`; `test_ai_disabled_never_calls_provider` asserts `provider.call_count == 0` |
| Report/findings/exports complete and correct without AI | Done (M5/M6, reconfirmed) | `app/reports/report_builder.py` has no AI narration slot at all; unaffected by this milestone |
| Four fixed, read-only tools: `get_findings`, `get_certificate`, `get_endpoints_for_certificate`, `get_summary_counts` | Done | `app/ai/tools.py::TOOL_SCHEMAS`, `ScanToolExecutor.call`; `tests/unit/test_ai_tools.py` (10 tests) |
| No write tool, ever | Done (by construction) | `ScanToolExecutor.call`'s dispatcher has no mutating branch |
| System prompt: role, "only use tool-returned data," fact/inference/recommendation labeling | Done | `app/ai/llm_client.py::_SYSTEM_PROMPT` |
| Tool-calling loop | Done | `AnthropicProvider.ask`, bounded by `_MAX_TOOL_ITERATIONS` |
| Grounding: every sentence traces to a finding_id/endpoint, inline citations | Done | `app/ai/analyst.py::_passes_grounding_check`/`_citations_in`; `answer_scan_question` returns `AskResponse.citations` |
| Hallucination control: post-check rejects/regenerates | Done | `_passes_grounding_check` + one retry in `answer_question` (`_MAX_ANSWER_ATTEMPTS = 2`), then falls back — see the Decision Log for why "fall back" rather than an unbounded regenerate loop |
| Fallback: LLM failure/timeout/AI-off shows a plain message, report never blocked | Done | `_FALLBACK_MESSAGE`; `LLMUnavailableError` is caught in `answer_question`, never propagated; the PDF/CSV report path is entirely independent of `app.ai` |

## Section 17 requirement mapping

| Requirement | Status | Evidence |
| --- | --- | --- |
| Data that MAY be sent: structured findings only (`certificate_id, subject_cn, san_list, issuer, days_to_expiry, risk_severity, chain_category, endpoints, flags`) | Done | `app/ai/tools.py::_finding_dict` returns exactly this shape; `test_finding_dict_never_includes_pem_bytes` asserts the exact key set |
| Data that must NEVER be sent: raw DER/PEM, device config, credentials, any non-surfaced field | Done | No code path in `app/ai/` reads `Certificate.pem` or anything from `app.scanning`/`app.core.config` credentials |
| Provider abstraction: one hosted provider at v0, swappable | Done | `LLMProvider` ABC (`app/ai/llm_client.py`); `AnthropicProvider` is the only concrete implementation, constructed solely by `build_llm_provider` |
| Prompt-injection handling: CN/SAN are attacker-influenceable, sent only as structured tool-result data, never concatenated into instructions | Done | Tool results are appended as `tool_result` content blocks, never string-formatted into `_SYSTEM_PROMPT` or the user message; the system prompt explicitly instructs the model to treat every tool-returned string as data, not a command |
| `/ask` rate limits (20/scan, 60/hour/IP) | Explicitly deferred to M8 | Section 25's own milestone table lists rate limiting under M8, separate from M7's scope; recorded in the Decision Log, consistent with the deferral pattern used since M3 |
| Cost controls: per-scan/per-IP limits bound worst case; daily spend cap is operational, not app code | Deferred to M8 alongside rate limiting | Same Decision Log entry |
| Logging/audit: every LLM tool call logged separately from app logs; question text logged for abuse investigation, never shown to anyone but the scan owner | Partially done | Tool calls are logged via a dedicated `certwatch.ai` logger (`AnthropicProvider.ask`); question-text logging for abuse investigation is left to M8, which owns the abuse-investigation/rate-limiting tooling this would feed — recorded in the Decision Log |

## Section 13 coverage (this milestone's route)

| Endpoint | Method | Status |
| --- | --- | --- |
| `/api/scans/{token}/ask` | POST | Implemented — `ask_certwatch` delegates to `answer_scan_question`, which delegates all AI logic to `app.ai.analyst.answer_question` |

## Test coverage

213 tests collected (28 net-new: 10 in `tests/unit/test_ai_tools.py`, 10 in
`tests/unit/test_ai_analyst.py`, 8 added to `tests/unit/test_routes_scans.py`;
`tests/unit/test_smoke.py::test_ask_not_yet_implemented` and
`tests/unit/test_web_routes.py::test_ask_shows_not_available_notice` were
rewritten in place for real M7 behavior rather than the M6-era 501 stub).
`ruff check`, `ruff format --check`, and `mypy app` (strict) all pass
cleanly. Coverage: `app/ai/tools.py` 100%, `app/ai/analyst.py` 97% (two
lines in an inner endpoint-shape branch of `_known_names` not hit — a
minor, non-load-bearing gap), `app/ai/llm_client.py` 55% (the
`AnthropicProvider.ask` tool-calling loop's real-network-call lines are
untested by design, the same class of gap `app/scanning/tls_client.py`
and `app/scanning/network_guard.py` already have — no test suite here
makes a real Anthropic API call), `app/api/routes_scans.py` 100%,
`app/web/routes.py` 100%.

## M7 implementation decisions (recorded in the Decision Log)

1. **Anthropic's Messages API is the v0 LLM provider**, resolving Section
   28's open decision #3.
2. **`LLMProvider.ask` takes a `tools: ScanToolExecutor` parameter**
   beyond the M0 stub's `(question, scan_token)` signature.
3. **`ask_certwatch`'s body is factored into a plain
   `answer_scan_question` function**, mirroring M6's `execute_scan`
   pattern, shared by the JSON API and the web UI.
4. **Grounding is a regex-based known-names check against tool results
   actually received**, not a second LLM call; a failing answer is
   retried once, then falls back — not regenerated indefinitely.
5. **Tool calls are logged via a dedicated `certwatch.ai` logger**;
   question-text logging for abuse investigation is left to M8.
6. **Rate limiting and cost controls (Section 18) remain explicitly
   deferred to M8**, per Section 25's own milestone split.

## Open items before M8

- M8 owns: rate limiting (20 questions/scan, 60/hour/IP, and the
  5/hour/IP submission limit already declared but unenforced since M3),
  secrets management, the scan-deletion endpoint, and prompt-injection
  *tests* (Section 17's prompt-injection *handling* is implemented here;
  M8 validates it under adversarial input).
- Question-text logging for abuse investigation (Section 17) has no
  consumer yet — building it now would be unused code; M8's rate-limiting
  work is the natural place to add a log sink with its own access
  controls.
- Real AI answers require `LLM_API_KEY` (and optionally `LLM_MODEL`) to be
  configured — with no key, `/ask` and the web Ask box work end-to-end
  and correctly return the fallback message, which is itself now
  covered by tests (`test_ask_with_no_configured_provider_returns_fallback`).
