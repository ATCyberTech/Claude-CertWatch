"""LLM tool-calling layer (Sections 16-17) — implemented at M7.

- Exposes exactly four fixed, read-only tools (`app.ai.tools`): get_findings,
  get_certificate, get_endpoints_for_certificate, get_summary_counts. No
  write tool exists.
- Sends only structured findings JSON to the LLM (`app.ai.tools._finding_dict`)
  — never raw certificate DER/PEM bytes, full device configuration, or any
  credential.
- Enforces the per-scan AI-enabled/AI-disabled toggle in `app.ai.analyst`:
  when `scan.ai_enabled` is False, `app.ai.llm_client` is never called, and
  the report/findings/exports remain complete and correct without it.
- Grounds every answer in tool-returned certificate/host names
  (`app.ai.analyst._passes_grounding_check`), falling back to a plain
  message rather than returning an ungrounded answer.
- Sits behind the `LLMProvider` abstraction (`app.ai.llm_client`) so the
  concrete provider (Anthropic's Messages API at v0 — Section 28 open
  decision #3, recorded in the Decision Log) can be swapped later.
- Is only ever called on-demand from the `/ask` route — never in a
  synchronous loop over every finding at report-build time.
"""
