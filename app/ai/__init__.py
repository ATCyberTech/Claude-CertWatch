"""LLM tool-calling layer — owned by M7.

NOT IMPLEMENTED YET. No LLM call of any kind exists in this codebase at M0.

When implemented (Sections 16-17), this package must:
    - Expose exactly four fixed, read-only tools: get_findings, get_certificate,
      get_endpoints_for_certificate, get_summary_counts. No write tool, ever.
    - Send only structured findings JSON to the LLM — never raw certificate
      DER/PEM bytes, full device configuration, or any credential.
    - Support a per-scan AI-enabled/AI-disabled toggle; when disabled, this
      package must not be called at all, and the report must be complete and
      correct without it (verified by a call-count assertion in Section 22).
    - Ground every answer in tool-returned finding_ids/endpoints, with a
      post-check rejecting and regenerating any answer naming a certificate
      or host absent from its own tool results.
    - Sit behind a provider abstraction so the concrete LLM provider (an open
      decision, Section 28) can be swapped without rewriting this package.
    - Never generate synchronous, serial LLM calls in a loop over every
      finding at report-build time (Section 19) — explanations are lazy/on-
      demand or batched in parallel, never a blocking sequential pass.
"""
