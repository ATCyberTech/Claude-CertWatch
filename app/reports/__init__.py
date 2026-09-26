"""PDF/CSV report generation — owned by M5.

NOT IMPLEMENTED YET. When implemented (Section 15), this package renders the
three-section report (certificates requiring attention, full inventory,
methodology/scope footer) from findings already computed by app.risk (M4),
via WeasyPrint for PDF and the standard library/pandas for CSV. Report
rendering must never block on an LLM call (Section 19) — AI narration, when
present, is composed separately by app.ai and merged in, not generated inline
during report assembly.
"""
