"""PDF/CSV report generation — Section 15, implemented as of M5.

See `app.reports.report_builder` for the implementation: the three-section
report (certificates requiring attention, full inventory, methodology/scope
footer) is rendered from `Certificate` objects already computed by
`app.risk` (M4), via WeasyPrint for PDF and the standard library's `csv`
module for CSV. Report rendering never blocks on an LLM call (Section 19)
— there is no AI layer yet (M7); when it exists, its narration is composed
separately and merged in, not generated inline during report assembly.
"""
