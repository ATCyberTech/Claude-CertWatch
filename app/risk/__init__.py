"""Deterministic risk engine — owned by M4.

NOT IMPLEMENTED YET. No LLM involvement in this package, ever (Section 9).

When implemented, this package computes, purely from app.parsing.models.Certificate
fields already populated by M1:
    - Expiry status tiers (EXPIRED / CRITICAL / HIGH / MEDIUM / LOW / OK)
    - Weak/obsolete cryptography flags
    - Duplicate-certificate and shared-across-endpoints detection
    - The single suspicious-configuration rule (inconsistent trust posture
      within one scan) — the wildcard-breadth inference is explicitly REMOVED
      per the Decision Log and must not be reintroduced
    - Overall risk_severity via the fixed priority table in Section 9 — a
      priority table, never a weighted numeric score, to stay explainable
      and testable

Wildcard presence (Certificate.is_wildcard) is informational metadata only —
this package must never use it to infer business necessity.
"""
