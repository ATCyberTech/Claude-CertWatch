"""Deterministic risk engine — Section 9, implemented as of M4. No LLM
involvement in this package, ever.

See `app.risk.risk_engine` for the implementation:
    - `expiry_tier` / `is_weak_crypto` — the individual per-certificate rules
    - `group_into_certificates` — builds Section 10's endpoint-grouped-by-
      certificate shape from a `ScanRecord`, on demand (not persisted)
    - `classify_risk` / `evaluate_flags` — the fixed-priority-table overall
      severity, plus the supplementary suspicious-configuration flag
    - `summarize_risk_severity` — the per-host severity summary used by
      `GET /api/scans/{token}`

Wildcard presence (`Certificate.is_wildcard`) is informational metadata
only — this package never uses it to infer business necessity (the
wildcard-breadth inference was explicitly removed per the Decision Log
and must not be reintroduced).
"""
