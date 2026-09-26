"""HTTP API routes (Section 13).

app.api.routes_health is fully implemented at M0 (the only real product
endpoint this milestone ships). app.api.routes_scans defines the full
Section 13 route table now, with every handler returning HTTP 501 Not
Implemented, so:

  - The API surface (paths, methods, request/response shapes) is fixed and
    reviewable today, matching Section 13 exactly.
  - M2 through M8 each implement one or two handlers in place, without ever
    adding a new route or changing this file's shape.

No route below performs a network call, a database/storage call, or an LLM
call at M0 — every handler is a stub.
"""
