"""CertWatch FastAPI application factory — M0.

A single monolithic FastAPI service (technical specification Section 2/23:
no microservices, no Kubernetes). This module wires together the routers
defined in app.api and app.web; it contains no business logic of its own.

M8 adds three cross-cutting security concerns, all owned by this factory
rather than any one route module since they apply across the whole app:

1. Rate limiting (Section 18): registers `app.api.routes_scans.limiter`
   as `app.state.limiter` and installs slowapi's own `RateLimitExceeded`
   handler, which is what actually turns an exceeded `@limiter.limit(...)`
   decorator (already applied to individual routes in `routes_scans` and
   `web.routes`) into a 429 response — without this wiring, a rate-limited
   route would raise `RateLimitExceeded` with no handler and 500.
2. Referrer-Policy (Section 12): `no-referrer` is set on every response
   via a small ASGI-level middleware, applied globally rather than only to
   token-bearing routes — a strict superset of what Section 12 requires
   and simpler than tracking which specific paths carry a token.
3. Log redaction (Section 12/21): `app.core.logging_config.configure_log_
   redaction` is called once here so every logger CertWatch's own code
   writes through has scan-token redaction attached before the app starts
   serving requests. See that module's docstring for its documented scope
   limits (it does not reach uvicorn's own built-in access log).
"""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes_health import router as health_router
from app.api.routes_scans import limiter
from app.api.routes_scans import router as scans_router
from app.core.config import get_settings
from app.core.logging_config import configure_log_redaction
from app.web.routes import router as web_router


def create_app() -> FastAPI:
    configure_log_redaction()

    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=(
            "CertWatch MVP v0 — deterministic-first, AI-assisted TLS certificate "
            "discovery and expiry monitoring. M0 architecture skeleton: no live "
            "scanning, parsing, storage, or AI logic is implemented yet."
        ),
    )

    app.state.limiter = limiter
    # slowapi's own handler is typed against a plain `Request`/`Response`
    # pair, not Starlette's more general exception-handler signature —
    # this is slowapi's stated integration pattern (its own README uses
    # the identical call), not a real type mismatch in the app.
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    @app.middleware("http")
    async def add_referrer_policy_header(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Section 12: `Referrer-Policy: no-referrer` on every response.
        Applied globally (a strict superset of "all token-bearing pages")
        rather than tracked per-route, since every route in this app either
        carries a token already or could start carrying one without this
        middleware needing an update."""
        response: Response = await call_next(request)
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.include_router(health_router)
    app.include_router(scans_router)
    app.include_router(web_router)

    return app


app = create_app()
