"""CertWatch FastAPI application factory — M0.

A single monolithic FastAPI service (technical specification Section 2/23:
no microservices, no Kubernetes). This module wires together the routers
defined in app.api and app.web; it contains no business logic of its own.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routes_health import router as health_router
from app.api.routes_scans import router as scans_router
from app.core.config import get_settings
from app.web.routes import router as web_router


def create_app() -> FastAPI:
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

    app.include_router(health_router)
    app.include_router(scans_router)
    app.include_router(web_router)

    return app


app = create_app()
