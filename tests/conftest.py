"""Shared pytest fixtures — M0.

Only fixtures needed by M0's own smoke/config tests live here. M1-M9 add
their own fixtures (e.g. certificate PEM fixtures for M1) alongside their
test modules rather than growing this file indefinitely.

M8 note (recorded in the Decision Log): `app.api.routes_scans.limiter` is
a module-level singleton whose in-memory rate-limit storage would
otherwise accumulate across every test in this process (see that module's
comment above the `limiter = Limiter(...)` line). `limiter.reset()` is
called here before each test yields its client so Section 18's rate
limits never leak between unrelated tests. `tests/unit/test_routes_scans.
py` and `tests/unit/test_web_routes.py` define their own local `client`
fixtures rather than reusing this one, so they each need the identical
reset call — see those files.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api.routes_scans import limiter
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    limiter.reset()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
