"""Shared pytest fixtures — M0.

Only fixtures needed by M0's own smoke/config tests live here. M1-M9 add
their own fixtures (e.g. certificate PEM fixtures for M1) alongside their
test modules rather than growing this file indefinitely.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
