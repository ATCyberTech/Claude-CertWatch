"""Fixtures for the M9 real-network e2e suite.

Unlike every other test file in this project, nothing here monkeypatches
`app.scanning.scanner.scan_hosts` — these tests exercise the real DNS
resolution, real TCP connect, and real TLS handshake against real public
hosts (see `test_end_to_end.py`'s module docstring for which hosts and
why). `LocalFilesystemStorage` is still pointed at `tmp_path` so a run
never touches the repo's own `.data/` directory or another test's files.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api.routes_scans import limiter
from app.core.config import Settings, get_settings
from app.main import create_app
from app.storage import get_object_storage
from app.storage.local_filesystem import LocalFilesystemStorage


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:
    # Same reason as every other test's client fixture (Decision Log,
    # app.api.routes_scans's module-level `limiter` comment): reset the
    # shared rate-limit state before each test.
    limiter.reset()
    app = create_app()
    storage = LocalFilesystemStorage(tmp_path)
    app.dependency_overrides[get_object_storage] = lambda: storage
    app.dependency_overrides[get_settings] = lambda: Settings(MAX_HOSTS_PER_SCAN=10)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client
