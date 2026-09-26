"""Object-storage abstraction — interface owned by M0, cloud backends owned by M3.

Per the Decision Log, PostgreSQL is out of v0 entirely: persistence is one JSON
document + one PDF per scan, in object storage, keyed by the CSPRNG scan token
(technical specification Section 11-12). This package defines that abstraction
now (get/put/delete over a string key) so:

  - Local development (M0 deliverable: "local development instructions") works
    today against a LocalFilesystemStorage backend, with no cloud account and
    no network dependency.
  - M3 adds the scan-specific persistence logic (token generation, JSON
    schema, save/load) in `app.storage.scan_store`, and a real cloud
    backend (S3 / Azure Blob / R2) behind the *same* interface once a
    specific cloud target is actually stood up — calling code never
    changes either way. See `app.storage.scan_store`'s module docstring
    for why a cloud backend isn't wired yet.

The interface itself is intentionally minimal (three methods) and holds no
scan-specific logic (no token generation, no JSON schema) — that lives in
`app.storage.scan_store` (Section 11-12).
"""

from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.storage.interface import ObjectStorage
from app.storage.local_filesystem import LocalFilesystemStorage


class UnsupportedStorageBackendError(Exception):
    """Raised when `OBJECT_STORAGE_BACKEND` names a backend not yet
    implemented — a real S3-compatible backend is deliberately deferred
    (see `app.storage.scan_store`'s module docstring) until a specific
    cloud target is actually being stood up."""


@lru_cache
def get_object_storage() -> ObjectStorage:
    """Return the process-wide `ObjectStorage` singleton for the
    configured backend. Mirrors `app.core.config.get_settings`'s caching
    pattern (no parameters — a FastAPI dependency callable that took a
    `Settings` parameter would itself be treated as a body field needing a
    `Settings` object from the request, which is not what's wanted here).
    Tests override this via FastAPI's `app.dependency_overrides` rather
    than mutating the cache."""
    settings = get_settings()
    if settings.object_storage_backend == "local":
        return LocalFilesystemStorage(settings.object_storage_local_path)
    raise UnsupportedStorageBackendError(
        f"OBJECT_STORAGE_BACKEND={settings.object_storage_backend!r} is not implemented yet — "
        "only 'local' exists today. See docs/deployment/ and the Decision Log."
    )
