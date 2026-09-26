"""Tests for the `get_object_storage` backend factory (M3, Section 11)."""

from __future__ import annotations

import pytest

from app.core.config import Settings, get_settings
from app.storage import UnsupportedStorageBackendError, get_object_storage
from app.storage.local_filesystem import LocalFilesystemStorage


@pytest.fixture(autouse=True)
def _clear_caches():
    get_object_storage.cache_clear()
    get_settings.cache_clear()
    yield
    get_object_storage.cache_clear()
    get_settings.cache_clear()


def test_local_backend_returns_local_filesystem_storage(monkeypatch, tmp_path):
    monkeypatch.setenv("OBJECT_STORAGE_BACKEND", "local")
    monkeypatch.setenv("OBJECT_STORAGE_LOCAL_PATH", str(tmp_path))
    storage = get_object_storage()
    assert isinstance(storage, LocalFilesystemStorage)


def test_get_object_storage_is_a_singleton(monkeypatch, tmp_path):
    monkeypatch.setenv("OBJECT_STORAGE_LOCAL_PATH", str(tmp_path))
    assert get_object_storage() is get_object_storage()


def test_unsupported_backend_raises(monkeypatch):
    monkeypatch.setenv("OBJECT_STORAGE_BACKEND", "s3")
    with pytest.raises(UnsupportedStorageBackendError):
        get_object_storage()


def test_settings_default_backend_is_local():
    # Documents the existing default (app/core/config.py) that this
    # factory relies on.
    assert Settings().object_storage_backend == "local"
