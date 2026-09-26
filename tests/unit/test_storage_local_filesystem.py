"""Tests for the M0 local-filesystem ObjectStorage backend.

This is dev-plumbing scaffolding (see app/storage/__init__.py), so tests here
cover the interface contract only — no scan/token logic exists yet to test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.storage.local_filesystem import InvalidStorageKeyError, LocalFilesystemStorage


def test_put_then_get_roundtrips(tmp_path: Path) -> None:
    storage = LocalFilesystemStorage(tmp_path)
    storage.put("scans/abc123/result.json", b'{"ok": true}')
    assert storage.get("scans/abc123/result.json") == b'{"ok": true}'


def test_get_missing_key_returns_none(tmp_path: Path) -> None:
    storage = LocalFilesystemStorage(tmp_path)
    assert storage.get("does/not/exist.json") is None


def test_delete_is_idempotent(tmp_path: Path) -> None:
    storage = LocalFilesystemStorage(tmp_path)
    storage.put("k", b"v")
    storage.delete("k")
    storage.delete("k")  # must not raise
    assert storage.get("k") is None


def test_path_traversal_key_is_rejected(tmp_path: Path) -> None:
    storage = LocalFilesystemStorage(tmp_path)
    with pytest.raises(InvalidStorageKeyError):
        storage.put("../escape.txt", b"x")


def test_empty_key_is_rejected(tmp_path: Path) -> None:
    storage = LocalFilesystemStorage(tmp_path)
    with pytest.raises(InvalidStorageKeyError):
        storage.get("")
