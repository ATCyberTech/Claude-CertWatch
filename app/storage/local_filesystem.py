"""Local-filesystem backend for ObjectStorage — the M0 development backend.

This is dev/test plumbing, not a product feature: it lets `make run` and
`pytest` work with zero cloud credentials and zero network dependency,
satisfying the M0 "local development instructions" deliverable. It is not
the eventual production backend — Section 11 specifies S3-compatible object
storage for that, selected at the M2 gate.

Path handling rejects any key containing path-traversal segments as a basic
defensive measure, even though no scan-specific (token) logic exists yet to
generate keys.
"""

from __future__ import annotations

from pathlib import Path

from app.storage.interface import ObjectStorage


class InvalidStorageKeyError(Exception):
    """Raised when a storage key would escape the storage root."""


class LocalFilesystemStorage(ObjectStorage):
    """Stores each key as a file under `root_path`, creating parent dirs as needed."""

    def __init__(self, root_path: str | Path) -> None:
        self._root = Path(root_path).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        if not key or ".." in Path(key).parts:
            raise InvalidStorageKeyError(f"refusing unsafe storage key: {key!r}")
        target = (self._root / key).resolve()
        if self._root not in target.parents and target != self._root:
            raise InvalidStorageKeyError(f"key escapes storage root: {key!r}")
        return target

    def get(self, key: str) -> bytes | None:
        path = self._resolve(key)
        if not path.is_file():
            return None
        return path.read_bytes()

    def put(self, key: str, data: bytes) -> None:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def delete(self, key: str) -> None:
        path = self._resolve(key)
        path.unlink(missing_ok=True)
