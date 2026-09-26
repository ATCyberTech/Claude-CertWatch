"""Object-storage interface — the only thing M0 defines; M3 owns everything else.

`ObjectStorage` is a plain get/put/delete key-value abstraction. It knows
nothing about scans, tokens, or JSON schemas — see app/storage/__init__.py
for why that boundary is drawn here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ObjectStorage(ABC):
    """Minimal key-value object-storage interface backing CertWatch persistence."""

    @abstractmethod
    def get(self, key: str) -> bytes | None:
        """Return the stored bytes for `key`, or None if it does not exist."""

    @abstractmethod
    def put(self, key: str, data: bytes) -> None:
        """Store `data` under `key`, overwriting any existing value."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove `key` if present. Must not raise if `key` does not exist."""
