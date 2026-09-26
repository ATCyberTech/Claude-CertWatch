"""Object-storage abstraction — interface owned by M0, cloud backends owned by M3.

Per the Decision Log, PostgreSQL is out of v0 entirely: persistence is one JSON
document + one PDF per scan, in object storage, keyed by the CSPRNG scan token
(technical specification Section 11-12). This package defines that abstraction
now (get/put/delete over a string key) so:

  - Local development (M0 deliverable: "local development instructions") works
    today against a LocalFilesystemStorage backend, with no cloud account and
    no network dependency.
  - M3 adds a real cloud backend (S3 / Azure Blob / R2) behind the *same*
    interface once the provider is selected at the M2 gate — calling code never
    changes.

The interface itself is intentionally minimal (three methods) and holds no
scan-specific logic (no token generation, no JSON schema) — that is M3's job
(Section 11-12). This is infrastructure plumbing, not the M3 feature.
"""
