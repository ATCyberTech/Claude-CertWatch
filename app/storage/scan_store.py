"""Scan-result persistence and token generation — owned by M3.

Implements Section 10 (data model), Section 11 (object-storage design:
"one JSON document per scan"), and Section 12 (token/access-control model)
on top of the M0 `ObjectStorage` interface.

Scope note (M3 implementation decision, recorded in the Decision Log):
this module persists RAW per-host scan outcomes (`HostResultRecord`, one
per submitted host:port) rather than Section 10's endpoint-grouped-by-
certificate shape (`Certificate.endpoints`, populated by grouping
identical fingerprints across hosts). This remains true after M4:
`app.risk.risk_engine.group_into_certificates` does that grouping
statelessly, on demand, from this raw persisted shape — it is never
written back to storage. `risk_severity` is computed the same way, on
demand, by the risk engine; `duplicate_of` is never populated at all (see
`certificate_from_record` and the Decision Log for why).

Scope note 2: a real S3-compatible cloud backend (Section 11) is
deliberately NOT added yet. Local Windows dev remains the current active
deployment target (M2 gate decision) and no cloud credentials exist to
test against — the `ObjectStorage` interface (M0) already makes that
swap-in trivial the moment a specific cloud target is actually stood up,
so speculatively wiring one now would be untested, unused code.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime

from pydantic import BaseModel

from app.parsing.models import Certificate, ChainCategory
from app.scanning.scanner import HostScanOutcome
from app.storage.interface import ObjectStorage


def generate_scan_token() -> str:
    """A CSPRNG-generated token — the sole scan identifier and the object-
    storage key (Section 12). ~256 bits of entropy from `token_urlsafe(32)`
    (well above the spec's stated ≥122-bit floor); no sequential or
    otherwise guessable identifier is ever generated anywhere in this
    module.
    """
    return secrets.token_urlsafe(32)


class CertificateRecord(BaseModel):
    """JSON-safe mirror of `app.parsing.models.Certificate` (Section 10)."""

    fingerprint_sha256: str
    subject_cn: str
    san_list: list[str]
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    signature_algorithm: str
    pem: str
    chain_category: str | None
    is_expired: bool | None
    days_to_expiry: int | None
    is_wildcard: bool | None
    hostname_mismatch: bool | None
    risk_severity: str | None
    duplicate_of: str | None


def certificate_to_record(certificate: Certificate) -> CertificateRecord:
    """Convert M1's `Certificate` dataclass to its JSON-safe storage form.

    `endpoints` is deliberately dropped here — see the module docstring:
    grouping identical certificates across hosts is M4's job, and M2's
    parser never populates that field today (each `Certificate` here
    describes exactly one host's presented chain).
    """
    return CertificateRecord(
        fingerprint_sha256=certificate.fingerprint_sha256,
        subject_cn=certificate.subject_cn,
        san_list=certificate.san_list,
        issuer=certificate.issuer,
        serial_number=certificate.serial_number,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        key_algorithm=certificate.key_algorithm,
        signature_algorithm=certificate.signature_algorithm,
        pem=certificate.pem,
        chain_category=certificate.chain_category.value if certificate.chain_category else None,
        is_expired=certificate.is_expired,
        days_to_expiry=certificate.days_to_expiry,
        is_wildcard=certificate.is_wildcard,
        hostname_mismatch=certificate.hostname_mismatch,
        risk_severity=certificate.risk_severity,
        duplicate_of=certificate.duplicate_of,
    )


def certificate_from_record(record: CertificateRecord) -> Certificate:
    """The reverse of `certificate_to_record` — owned by M4 (Section 9's
    risk engine operates on `Certificate` dataclass instances, grouped by
    fingerprint via `app.risk.risk_engine.group_into_certificates`, not on
    the raw JSON-safe records this module persists).

    `endpoints` is left at its default empty list here on purpose — the
    caller (`group_into_certificates`) populates it by merging every
    `HostResultRecord` that shares this fingerprint, which this function,
    operating on a single record, has no visibility into.
    """
    return Certificate(
        fingerprint_sha256=record.fingerprint_sha256,
        subject_cn=record.subject_cn,
        san_list=record.san_list,
        issuer=record.issuer,
        serial_number=record.serial_number,
        not_before=record.not_before,
        not_after=record.not_after,
        key_algorithm=record.key_algorithm,
        signature_algorithm=record.signature_algorithm,
        pem=record.pem,
        chain_category=ChainCategory(record.chain_category) if record.chain_category else None,
        is_expired=record.is_expired,
        days_to_expiry=record.days_to_expiry,
        is_wildcard=record.is_wildcard,
        hostname_mismatch=record.hostname_mismatch,
        risk_severity=record.risk_severity,
        duplicate_of=record.duplicate_of,
    )


class HostResultRecord(BaseModel):
    """One submitted host:port's scan outcome (Section 10's `endpoints[]`
    entry, before M4 groups them by certificate fingerprint)."""

    hostname: str
    port: int
    status: str
    detail: str | None = None
    certificate: CertificateRecord | None = None


def host_outcome_to_record(outcome: HostScanOutcome) -> HostResultRecord:
    return HostResultRecord(
        hostname=outcome.hostname,
        port=outcome.port,
        status=outcome.status.value,
        detail=outcome.detail,
        certificate=(certificate_to_record(outcome.certificate) if outcome.certificate else None),
    )


class ScanRecord(BaseModel):
    """The full "one JSON document per scan" (Section 10/11)."""

    token: str
    submitted_at: datetime
    input_type: str = "host_list"
    host_count: int
    status: str
    # Retained for abuse investigation only — never returned by any API
    # response (Section 10).
    source_ip: str | None = None
    ai_enabled: bool = True
    requester_email: str | None = None
    host_results: list[HostResultRecord] = []


def scan_storage_key(token: str) -> str:
    """`scans/{token}/result.json` (Section 11) — the token IS the key."""
    return f"scans/{token}/result.json"


def save_scan_record(storage: ObjectStorage, record: ScanRecord) -> None:
    storage.put(scan_storage_key(record.token), record.model_dump_json().encode("utf-8"))


def load_scan_record(storage: ObjectStorage, token: str) -> ScanRecord | None:
    """Return the stored `ScanRecord` for `token`, or `None` if it doesn't
    exist — deliberately not an exception: an unknown token is an ordinary,
    expected outcome (a typo, an expired/deleted scan), not a bug."""
    raw = storage.get(scan_storage_key(token))
    if raw is None:
        return None
    return ScanRecord.model_validate(json.loads(raw))


def summarize_host_statuses(host_results: list[HostResultRecord]) -> dict[str, int]:
    """Counts of host-scan outcomes by status (Section 13's `summary_counts`).

    M3-implementation-scoped: these are `HostScanStatus` counts (ok,
    disallowed_port, handshake_failed, ...), NOT the risk-severity tiers
    Section 9's deterministic risk engine will eventually produce — M4
    replaces/extends this once that engine exists. The response shape
    (`{status, summary_counts: dict[str, int]}`) does not change either
    way, so this is forward-compatible, not a contract to redo.
    """
    counts: dict[str, int] = {}
    for result in host_results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts
