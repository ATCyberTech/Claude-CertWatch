"""Deterministic risk engine — Section 9, owned by M4. No LLM involvement
anywhere in this module, ever.

`classify_risk` operates on already-parsed `app.parsing.models.Certificate`
objects, one per unique fingerprint within a scan, each with every
observing host:port merged into `.endpoints` — never on the raw per-host
`ScanRecord`/`HostResultRecord` shape M3 persists directly.
`group_into_certificates` builds that grouped list from a `ScanRecord` on
demand; nothing here is written back to storage (see its docstring and
`app.storage.scan_store`'s module docstring).

Wildcard presence (`Certificate.is_wildcard`) is informational metadata
only and plays no part in any rule here — the wildcard-breadth inference
was explicitly removed from scope during the technical-specification
review (Decision Log) and must not be reintroduced. Wildcard *hostname*
mismatch is not a separate rule either: it already folds into the ordinary
`hostname_mismatch` flag, via M1's wildcard-aware SAN matching.
"""

from __future__ import annotations

from app.parsing.models import Certificate, ChainCategory, Endpoint
from app.storage.scan_store import ScanRecord, certificate_from_record

# Section 9's "Expiry status" rule: EXPIRED is handled separately (any
# negative days_to_expiry); these are the four approaching-expiry tiers,
# checked in order, each threshold being "N or fewer days remain".
_EXPIRY_TIERS: tuple[tuple[int, str], ...] = (
    (7, "critical"),
    (30, "high"),
    (60, "medium"),
    (90, "low"),
)

_APPROACHING_EXPIRY_TIERS = frozenset(tier for _, tier in _EXPIRY_TIERS)

# Section 9's fixed priority order for "Overall risk severity" (highest
# first), exactly as stated: "EXPIRED, then weak crypto or broken chain,
# then hostname/SAN mismatch, then approaching-expiry tiers, then shared,
# then private CA." "suspicious_configuration" is deliberately absent —
# the spec's own priority sentence names only these; suspicious
# configuration is a supplementary flag (see `_is_suspicious_configuration`
# and `evaluate_flags`), not part of this chain (Decision Log, M4). Where
# the spec groups two names at one priority position ("weak crypto or
# broken chain"), weak crypto is checked first — an arbitrary but
# documented tie-break, since the spec does not order the two relative to
# each other (Decision Log, M4).
_SEVERITY_PRIORITY: tuple[str, ...] = (
    "expired",
    "weak_crypto",
    "broken_chain",
    "hostname_mismatch",
    "critical",
    "high",
    "medium",
    "low",
    "shared",
    "private_ca",
)

_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 256


def expiry_tier(days_to_expiry: int) -> str:
    """One of expired/critical/high/medium/low/ok (Section 9, "Expiry
    status" rule) — computed from `days_to_expiry` alone."""
    if days_to_expiry < 0:
        return "expired"
    for threshold, tier in _EXPIRY_TIERS:
        if days_to_expiry <= threshold:
            return tier
    return "ok"


def is_weak_crypto(key_algorithm: str, signature_algorithm: str) -> bool:
    """Section 9: "RSA under 2048 bits, DSA, or ECDSA under P-256;
    signature algorithm MD5 or SHA1."

    Parses the exact string formats `app.parsing.certificate_parser`
    produces (`RSA-{bits}`, `DSA-{bits}`, `EC-{curve}-{bits}`, `Ed25519`,
    `Ed448`, or `Unknown (...)`). DSA is flagged unconditionally — the spec
    gives RSA and EC each a bit-size floor but names DSA with no threshold
    of its own, so any key size counts. Ed25519/Ed448 and any unrecognized
    key-algorithm string are never flagged in v0 — Section 9 names only
    RSA, DSA, and ECDSA.
    """
    sig = signature_algorithm.lower()
    if sig.startswith("md5") or sig.startswith("sha1"):
        return True
    if key_algorithm.startswith("RSA-"):
        return int(key_algorithm.removeprefix("RSA-")) < _MIN_RSA_BITS
    if key_algorithm.startswith("DSA-"):
        return True
    if key_algorithm.startswith("EC-"):
        bits = int(key_algorithm.rsplit("-", 1)[-1])
        return bits < _MIN_EC_BITS
    return False


def _is_shared(certificate: Certificate) -> bool:
    """Section 9: "Count of endpoints per certificate is greater than 1
    within the scan" — the same underlying signal the rule table calls
    both "Duplicate certificates" and "Certificates shared across
    endpoints" ("surfaced as shared, not an error")."""
    return len(certificate.endpoints) > 1


def _is_suspicious_configuration(
    certificate: Certificate, all_certificates_in_scan: list[Certificate]
) -> bool:
    """Section 9: "A self-signed cert on a host where other discovered
    certs in the same scan are CA-issued, an inconsistent trust posture
    within one scan." Supplementary flag only — see the priority-order
    comment above `_SEVERITY_PRIORITY`."""
    if certificate.chain_category is not ChainCategory.SELF_SIGNED:
        return False
    return any(
        other.chain_category in (ChainCategory.PUBLIC_CA, ChainCategory.PRIVATE_CA)
        for other in all_certificates_in_scan
        if other is not certificate
    )


def evaluate_flags(
    certificate: Certificate, all_certificates_in_scan: list[Certificate]
) -> list[str]:
    """Every applicable flag for `certificate`, in Section 9's fixed
    priority order, with the supplementary `suspicious_configuration` flag
    appended last when it applies. `flags[0]`, if any, is the same value
    `classify_risk` returns; an empty list means "ok"."""
    tier = (
        expiry_tier(certificate.days_to_expiry) if certificate.days_to_expiry is not None else "ok"
    )
    weak_crypto = is_weak_crypto(certificate.key_algorithm, certificate.signature_algorithm)
    broken_chain = certificate.chain_category is ChainCategory.BROKEN
    hostname_mismatch = bool(certificate.hostname_mismatch)
    shared = _is_shared(certificate)
    private_ca = certificate.chain_category is ChainCategory.PRIVATE_CA

    flags: list[str] = []
    if tier == "expired":
        flags.append("expired")
    if weak_crypto:
        flags.append("weak_crypto")
    if broken_chain:
        flags.append("broken_chain")
    if hostname_mismatch:
        flags.append("hostname_mismatch")
    if tier in _APPROACHING_EXPIRY_TIERS:
        flags.append(tier)
    if shared:
        flags.append("shared")
    if private_ca:
        flags.append("private_ca")
    if _is_suspicious_configuration(certificate, all_certificates_in_scan):
        flags.append("suspicious_configuration")
    return flags


def classify_risk(certificate: Certificate, all_certificates_in_scan: list[Certificate]) -> str:
    """Return the overall risk_severity for one certificate within a scan —
    the single worst applicable flag by Section 9's fixed priority table
    (never a weighted numeric score). "ok" when nothing in the priority
    chain applies.

    `all_certificates_in_scan` is required because `suspicious_configuration`
    (surfaced via `evaluate_flags` but not part of the returned severity
    itself, per the priority-order note above) is relative to the rest of
    the scan, not computable from a single certificate in isolation.
    """
    for flag in evaluate_flags(certificate, all_certificates_in_scan):
        if flag in _SEVERITY_PRIORITY:
            return flag
    return "ok"


def group_into_certificates(scan_record: ScanRecord) -> list[Certificate]:
    """Group a scan's raw per-host results (M3's persisted shape) into one
    `Certificate` per unique fingerprint, with every observing host:port
    merged into `.endpoints` — Section 10's endpoint-grouped-by-certificate
    shape, built on demand rather than persisted (see both modules'
    docstrings).

    Hosts with no certificate (a failed handshake, a disallowed port,
    etc.) contribute nothing here — there is no certificate data to group.
    Result order follows first-seen order in `scan_record.host_results`.

    `duplicate_of` is intentionally left `None` on every result (Decision
    Log, M4): deduplication here is expressed by merging same-fingerprint
    occurrences into one record with an aggregated `endpoints[]`, so there
    is no second, separate record left over that would need a pointer back
    to a canonical one. The field stays on `Certificate` for Section 10
    schema compatibility but is unused by this implementation.
    """
    by_fingerprint: dict[str, Certificate] = {}
    for host_result in scan_record.host_results:
        if host_result.certificate is None:
            continue
        fingerprint = host_result.certificate.fingerprint_sha256
        certificate = by_fingerprint.get(fingerprint)
        if certificate is None:
            certificate = certificate_from_record(host_result.certificate)
            by_fingerprint[fingerprint] = certificate
        certificate.endpoints.append(Endpoint(host=host_result.hostname, port=host_result.port))
    return list(by_fingerprint.values())


def apply_risk_engine(certificates: list[Certificate]) -> None:
    """Set `.risk_severity` on every certificate in place, via
    `classify_risk` against the full list (so `suspicious_configuration`
    sees the rest of the scan)."""
    for certificate in certificates:
        certificate.risk_severity = classify_risk(certificate, certificates)


def severity_sort_key(severity: str) -> int:
    """Sort key placing severities in Section 9's priority order (worst
    first), with "ok" and anything unrecognized sorted last."""
    try:
        return _SEVERITY_PRIORITY.index(severity)
    except ValueError:
        return len(_SEVERITY_PRIORITY)


def summarize_risk_severity(scan_record: ScanRecord) -> dict[str, int]:
    """Per-host risk-severity counts for `GET /api/scans/{token}` (Section
    12/13). Supersedes M3's raw `HostScanStatus` counts (Decision Log) —
    same field name and response shape, different vocabulary: each host
    contributes to the severity bucket of the certificate it presented, or
    to "scan_failed" if it has no certificate at all (a failed handshake,
    a disallowed port, a parse error — there is no certificate to score).
    """
    certificates = group_into_certificates(scan_record)
    apply_risk_engine(certificates)
    severity_by_fingerprint: dict[str, str] = {
        certificate.fingerprint_sha256: certificate.risk_severity
        for certificate in certificates
        if certificate.risk_severity is not None
    }

    counts: dict[str, int] = {}
    for host_result in scan_record.host_results:
        if host_result.certificate is None:
            key = "scan_failed"
        else:
            key = severity_by_fingerprint.get(host_result.certificate.fingerprint_sha256, "ok")
        counts[key] = counts.get(key, 0) + 1
    return counts
