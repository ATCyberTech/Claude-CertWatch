"""Data model for parsed certificates — owned by M1.

Defined ahead of M1's parsing logic so the data model (technical specification
Section 10) is fixed as a module boundary now, and M1 fills in construction
logic against an already-agreed shape rather than inventing the shape too.

Fields mirror Section 10 exactly. Required/optional/derived status is noted
per field; nothing here is populated at M0 — these are structural stubs only.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class ChainCategory(enum.Enum):
    """The five chain-outcome categories from Section 8. Never collapsed."""

    SELF_SIGNED = "self_signed"
    PUBLIC_CA = "public_ca"
    PRIVATE_CA = "private_ca"
    BROKEN = "broken"
    # NOTE: hostname/SAN mismatch (category 5) is not a ChainCategory value — it is
    # orthogonal and stored as its own boolean/flag on Certificate, since it can
    # co-occur with any of the four categories above (Section 8).


@dataclass
class Endpoint:
    """A host:port where a certificate was observed (Section 10)."""

    host: str  # required
    port: int  # required
    environment: str | None = None  # optional, user-tagged only, never AI-inferred
    owner: str | None = None  # optional, user-tagged only, never AI-inferred


@dataclass
class Certificate:
    """A parsed certificate and its derived findings (Section 10).

    NOT CONSTRUCTED ANYWHERE YET — this is the target shape for M1's parser
    output, not a working object. Required fields have no default; derived
    fields default to None until M1/M4 populate them.
    """

    # Required, parsed directly from the certificate
    fingerprint_sha256: str
    subject_cn: str
    san_list: list[str]
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    signature_algorithm: str
    pem: str  # public certificate only — never a private key (Section 21)

    # Derived — populated by M1 (chain_category) and M4 (everything risk-related)
    chain_category: ChainCategory | None = None
    is_expired: bool | None = None
    days_to_expiry: int | None = None
    is_wildcard: bool | None = None  # informational metadata only (Decision Log)
    risk_severity: str | None = None
    duplicate_of: str | None = None  # fingerprint_sha256 of the matching certificate, if any

    endpoints: list[Endpoint] = field(default_factory=list)
