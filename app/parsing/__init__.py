"""X.509 certificate parsing and chain classification — owned by M1.

Implemented as of M1 (technical specification Section 8), against local
certificate fixtures (tests/fixtures/certs/) only — no live network
dependency; it does not need app.scanning (M2) to exist.

- `certificate_parser.parse_certificate_chain` parses certificate fields
  (subject, SAN, issuer, validity, key/signature algorithm, fingerprint)
  using the `cryptography` library and classifies chain outcome into
  exactly one of five categories, never collapsed:
    1. Genuinely self-signed leaf
    2. Valid chain to a public trusted root
    3. Correctly built private/internal CA chain (not independently verified)
    4. Broken/incomplete/invalid chain
    5. Hostname/SAN mismatch (orthogonal — can co-occur with 1-4; stored as
       `Certificate.hostname_mismatch`, an M1-added field — Decision Log)
  via the two-pass `pyhanko-certvalidator` algorithm recorded in the
  Decision Log (Pass 1 against a public trust bundle — `trust_store`,
  normally certifi; Pass 2 with trust roots extended to the server's own
  presented certificates).
- Malformed/adversarial ASN.1 (T9) never crashes or misbehaves: a parse
  failure raises `certificate_parser.CertificateParseError`, a distinct,
  catchable exception — never a silent drop or an unhandled exception
  escaping this package. Adversarial certificate metadata (e.g. a subject
  CN containing control characters) is stored and displayed as an inert
  string, never interpreted.

`parse_certificate_chain` is async (an M1 implementation decision — see the
Decision Log — because `pyhanko-certvalidator`'s path validator is
async-only; the M0 stub signature was synchronous).
"""
