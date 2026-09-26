"""X.509 certificate parsing and chain classification — owned by M1.

NOT IMPLEMENTED YET. M1 proceeds entirely against local certificate fixtures
(tests/fixtures/certs/) with no live network dependency — it does not need
app.scanning to exist yet.

When implemented (technical specification Section 8), this package must:
    - Parse certificate fields (subject, SAN, issuer, validity, key/signature
      algorithm, fingerprint) using the `cryptography` library.
    - Classify chain outcome into exactly one of five categories, never collapsed:
        1. Genuinely self-signed leaf
        2. Valid chain to a public trusted root
        3. Correctly built private/internal CA chain (not independently verified)
        4. Broken/incomplete/invalid chain
        5. Hostname/SAN mismatch (orthogonal — can co-occur with 1-4)
      via the two-pass `pyhanko-certvalidator` algorithm recorded in the Decision
      Log (Pass 1 against the certifi public trust store; Pass 2 with trust roots
      extended to the server's own presented certificates).
    - Never crash or misbehave on malformed/adversarial ASN.1 (T9) — a parse
      failure is its own distinct finding, never a silent drop or an exception
      that escapes this package.
"""
