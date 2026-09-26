"""Public trust-root loading for certificate chain validation — owned by M1.

Loads the certifi CA bundle into `asn1crypto.x509.Certificate` objects for
use as Pass 1's trust anchors in the two-pass validation algorithm
(CertWatch MVP Technical Specification v1, Section 8). Certificate
validation itself never fetches anything over the network (`allow_fetching`
is always False in `certificate_parser.py`) — this module only reads the
static, locally-installed certifi bundle.
"""

from __future__ import annotations

from functools import lru_cache

import asn1crypto.pem
import asn1crypto.x509 as asn1_x509
import certifi


@lru_cache
def default_public_trust_roots() -> tuple[asn1_x509.Certificate, ...]:
    """Return the certifi public trust bundle as asn1crypto certificates.

    Cached for the life of the process — certifi's installed bundle does
    not change without a package upgrade and a restart. Returned as a
    tuple (not a list) so the cached result can't be mutated by a caller
    and silently corrupt every later Pass 1 validation.
    """
    with open(certifi.where(), "rb") as f:
        bundle = f.read()
    roots = [
        asn1_x509.Certificate.load(der)
        for type_name, _headers, der in asn1crypto.pem.unarmor(bundle, multiple=True)
        if type_name == "CERTIFICATE"
    ]
    return tuple(roots)
