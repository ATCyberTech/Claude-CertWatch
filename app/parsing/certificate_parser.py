"""Certificate parsing entry point — module boundary only, owned by M1.

See app/parsing/__init__.py for the full scope. This stub exists so
tests/unit and tests/integration have a stable import path to write M1's
fixture-driven test suite against (Section 22) ahead of the implementation
landing.
"""

from __future__ import annotations

from app.parsing.models import Certificate


def parse_certificate_chain(pem_chain: list[bytes], observed_hostname: str) -> Certificate:
    """Parse a presented certificate chain and classify its chain outcome.

    NOT IMPLEMENTED — owned by M1. See app/parsing/__init__.py.
    """
    raise NotImplementedError(
        "app.parsing.certificate_parser.parse_certificate_chain is owned by M1. "
        "See app/parsing/__init__.py for the required behavior."
    )
