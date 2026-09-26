"""Risk classification entry point — module boundary only, owned by M4.

See app/risk/__init__.py for full scope.
"""

from __future__ import annotations

from app.parsing.models import Certificate


def classify_risk(certificate: Certificate, all_certificates_in_scan: list[Certificate]) -> str:
    """Return the overall risk_severity for one certificate within a scan.

    `all_certificates_in_scan` is required because duplicate-detection and
    shared-across-endpoints findings are relative to the rest of the scan,
    not computable from a single certificate in isolation.

    NOT IMPLEMENTED — owned by M4. See app/risk/__init__.py.
    """
    raise NotImplementedError(
        "app.risk.risk_engine.classify_risk is owned by M4. "
        "See app/risk/__init__.py for the required rule set."
    )
