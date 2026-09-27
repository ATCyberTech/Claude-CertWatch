"""The four fixed, read-only LLM tools (Section 16) — owned by M7.

Each tool operates over one scan's already risk-scored `Certificate` list
— the exact same list `app.api.routes_scans.get_scan_findings` serves —
and returns only the structured finding shape Section 17 names as safe to
send to the LLM: `{certificate_id, subject_cn, san_list, issuer,
days_to_expiry, risk_severity, chain_category, endpoints, flags}`. Raw
PEM/DER bytes, device configuration, and credentials never appear here —
`Certificate.pem` is never read by anything in this module.

No write tool exists, and none of these functions can be made to have
side effects: each is a pure read over data already computed before the
LLM is ever called.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.parsing.models import Certificate
from app.risk.risk_engine import evaluate_flags, summarize_risk_severity
from app.storage.scan_store import ScanRecord

TOOL_SCHEMAS: list[dict[str, object]] = [
    {
        "name": "get_findings",
        "description": (
            "List this scan's findings, one per certificate. Optionally filter "
            "to an exact risk_severity (e.g. 'critical', 'expired', 'ok')."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Exact risk_severity to filter to. Omit for every finding.",
                }
            },
        },
    },
    {
        "name": "get_certificate",
        "description": (
            "Get one finding by its certificate_id (the certificate's SHA-256 fingerprint)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"certificate_id": {"type": "string"}},
            "required": ["certificate_id"],
        },
    },
    {
        "name": "get_endpoints_for_certificate",
        "description": "List the host:port endpoints that presented a given certificate_id.",
        "input_schema": {
            "type": "object",
            "properties": {"certificate_id": {"type": "string"}},
            "required": ["certificate_id"],
        },
    },
    {
        "name": "get_summary_counts",
        "description": (
            "Get this scan's risk-severity summary counts (same shape as GET /api/scans/{token})."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
]


def _endpoint_dict(endpoint) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "host": endpoint.host,
        "port": endpoint.port,
        "environment": endpoint.environment,
        "owner": endpoint.owner,
    }


def _finding_dict(
    certificate: Certificate, all_certificates: list[Certificate]
) -> dict[str, object]:
    return {
        "certificate_id": certificate.fingerprint_sha256,
        "subject_cn": certificate.subject_cn,
        "san_list": certificate.san_list,
        "issuer": certificate.issuer,
        "days_to_expiry": certificate.days_to_expiry,
        "risk_severity": certificate.risk_severity or "ok",
        "chain_category": certificate.chain_category.value if certificate.chain_category else None,
        "endpoints": [_endpoint_dict(e) for e in certificate.endpoints],
        "flags": evaluate_flags(certificate, all_certificates),
    }


@dataclass
class ScanToolExecutor:
    """Binds the four fixed tools to one scan's data. `LLMProvider`
    implementations call `.call(name, arguments)` for every tool-use block
    the model emits; this class never talks to the LLM itself."""

    record: ScanRecord
    certificates: list[Certificate]

    def _find(self, certificate_id: object) -> Certificate | None:
        return next((c for c in self.certificates if c.fingerprint_sha256 == certificate_id), None)

    def call(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
        if tool_name == "get_findings":
            severity = arguments.get("severity")
            findings = [
                _finding_dict(c, self.certificates)
                for c in self.certificates
                if severity is None or (c.risk_severity or "ok") == severity
            ]
            return {"findings": findings}

        if tool_name == "get_certificate":
            certificate_id = arguments.get("certificate_id")
            certificate = self._find(certificate_id)
            if certificate is None:
                return {"error": f"No certificate with id {certificate_id!r} in this scan."}
            return _finding_dict(certificate, self.certificates)

        if tool_name == "get_endpoints_for_certificate":
            certificate_id = arguments.get("certificate_id")
            certificate = self._find(certificate_id)
            if certificate is None:
                return {"error": f"No certificate with id {certificate_id!r} in this scan."}
            return {"endpoints": [_endpoint_dict(e) for e in certificate.endpoints]}

        if tool_name == "get_summary_counts":
            return {"summary_counts": summarize_risk_severity(self.record)}

        return {"error": f"Unknown tool {tool_name!r}."}
