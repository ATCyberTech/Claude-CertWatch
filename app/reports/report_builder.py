"""Report assembly entry points — module boundary only, owned by M5."""

from __future__ import annotations

from app.parsing.models import Certificate


def build_pdf_report(certificates: list[Certificate]) -> bytes:
    """NOT IMPLEMENTED — owned by M5. See app/reports/__init__.py."""
    raise NotImplementedError("app.reports.report_builder.build_pdf_report is owned by M5.")


def build_csv_report(certificates: list[Certificate]) -> bytes:
    """NOT IMPLEMENTED — owned by M5. See app/reports/__init__.py."""
    raise NotImplementedError("app.reports.report_builder.build_csv_report is owned by M5.")
