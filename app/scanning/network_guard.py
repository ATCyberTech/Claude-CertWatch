"""SSRF / DNS-rebinding guard — module boundary only, owned by M2.

This file intentionally contains no working network logic. It exists so that:
  1. The import path `app.scanning.network_guard` is stable from M0 onward, and
  2. Tests written ahead of M2 (Section 22's SSRF/rebinding test suite) have a
     concrete module to import against and can be written failing (red) before
     M2 makes them pass — rather than being invented from scratch at M2 time.

See app/scanning/__init__.py for the M2 gate condition and the required
function signatures. Raising NotImplementedError here is deliberate: a caller
that reaches this code before M2 is complete should fail loudly, not silently
proceed to a real network call.
"""

from __future__ import annotations

import ipaddress


class DisallowedAddressError(Exception):
    """Raised when a resolved address falls in a disallowed range (Section 5)."""


class DisallowedPortError(Exception):
    """Raised when a requested port is outside the fixed allowlist (Section 5)."""


def resolve_and_validate(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve `hostname` once and validate every returned address.

    NOT IMPLEMENTED — owned by M2, gated per app/scanning/__init__.py.
    """
    raise NotImplementedError(
        "app.scanning.network_guard.resolve_and_validate is owned by M2 and is "
        "gated on cloud-provider selection and network-isolation configuration "
        "(technical specification Section 25, M2 gate). Do not implement before "
        "that gate is satisfied and recorded in the Decision Log."
    )


def validate_port(port: int, allowed_ports: frozenset[int]) -> None:
    """Reject any port outside the fixed allowlist, before any network call.

    This check has no network dependency and could in principle run today,
    but is kept alongside resolve_and_validate under the same M2 ownership so
    the whole SSRF-relevant code path lands, and is reviewed, as one unit.
    """
    raise NotImplementedError("Owned by M2 — see module docstring.")
