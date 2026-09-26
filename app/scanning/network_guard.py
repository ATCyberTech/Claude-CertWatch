"""SSRF / DNS-rebinding defense — owned by M2.

Implements Sections 5 and 6 of the CertWatch MVP Technical Specification
v1. Section 5 calls this "the single highest-risk component in the
product" and requires it to be correct before M2, not patched afterward.

The pattern, always in this order:
  1. `validate_port` — reject an out-of-allowlist port before any DNS
     resolution or network call happens at all (Section 5).
  2. `resolve_and_validate` — resolve the hostname exactly once, collect
     EVERY returned address (not just the first), and reject the whole
     host if any one of them falls in a disallowed range (Section 5/6).
  3. The caller (`app.scanning.tls_client`) connects directly to one of
     the validated IP literals returned by step 2 — never re-resolves for
     this attempt (Section 6's "resolve-once, connect-to-pinned-IP": this
     is what defeats DNS rebinding, T2).

All address parsing and range comparison goes through the `ipaddress`
standard-library module only — never string/regex matching on the
address text (Section 6's "real IP-parsing library only" control).
`socket.getaddrinfo` always canonicalizes numeric hosts (decimal, octal,
hex, and shorthand IP forms all collapse to dotted-quad/colon-hex in its
result), so `ipaddress.ip_address()` only ever sees the canonical form —
no encoding trick in a submitted hostname string can bypass this by
reaching a private address through an alternate representation.

This module provides only the APPLICATION-LAYER half of the SSRF
defense. The NETWORK-LAYER half (Section 23: the scan-worker process
running where it cannot reach private address space or the cloud
metadata address even if this code has a bug) is a deployment-time
control, not application code — see docs/deployment/ for the per-target
isolation mechanism (AWS, GCP, Azure, OCI, self-hosted, or the
unconfigured local-development default this repo currently runs under).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DisallowedAddressError(Exception):
    """A hostname resolved to at least one address in a disallowed range.

    The whole host is rejected if even one resolved address is disallowed
    (Section 5) — never silently dropping the bad address and proceeding
    with the others.
    """


class DisallowedPortError(Exception):
    """A submitted port is outside the fixed allowlist.

    Always raised before any DNS resolution or network call (Section 5).
    """


class ResolutionError(Exception):
    """A hostname could not be resolved at all (NXDOMAIN, timeout, etc.).

    Distinct from `DisallowedAddressError`: a name that doesn't resolve is
    an ordinary scan-result finding, not a security rejection.
    """


@dataclass(frozen=True)
class ValidatedTarget:
    """A hostname that resolved to at least one address, all validated safe.

    `addresses` preserves every validated address (both A and AAAA
    records) so a caller may attempt more than one if the first connection
    fails, without ever calling the resolver again for this attempt.
    """

    hostname: str
    port: int
    addresses: tuple[IPAddress, ...]


def validate_port(port: int, allowed_ports: frozenset[int]) -> None:
    """Reject a port outside the fixed allowlist. Call before resolving."""
    if port not in allowed_ports:
        raise DisallowedPortError(
            f"port {port} is not in the allowed scan-port list {sorted(allowed_ports)}"
        )


def _is_disallowed(ip: IPAddress) -> bool:
    """True if `ip` must never be connected to by the scanner.

    Deliberately over-inclusive and redundant — several of these checks
    already imply others in CPython's own `ipaddress` implementation
    (e.g. `is_private` already covers loopback, link-local/metadata, and
    unspecified for IPv4). This is the single highest-risk function in
    the product (Section 5); clarity and auditability matter more here
    than avoiding overlap between checks.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # covers the cloud metadata address, 169.254.0.0/16
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True
    # IPv4-mapped IPv6 (::ffff:x.x.x.x): `ipaddress` already classifies
    # these correctly via the checks above, but the embedded IPv4 address
    # is re-validated explicitly here too, for auditability (Section 5/6
    # both call out IPv4-mapped IPv6 as its own named case).
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped is not None and _is_disallowed(mapped)


async def resolve_and_validate(hostname: str, port: int) -> ValidatedTarget:
    """Resolve `hostname` exactly once and validate every returned address.

    Raises `DisallowedAddressError` if ANY resolved address (IPv4 or
    IPv6) is in a disallowed range — the whole host is rejected, never
    just the bad address. Raises `ResolutionError` if the hostname does
    not resolve at all. Never calls the resolver a second time; the
    caller must connect using only the addresses returned here (Section
    6: resolve-once, connect-to-pinned-IP — this is what defeats DNS
    rebinding).
    """
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise ResolutionError(f"could not resolve {hostname!r}: {exc}") from exc

    if not results:
        raise ResolutionError(f"{hostname!r} resolved to no addresses")

    addresses: list[IPAddress] = []
    seen: set[IPAddress] = set()
    for _family, _type, _proto, _canonname, sockaddr in results:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip in seen:
            continue
        seen.add(ip)
        if _is_disallowed(ip):
            raise DisallowedAddressError(
                f"{hostname!r} resolved to disallowed address {ip} — rejecting the whole host"
            )
        addresses.append(ip)

    return ValidatedTarget(hostname=hostname, port=port, addresses=tuple(addresses))
