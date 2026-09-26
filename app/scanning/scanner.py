"""Per-scan orchestration: network_guard -> tls_client -> parsing — owned by M2.

Wires the SSRF guard, TLS handshake, and M1's certificate parser into a
single per-host pipeline (Section 3: end-to-end workflow), and enforces
the concurrency and timeout budget from Section 19.

Never raises for an ordinary per-host failure (disallowed port/address,
resolution failure, handshake failure, unparseable certificate) — those
are `HostScanOutcome` values, so one bad host in a batch never crashes the
rest of the scan.
"""

from __future__ import annotations

import asyncio
import enum
import functools
from dataclasses import dataclass

from app.core.config import Settings
from app.parsing.certificate_parser import CertificateParseError, parse_certificate_chain
from app.parsing.models import Certificate
from app.scanning.network_guard import (
    DisallowedAddressError,
    DisallowedPortError,
    ResolutionError,
    resolve_and_validate,
    validate_port,
)
from app.scanning.tls_client import HandshakeError, perform_tls_handshake


class HostScanStatus(enum.Enum):
    """Why a host scan ended the way it did — never a raised exception."""

    OK = "ok"
    DISALLOWED_PORT = "disallowed_port"
    DISALLOWED_ADDRESS = "disallowed_address"
    RESOLUTION_FAILED = "resolution_failed"
    HANDSHAKE_FAILED = "handshake_failed"
    PARSE_FAILED = "parse_failed"


@dataclass(frozen=True)
class HostScanOutcome:
    """One host's scan result — always exactly one of these per submitted host.

    `detail` is an internal diagnostic string only. Section 5's "no
    differentiated error surface" control means the REPORT layer (M5)
    must not surface fine-grained network state to the user beyond what
    the report needs — that redaction happens there, not here; this type
    keeps the full detail for logging/debugging.
    """

    hostname: str
    port: int
    status: HostScanStatus
    certificate: Certificate | None = None
    detail: str | None = None


async def scan_host(hostname: str, port: int, settings: Settings) -> HostScanOutcome:
    """Run the full pipeline for one host. Never raises for a normal failure."""
    try:
        validate_port(port, settings.allowed_scan_ports)
    except DisallowedPortError as exc:
        return HostScanOutcome(hostname, port, HostScanStatus.DISALLOWED_PORT, detail=str(exc))

    try:
        target = await resolve_and_validate(hostname, port)
    except DisallowedAddressError as exc:
        return HostScanOutcome(hostname, port, HostScanStatus.DISALLOWED_ADDRESS, detail=str(exc))
    except ResolutionError as exc:
        return HostScanOutcome(hostname, port, HostScanStatus.RESOLUTION_FAILED, detail=str(exc))

    try:
        handshake = await perform_tls_handshake(
            hostname,
            port,
            target.addresses,
            connect_timeout_seconds=settings.scan_connect_timeout_seconds,
            handshake_timeout_seconds=settings.scan_handshake_timeout_seconds,
        )
    except HandshakeError as exc:
        return HostScanOutcome(hostname, port, HostScanStatus.HANDSHAKE_FAILED, detail=str(exc))

    try:
        certificate = await parse_certificate_chain(handshake.pem_chain, hostname)
    except CertificateParseError as exc:
        return HostScanOutcome(hostname, port, HostScanStatus.PARSE_FAILED, detail=str(exc))

    return HostScanOutcome(hostname, port, HostScanStatus.OK, certificate=certificate)


@functools.lru_cache(maxsize=1)
def _global_semaphore(capacity: int) -> asyncio.Semaphore:
    """A single process-wide semaphore, shared across every call to
    `scan_hosts` regardless of which scan it belongs to.

    Section 19/22 require the global concurrency cap to hold "under
    simultaneous scan submissions" — i.e. across different scans
    submitted at the same time, not just within one. `lru_cache` makes
    this a true singleton for the life of the process: the first call
    fixes the capacity: capacity should not be expected to change within
    one running process.
    """
    return asyncio.Semaphore(capacity)


async def scan_hosts(hosts: list[tuple[str, int]], settings: Settings) -> list[HostScanOutcome]:
    """Run `scan_host` over every (hostname, port) pair under Section 19's
    concurrency and timeout budget.

    Bounded by two semaphores: a per-scan one (`scan_concurrency_per_scan`,
    fresh per call) and a process-wide global one
    (`scan_concurrency_global`, shared across every concurrently running
    scan). `scan_total_timeout_seconds` is the safety-net cap on the whole
    batch: any host still running when it fires is recorded as a
    handshake failure rather than left to hang indefinitely.
    """
    global_semaphore = _global_semaphore(settings.scan_concurrency_global)
    per_scan_semaphore = asyncio.Semaphore(settings.scan_concurrency_per_scan)

    async def _bounded(hostname: str, port: int) -> HostScanOutcome:
        async with global_semaphore, per_scan_semaphore:
            return await scan_host(hostname, port, settings)

    tasks = [asyncio.create_task(_bounded(hostname, port)) for hostname, port in hosts]
    done, pending = await asyncio.wait(tasks, timeout=settings.scan_total_timeout_seconds)

    outcomes: list[HostScanOutcome] = []
    for (hostname, port), task in zip(hosts, tasks, strict=True):
        if task in pending:
            task.cancel()
            outcomes.append(
                HostScanOutcome(
                    hostname,
                    port,
                    HostScanStatus.HANDSHAKE_FAILED,
                    detail="scan-wide safety-net timeout reached before this host finished",
                )
            )
        else:
            outcomes.append(task.result())
    return outcomes
